use chrono::Local;
use std::fs;
use std::path::{Path, PathBuf};

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Represents a single dirty page reference and its corresponding data
#[derive(Debug, Clone)]
struct DirtyPage {
    offset_in_bins: usize,
    data: Vec<u8>,
}

/// Represents a parsed HvLE log entry
#[derive(Debug, Clone)]
struct HvLeEntry {
    sequence_number: u32,
    hive_bins_data_size: usize,
    dirty_pages: Vec<DirtyPage>,
}

/// Checks if a hive buffer is marked as "dirty" (primary != secondary sequence number)
pub fn is_hive_dirty(hive_data: &[u8]) -> bool {
    if hive_data.len() < 12 {
        return false;
    }
    let primary_seq = u32::from_le_bytes([hive_data[4], hive_data[5], hive_data[6], hive_data[7]]);
    let secondary_seq = u32::from_le_bytes([hive_data[8], hive_data[9], hive_data[10], hive_data[11]]);
    primary_seq != secondary_seq
}

/// Finds adjacent transaction log files (.LOG, .LOG1, .LOG2) for a given hive file path
pub fn find_associated_logs(hive_path: &Path) -> Vec<PathBuf> {
    let mut logs = Vec::new();
    let parent = match hive_path.parent() {
        Some(p) => p,
        None => return logs,
    };

    let filename = match hive_path.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return logs,
    };

    // Standard extensions: .LOG, .LOG1, .LOG2 (and variations)
    let candidates = [
        format!("{}.LOG", filename),
        format!("{}.LOG1", filename),
        format!("{}.LOG2", filename),
        format!("{}.log", filename),
        format!("{}.log1", filename),
        format!("{}.log2", filename),
    ];

    for candidate in &candidates {
        let log_path = parent.join(candidate);
        if log_path.exists() && log_path.is_file() {
            if !logs.contains(&log_path) {
                logs.push(log_path);
            }
        }
    }

    logs
}

/// Replays transaction logs into a primary registry hive buffer.
/// Returns the updated in-memory hive buffer (original files on disk are never altered).
pub fn replay_hive_logs(hive_path: &Path, hive_data: &[u8], silent: bool) -> Vec<u8> {
    let dirty = is_hive_dirty(hive_data);
    let log_files = find_associated_logs(hive_path);

    if log_files.is_empty() {
        return hive_data.to_vec();
    }

    let primary_seq = if hive_data.len() >= 8 {
        u32::from_le_bytes([hive_data[4], hive_data[5], hive_data[6], hive_data[7]])
    } else {
        0
    };

    let secondary_seq = if hive_data.len() >= 12 {
        u32::from_le_bytes([hive_data[8], hive_data[9], hive_data[10], hive_data[11]])
    } else {
        0
    };

    let min_seq = primary_seq.min(secondary_seq);

    // Read and parse all candidate log entries from all associated log files
    let mut all_hvle_entries: Vec<HvLeEntry> = Vec::new();
    let mut total_dirt_pages = 0;

    for log_path in &log_files {
        if let Ok(log_data) = fs::read(log_path) {
            // Try parsing new format (HvLE)
            let hvle_entries = parse_hvle_log(&log_data);
            if !hvle_entries.is_empty() {
                all_hvle_entries.extend(hvle_entries);
            } else {
                // Try legacy DIRT format
                let dirt_pages = parse_dirt_log(&log_data);
                if !dirt_pages.is_empty() {
                    total_dirt_pages += dirt_pages.len();
                }
            }
        }
    }

    // Filter and sort HvLE entries by sequence number
    all_hvle_entries.retain(|e| e.sequence_number >= min_seq);
    all_hvle_entries.sort_by_key(|e| e.sequence_number);
    all_hvle_entries.dedup_by_key(|e| e.sequence_number);

    if all_hvle_entries.is_empty() && total_dirt_pages == 0 {
        return hive_data.to_vec();
    }

    log_message(
        silent,
        &format!(
            "🔄 Replaying transaction logs for {}: found {} log files, applying {} HvLE entries (dirty hive: {})",
            hive_path.display(),
            log_files.len(),
            all_hvle_entries.len(),
            dirty
        ),
    );

    let mut recovered_buffer = hive_data.to_vec();
    let mut last_seq = primary_seq;
    let mut pages_applied = 0;

    // Apply HvLE entries
    for entry in all_hvle_entries {
        last_seq = entry.sequence_number;

        // Ensure buffer can accommodate hive bins data size
        let target_size = 4096 + entry.hive_bins_data_size;
        if recovered_buffer.len() < target_size {
            recovered_buffer.resize(target_size, 0);
        }

        for page in entry.dirty_pages {
            let write_offset = 4096 + page.offset_in_bins;
            let end_offset = write_offset + page.data.len();

            if recovered_buffer.len() < end_offset {
                recovered_buffer.resize(end_offset, 0);
            }

            recovered_buffer[write_offset..end_offset].copy_from_slice(&page.data);
            pages_applied += 1;
        }
    }

    // Apply legacy DIRT pages if any
    for log_path in &log_files {
        if let Ok(log_data) = fs::read(log_path) {
            let dirt_pages = parse_dirt_log(&log_data);
            for page in dirt_pages {
                let write_offset = 4096 + page.offset_in_bins;
                let end_offset = write_offset + page.data.len();
                if recovered_buffer.len() < end_offset {
                    recovered_buffer.resize(end_offset, 0);
                }
                recovered_buffer[write_offset..end_offset].copy_from_slice(&page.data);
                pages_applied += 1;
            }
        }
    }

    // Update base block sequence numbers to mark hive as clean and synchronized
    if recovered_buffer.len() >= 12 {
        let seq_bytes = last_seq.to_le_bytes();
        recovered_buffer[4..8].copy_from_slice(&seq_bytes);
        recovered_buffer[8..12].copy_from_slice(&seq_bytes);
    }

    log_message(
        silent,
        &format!(
            "✅ Replay complete for {}: applied {} dirty pages (synchronized sequence: {})",
            hive_path.display(),
            pages_applied,
            last_seq
        ),
    );

    recovered_buffer
}

/// Parses an incremental transaction log file (New format, HvLE)
fn parse_hvle_log(data: &[u8]) -> Vec<HvLeEntry> {
    let mut entries = Vec::new();

    // The first sector (512 bytes) is the base block
    if data.len() < 1024 {
        return entries;
    }

    // Verify file header starts with "regf"
    if &data[0..4] != b"regf" {
        return entries;
    }

    let mut offset = 512; // Log entries start at second sector

    while offset + 40 <= data.len() {
        if &data[offset..offset + 4] != b"HvLE" {
            // Not a valid entry at this 512-byte boundary
            break;
        }

        let entry_size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        if entry_size < 40 || offset + entry_size > data.len() {
            break;
        }

        let sequence_number = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);

        let hive_bins_data_size = u32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]) as usize;

        let dirty_pages_count = u32::from_le_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]) as usize;

        let refs_offset = offset + 40;
        let refs_total_size = dirty_pages_count * 8;
        let mut raw_data_offset = refs_offset + refs_total_size;

        if raw_data_offset > offset + entry_size {
            break;
        }

        let mut dirty_pages = Vec::with_capacity(dirty_pages_count);
        let mut valid = true;

        for i in 0..dirty_pages_count {
            let ref_ptr = refs_offset + (i * 8);
            let page_offset = u32::from_le_bytes([
                data[ref_ptr],
                data[ref_ptr + 1],
                data[ref_ptr + 2],
                data[ref_ptr + 3],
            ]) as usize;

            let page_size = u32::from_le_bytes([
                data[ref_ptr + 4],
                data[ref_ptr + 5],
                data[ref_ptr + 6],
                data[ref_ptr + 7],
            ]) as usize;

            if raw_data_offset + page_size > offset + entry_size {
                valid = false;
                break;
            }

            dirty_pages.push(DirtyPage {
                offset_in_bins: page_offset,
                data: data[raw_data_offset..raw_data_offset + page_size].to_vec(),
            });

            raw_data_offset += page_size;
        }

        if valid {
            entries.push(HvLeEntry {
                sequence_number,
                hive_bins_data_size,
                dirty_pages,
            });
        }

        // Align next entry offset to 512-byte boundary
        offset = (offset + entry_size + 511) & !511;
    }

    entries
}

/// Parses a legacy transaction log file (Old format, DIRT)
fn parse_dirt_log(data: &[u8]) -> Vec<DirtyPage> {
    let mut pages = Vec::new();

    if data.len() < 1024 || &data[0..4] != b"regf" {
        return pages;
    }

    // Check for "DIRT" signature at offset 512
    if &data[512..516] != b"DIRT" {
        return pages;
    }

    let hive_bins_size = if data.len() >= 0x2C {
        u32::from_le_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]) as usize
    } else {
        0
    };

    let total_pages = hive_bins_size / 512;
    let bitmap_bytes_len = (total_pages + 7) / 8;
    let bitmap_start = 516;
    let bitmap_end = bitmap_start + bitmap_bytes_len;

    if bitmap_end > data.len() {
        return pages;
    }

    // Dirty pages start at next 512-byte aligned sector after dirty vector
    let pages_data_start = (bitmap_end + 511) & !511;
    let mut current_page_offset = pages_data_start;

    for bit_index in 0..total_pages {
        let byte_pos = bitmap_start + (bit_index / 8);
        let bit_pos = bit_index % 8;

        if byte_pos >= data.len() {
            break;
        }

        if (data[byte_pos] & (1 << bit_pos)) != 0 {
            if current_page_offset + 512 <= data.len() {
                pages.push(DirtyPage {
                    offset_in_bins: bit_index * 512,
                    data: data[current_page_offset..current_page_offset + 512].to_vec(),
                });
                current_page_offset += 512;
            } else {
                break;
            }
        }
    }

    pages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_hive_dirty() {
        let mut clean_hive = vec![0u8; 4096];
        clean_hive[..4].copy_from_slice(b"regf");
        clean_hive[4..8].copy_from_slice(&100u32.to_le_bytes());
        clean_hive[8..12].copy_from_slice(&100u32.to_le_bytes());
        assert!(!is_hive_dirty(&clean_hive));

        let mut dirty_hive = clean_hive.clone();
        dirty_hive[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert!(is_hive_dirty(&dirty_hive));
    }

    #[test]
    fn test_hvle_entry_replay() {
        // Create base hive with sequence 10
        let mut base_hive = vec![0u8; 8192];
        base_hive[..4].copy_from_slice(b"regf");
        base_hive[4..8].copy_from_slice(&10u32.to_le_bytes());
        base_hive[8..12].copy_from_slice(&9u32.to_le_bytes()); // dirty: 10 != 9

        // Construct synthetic HvLE log file
        let mut log_data = vec![0u8; 2048];
        log_data[..4].copy_from_slice(b"regf");

        let entry_offset = 512;
        log_data[entry_offset..entry_offset + 4].copy_from_slice(b"HvLE");

        let dirty_page_content = b"CAAREA_FORENSIC_RECOVERED_PAGE_DATA";
        let page_size = dirty_page_content.len() as u32;
        let entry_size = 40 + 8 + page_size;
        let entry_size_padded = (entry_size + 511) & !511;

        log_data[entry_offset + 4..entry_offset + 8].copy_from_slice(&entry_size_padded.to_le_bytes());
        log_data[entry_offset + 12..entry_offset + 16].copy_from_slice(&10u32.to_le_bytes()); // seq 10
        log_data[entry_offset + 16..entry_offset + 20].copy_from_slice(&4096u32.to_le_bytes()); // bins size 4096
        log_data[entry_offset + 20..entry_offset + 24].copy_from_slice(&1u32.to_le_bytes()); // 1 dirty page

        // Dirty page reference: offset 0x20 in hive bins, size `page_size`
        let ref_offset = entry_offset + 40;
        log_data[ref_offset..ref_offset + 4].copy_from_slice(&0x20u32.to_le_bytes());
        log_data[ref_offset + 4..ref_offset + 8].copy_from_slice(&page_size.to_le_bytes());

        // Dirty page data
        let data_offset = ref_offset + 8;
        log_data[data_offset..data_offset + dirty_page_content.len()].copy_from_slice(dirty_page_content);

        let parsed = parse_hvle_log(&log_data);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].sequence_number, 10);
        assert_eq!(parsed[0].dirty_pages.len(), 1);
        assert_eq!(parsed[0].dirty_pages[0].offset_in_bins, 0x20);
        assert_eq!(parsed[0].dirty_pages[0].data, dirty_page_content);
    }
}
