//! Windows Prefetch files (`C:\Windows\Prefetch\*.pf`): the executable, its last eight run
//! times, the run counter, the files it touched and the volume it ran from.
//!
//! Versions: 17 (XP/2003), 23 (Vista/7), 26 (8/8.1), 30 (10/11). Windows 10 and later store
//! the file LZXPRESS-Huffman compressed behind a `MAM\x04` header.

use std::path::Path;

use super::xpress;
use crate::parsers::evtx::Event;
use crate::utils::filetime_to_iso;

pub const MAM_MAGIC: &[u8; 4] = b"MAM\x04";
pub const SCCA_MAGIC: &[u8; 4] = b"SCCA";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    pub device: String,
    pub serial: u32,
    pub created: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefetch {
    pub version: u32,
    pub executable: String,
    pub hash: u32,
    pub run_count: u32,
    /// Canonical UTC, most recent first, zeros skipped.
    pub last_runs: Vec<String>,
    pub files: Vec<String>,
    pub volumes: Vec<Volume>,
}

impl Prefetch {
    /// Full path of the executable as recorded in the loaded-files list, when present.
    pub fn executable_path(&self) -> Option<&str> {
        let suffix = format!("\\{}", self.executable.to_uppercase());
        self.files.iter().map(|s| s.as_str()).find(|f| f.to_uppercase().ends_with(&suffix))
    }
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

fn utf16_at(b: &[u8], off: usize, max_bytes: usize) -> String {
    let end = (off + max_bytes).min(b.len());
    if off >= end {
        return String::new();
    }
    let units: Vec<u16> = b[off..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Is this buffer a prefetch file (compressed or not)?
pub fn is_prefetch(header: &[u8]) -> bool {
    header.len() >= 8 && (header.starts_with(MAM_MAGIC) || &header[4..8] == SCCA_MAGIC)
}

/// Decompresses a `MAM\x04` container, or returns the bytes untouched when already plain.
pub fn decompress_if_needed(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.starts_with(MAM_MAGIC) {
        let size = u32_at(raw, 4).ok_or("truncated MAM header")? as usize;
        return xpress::decompress(&raw[8..], size);
    }
    Ok(raw.to_vec())
}

/// Parses a prefetch file (compressed or plain).
pub fn parse(raw: &[u8]) -> Result<Prefetch, String> {
    let data = decompress_if_needed(raw)?;
    if data.len() < 0x54 + 68 || &data[4..8] != SCCA_MAGIC {
        return Err("not a prefetch file (SCCA signature missing)".into());
    }
    let version = u32_at(&data, 0).unwrap_or(0);
    let executable = utf16_at(&data, 0x10, 60);
    let hash = u32_at(&data, 0x4C).unwrap_or(0);

    let metrics_offset = u32_at(&data, 0x54).unwrap_or(0) as usize;
    let strings_offset = u32_at(&data, 0x64).unwrap_or(0) as usize;
    let strings_size = u32_at(&data, 0x68).unwrap_or(0) as usize;
    let volumes_offset = u32_at(&data, 0x6C).unwrap_or(0) as usize;
    let volumes_count = u32_at(&data, 0x70).unwrap_or(0) as usize;

    let (run_times_offset, run_times_count, run_count_offset, volume_entry_size) = match version {
        17 => (0x78, 1, 0x90, 40),
        23 => (0x80, 1, 0x98, 104),
        26 => (0x80, 8, 0xD0, 104),
        v if v >= 30 => {
            // Windows 10 1507-1607 keep the run counter at 0xD0 (file metrics start at 0x130);
            // 1703 and later shrink the file information by 4 bytes (metrics at 0x12C) and the
            // counter moves to 0xC8.
            let rc = if metrics_offset == 0x12C { 0xC8 } else { 0xD0 };
            (0x80, 8, rc, 96)
        }
        v => return Err(format!("unsupported prefetch version {}", v)),
    };

    let mut last_runs = Vec::new();
    for i in 0..run_times_count {
        if let Some(ft) = u64_at(&data, run_times_offset + i * 8) {
            if ft != 0 {
                if let Some(iso) = filetime_to_iso(ft) {
                    last_runs.push(iso);
                }
            }
        }
    }
    let run_count = u32_at(&data, run_count_offset).unwrap_or(0);

    let mut files = Vec::new();
    if strings_offset < data.len() && strings_size > 0 {
        let end = (strings_offset + strings_size).min(data.len());
        let units: Vec<u16> = data[strings_offset..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        for part in units.split(|&u| u == 0) {
            if !part.is_empty() {
                files.push(String::from_utf16_lossy(part));
            }
        }
    }

    let mut volumes = Vec::new();
    for i in 0..volumes_count.min(16) {
        let base = volumes_offset + i * volume_entry_size;
        let (Some(path_off), Some(path_chars), Some(created), Some(serial)) =
            (u32_at(&data, base), u32_at(&data, base + 4), u64_at(&data, base + 8), u32_at(&data, base + 16))
        else {
            break;
        };
        let device = utf16_at(&data, volumes_offset + path_off as usize, (path_chars as usize) * 2);
        volumes.push(Volume { device, serial, created: filetime_to_iso(created).unwrap_or_default() });
    }

    Ok(Prefetch { version, executable, hash, run_count, last_runs, files, volumes })
}

/// One timeline row per recorded run.
pub fn events_for(pf: &Prefetch, source_name: &str, computer: &str) -> Vec<Event> {
    let exe_path = pf.executable_path().unwrap_or(&pf.executable).to_string();
    let volume = pf
        .volumes
        .first()
        .map(|v| format!("volume {} serial {:08X}", v.device, v.serial))
        .unwrap_or_default();
    let total = pf.last_runs.len();
    pf.last_runs
        .iter()
        .enumerate()
        .map(|(i, ts)| Event {
            timestamp: ts.clone(),
            computer: computer.to_string(),
            artifact: "prefetch".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: String::new(),
            target_username: String::new(),
            processname: exe_path.clone(),
            commandline: Some(format!(
                "Prefetch run {} of {} recorded (run count {}); {} files loaded; {}",
                total - i,
                total,
                pf.run_count,
                pf.files.len(),
                volume
            )),
            parentprocessname: source_name.to_string(),
        })
        .collect()
}

/// Parses a `.pf` file on disk into timeline rows.
pub fn parse_file(path: &Path, computer: &str) -> Result<Vec<Event>, String> {
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    // Debug aid: CAAREA_DUMP_PREFETCH=<dir> writes the decompressed image of every file there.
    if let Ok(dir) = std::env::var("CAAREA_DUMP_PREFETCH") {
        if let (Ok(plain), Some(name)) = (decompress_if_needed(&raw), path.file_name()) {
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(Path::new(&dir).join(name).with_extension("pf.bin"), plain);
        }
    }
    let pf = parse(&raw)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    Ok(events_for(&pf, &name, computer))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal plain version-30 prefetch image (224-byte file information).
    fn synthetic_v30() -> Vec<u8> {
        let mut d = vec![0u8; 0x400];
        d[0..4].copy_from_slice(&30u32.to_le_bytes());
        d[4..8].copy_from_slice(SCCA_MAGIC);
        let name: Vec<u8> = "CAAREA-TEST.EXE".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        d[0x10..0x10 + name.len()].copy_from_slice(&name);
        d[0x4C..0x50].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let metrics = 0x54 + 224;
        d[0x54..0x58].copy_from_slice(&(metrics as u32).to_le_bytes());
        // filename strings at 0x200
        let strings: Vec<u8> = "\\VOLUME{guid}\\WINDOWS\\SYSTEM32\\NTDLL.DLL\0\\VOLUME{guid}\\TEMP\\CAAREA-TEST.EXE\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        d[0x64..0x68].copy_from_slice(&0x200u32.to_le_bytes());
        d[0x68..0x6C].copy_from_slice(&(strings.len() as u32).to_le_bytes());
        d[0x200..0x200 + strings.len()].copy_from_slice(&strings);
        // one volume at 0x300: device path right after the 96-byte entry
        d[0x6C..0x70].copy_from_slice(&0x300u32.to_le_bytes());
        d[0x70..0x74].copy_from_slice(&1u32.to_le_bytes());
        let dev: Vec<u8> = "\\DEVICE\\HARDDISKVOLUME3".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        d[0x300..0x304].copy_from_slice(&96u32.to_le_bytes());
        d[0x304..0x308].copy_from_slice(&((dev.len() / 2) as u32).to_le_bytes());
        d[0x308..0x310].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        d[0x310..0x314].copy_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        d[0x360..0x360 + dev.len()].copy_from_slice(&dev);
        // two run times (2024-03-18T12:52:11Z and one hour earlier) and run count 7 at 0xD0
        let ft = 133_552_399_310_000_000u64; // 2024-03-18T12:52:11Z
        d[0x80..0x88].copy_from_slice(&ft.to_le_bytes());
        d[0x88..0x90].copy_from_slice(&(ft - 36_000_000_000).to_le_bytes());
        d[0xD0..0xD4].copy_from_slice(&7u32.to_le_bytes());
        d
    }

    #[test]
    fn parses_plain_v30() {
        let pf = parse(&synthetic_v30()).unwrap();
        assert_eq!(pf.version, 30);
        assert_eq!(pf.executable, "CAAREA-TEST.EXE");
        assert_eq!(pf.hash, 0xDEADBEEF);
        assert_eq!(pf.run_count, 7);
        assert_eq!(pf.last_runs.len(), 2);
        assert_eq!(pf.last_runs[0], "2024-03-18T12:52:11.000000Z");
        assert_eq!(pf.files.len(), 2);
        assert_eq!(pf.executable_path(), Some("\\VOLUME{guid}\\TEMP\\CAAREA-TEST.EXE"));
        assert_eq!(pf.volumes[0].device, "\\DEVICE\\HARDDISKVOLUME3");
        assert_eq!(pf.volumes[0].serial, 0xA1B2C3D4);

        let rows = events_for(&pf, "CAAREA-TEST.EXE-1234ABCD.pf", "HOST");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].artifact, "prefetch");
        assert_eq!(rows[0].processname, "\\VOLUME{guid}\\TEMP\\CAAREA-TEST.EXE");
        assert_eq!(rows[0].parentprocessname, "CAAREA-TEST.EXE-1234ABCD.pf");
        assert!(rows[0].commandline.as_deref().unwrap().contains("run count 7"));
    }

    #[test]
    fn v30_216_byte_layout_moves_the_run_counter() {
        let mut d = synthetic_v30();
        d[0x54..0x58].copy_from_slice(&0x12Cu32.to_le_bytes());
        d[0xD0..0xD4].copy_from_slice(&0u32.to_le_bytes());
        d[0xC8..0xCC].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(parse(&d).unwrap().run_count, 9);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[0u8; 300]).is_err());
        assert!(!is_prefetch(&[0u8; 8]));
        assert!(is_prefetch(b"MAM\x04\x10\x00\x00\x00"));
    }
}
