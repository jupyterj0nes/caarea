//! Recovery of deleted registry keys and values from the free cells of a hive.
//!
//! When a key or value is deleted, Windows only flips the sign of its cell size: the bytes
//! stay in place until the space is reused. This module walks every hive bin with its own
//! bounds-checked parser (free cells may hold garbage, so nothing here trusts a count or an
//! offset without checking it), rebuilds the path of each deleted key through the parent
//! chain, and turns the ones that record executions into rows with the `deleted` origin:
//! BAM entries, Run values, services, scheduled tasks, UserAssist, MUICache, Amcache
//! programs and files. The cell walker is the one faramir uses for deleted persistence.

use std::collections::{HashMap, HashSet};

use crate::parsers::evtx::Event;
use crate::provenance::{Origin, Provenance};
use crate::utils::{filetime_to_iso, resolve_sid};

const BASE_BLOCK_SIZE: usize = 4096;
const HBIN_HEADER: usize = 32;
const NK_FIXED: usize = 0x4c;
const VK_FIXED: usize = 0x14;
const MAX_VALUES_PER_KEY: u32 = 4096;
const MAX_DATA_BYTES: usize = 64 * 1024;
const MAX_NAME_BYTES: usize = 512;
const MAX_CHAIN: usize = 128;
/// FILETIME bounds for "plausible" binary timestamps (2000-01-01 .. 2040-01-01).
const FT_MIN: u64 = 125_911_584_000_000_000;
const FT_MAX: u64 = 138_535_776_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawKey {
    pub offset: u32,
    pub allocated: bool,
    pub name: String,
    pub parent: u32,
    pub timestamp_filetime: u64,
    pub values_count: u32,
    pub values_list: u32,
    pub is_root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawValue {
    pub offset: u32,
    pub allocated: bool,
    pub name: String,
    pub data_type: u32,
    /// REG_SZ / REG_EXPAND_SZ text.
    pub text: Option<String>,
    /// First bytes of REG_BINARY / REG_QWORD data (up to 64).
    pub binary: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedKey {
    pub key: RawKey,
    /// Root-relative path, or `?\<reachable tail>` when the parent chain is broken.
    pub path: String,
    pub values: Vec<RawValue>,
}

#[derive(Debug, Default, Clone)]
pub struct DeletedScan {
    pub bins: usize,
    pub cells: usize,
    pub live_keys: usize,
    pub deleted_keys: Vec<DeletedKey>,
    pub orphan_values: Vec<RawValue>,
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

fn decode_name(raw: &[u8], ascii: bool) -> Option<String> {
    let s = if ascii {
        raw.iter().map(|&b| b as char).collect::<String>()
    } else {
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16(&units).ok()?
    };
    if s.is_empty() || s.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(s)
}

fn decode_utf16_string(raw: &[u8]) -> String {
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// Bounds-checked view over a hive's bytes.
pub struct HiveImage<'a> {
    bytes: &'a [u8],
    root_cell: u32,
}

impl<'a> HiveImage<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < BASE_BLOCK_SIZE + HBIN_HEADER || &bytes[..4] != b"regf" {
            return None;
        }
        Some(HiveImage { bytes, root_cell: u32_at(bytes, 0x24) })
    }

    /// Last-written time of the hive itself (base block).
    pub fn hive_timestamp(&self) -> u64 {
        u64_at(self.bytes, 0x0c)
    }

    fn region(&self) -> &[u8] {
        &self.bytes[BASE_BLOCK_SIZE..]
    }

    /// Cell at `off` (relative to the bins): (allocated, payload after the size field).
    fn cell(&self, off: u32) -> Option<(bool, &[u8])> {
        let r = self.region();
        let o = off as usize;
        if o + 4 > r.len() || !o.is_multiple_of(8) {
            return None;
        }
        let raw = i32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
        let size = raw.unsigned_abs() as usize;
        if size < 8 || !size.is_multiple_of(8) || o + size > r.len() {
            return None;
        }
        Some((raw < 0, &r[o + 4..o + size]))
    }

    fn parse_nk(&self, off: u32) -> Option<RawKey> {
        let (allocated, p) = self.cell(off)?;
        if p.len() < NK_FIXED || &p[..2] != b"nk" {
            return None;
        }
        let flags = u16_at(p, 2);
        let name_len = u16_at(p, 0x48) as usize;
        if name_len == 0 || name_len > MAX_NAME_BYTES || NK_FIXED + name_len > p.len() {
            return None;
        }
        let name = decode_name(&p[NK_FIXED..NK_FIXED + name_len], flags & 0x20 != 0)?;
        Some(RawKey {
            offset: off,
            allocated,
            name,
            parent: u32_at(p, 0x10),
            timestamp_filetime: u64_at(p, 0x04),
            values_count: u32_at(p, 0x24),
            values_list: u32_at(p, 0x28),
            is_root: flags & 0x04 != 0 || off == self.root_cell,
        })
    }

    fn parse_vk(&self, off: u32) -> Option<RawValue> {
        let (allocated, p) = self.cell(off)?;
        if p.len() < VK_FIXED || &p[..2] != b"vk" {
            return None;
        }
        let name_len = u16_at(p, 2) as usize;
        let data_size = u32_at(p, 4);
        let data_field = u32_at(p, 8);
        let data_type = u32_at(p, 12);
        let flags = u16_at(p, 16);
        if name_len > MAX_NAME_BYTES || VK_FIXED + name_len > p.len() {
            return None;
        }
        let name = if name_len == 0 { "(Default)".to_string() } else { decode_name(&p[VK_FIXED..VK_FIXED + name_len], flags & 1 != 0)? };
        let raw = self.raw_data(data_size, data_field);
        let (text, binary) = match data_type {
            1 | 2 => (raw.as_deref().map(decode_utf16_string), None),
            3 | 11 => (None, raw.map(|r| r[..r.len().min(64)].to_vec())),
            _ => (None, None),
        };
        Some(RawValue { offset: off, allocated, name, data_type, text, binary })
    }

    fn raw_data(&self, data_size: u32, data_field: u32) -> Option<Vec<u8>> {
        let len = (data_size & 0x7fff_ffff) as usize;
        if data_size & 0x8000_0000 != 0 {
            let bytes = data_field.to_le_bytes();
            return Some(bytes[..len.min(4)].to_vec());
        }
        if len == 0 || len > MAX_DATA_BYTES {
            return None;
        }
        let (_, p) = self.cell(data_field)?;
        if p.len() < len {
            return None;
        }
        Some(p[..len].to_vec())
    }

    fn values_of(&self, key: &RawKey, referenced: &mut HashSet<u32>) -> Vec<RawValue> {
        let count = key.values_count;
        if count == 0 || count > MAX_VALUES_PER_KEY || key.values_list == 0xffff_ffff {
            return Vec::new();
        }
        let Some((_, list)) = self.cell(key.values_list) else { return Vec::new() };
        let mut out = Vec::new();
        for i in 0..count as usize {
            if (i + 1) * 4 > list.len() {
                break;
            }
            let vk_off = u32_at(list, i * 4);
            if let Some(v) = self.parse_vk(vk_off) {
                referenced.insert(vk_off);
                out.push(v);
            }
        }
        out
    }

    /// Walks every hive bin and classifies its cells.
    pub fn scan(&self) -> DeletedScan {
        let r = self.region();
        let mut scan = DeletedScan::default();
        let mut keys: HashMap<u32, RawKey> = HashMap::new();
        let mut free_vk: Vec<u32> = Vec::new();

        let mut pos = 0usize;
        while pos + HBIN_HEADER <= r.len() {
            if &r[pos..pos + 4] != b"hbin" {
                pos += 4096;
                continue;
            }
            let size = u32_at(r, pos + 8) as usize;
            if size == 0 || !size.is_multiple_of(4096) || pos + size > r.len() {
                pos += 4096;
                continue;
            }
            scan.bins += 1;
            let end = pos + size;
            let mut c = pos + HBIN_HEADER;
            while c + 8 <= end {
                let raw = i32::from_le_bytes([r[c], r[c + 1], r[c + 2], r[c + 3]]);
                let csize = raw.unsigned_abs() as usize;
                if csize < 8 || !csize.is_multiple_of(8) || c + csize > end {
                    break;
                }
                scan.cells += 1;
                let magic = &r[c + 4..c + 6];
                let off = c as u32;
                if magic == b"nk" {
                    if let Some(k) = self.parse_nk(off) {
                        if k.allocated {
                            scan.live_keys += 1;
                        }
                        keys.insert(off, k);
                    }
                } else if magic == b"vk" && raw > 0 {
                    free_vk.push(off);
                }
                c += csize;
            }
            pos = end;
        }

        let mut referenced: HashSet<u32> = HashSet::new();
        let mut deleted: Vec<DeletedKey> = Vec::new();
        for key in keys.values().filter(|k| !k.allocated) {
            let path = self.resolve_path(key, &keys);
            let values = self.values_of(key, &mut referenced);
            deleted.push(DeletedKey { key: key.clone(), path, values });
        }
        deleted.sort_by(|a, b| a.path.cmp(&b.path).then(a.key.offset.cmp(&b.key.offset)));
        scan.deleted_keys = deleted;

        for off in free_vk {
            if referenced.contains(&off) {
                continue;
            }
            if let Some(v) = self.parse_vk(off) {
                scan.orphan_values.push(v);
            }
        }
        scan
    }

    fn resolve_path(&self, key: &RawKey, keys: &HashMap<u32, RawKey>) -> String {
        let mut parts = vec![key.name.clone()];
        let mut cur = key.parent;
        let mut hops = 0;
        loop {
            if cur == self.root_cell {
                parts.reverse();
                return parts.join("\\");
            }
            hops += 1;
            if hops > MAX_CHAIN {
                break;
            }
            match keys.get(&cur) {
                Some(p) if p.is_root => {
                    parts.reverse();
                    return parts.join("\\");
                }
                Some(p) => {
                    parts.push(p.name.clone());
                    cur = p.parent;
                }
                None => break,
            }
        }
        parts.push("?".to_string());
        parts.reverse();
        parts.join("\\")
    }
}

// ─── turning recovered cells into execution rows ───────────────────────────

fn looks_executable(s: &str) -> bool {
    let d = s.trim().to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    let ext = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".com", ".msi", ".hta", ".sys"];
    ext.iter().any(|e| d.contains(e)) || d.contains(":\\") || d.starts_with("\\device\\")
}

fn plausible_filetime(ft: u64) -> bool {
    (FT_MIN..FT_MAX).contains(&ft)
}

/// Segment of a path after `marker` (case-insensitive), e.g. the SID after `UserSettings\`.
fn after<'a>(path: &'a str, marker: &str) -> Option<&'a str> {
    let lower = path.to_ascii_lowercase();
    let m = marker.to_ascii_lowercase();
    let p = lower.find(&m)? + m.len();
    Some(&path[p..])
}

fn contains_ci(path: &str, needle: &str) -> bool {
    path.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

/// What a deleted key means for the timeline: `(artifact, process name, description)`.
fn classify_key(dk: &DeletedKey) -> Option<(&'static str, String, String)> {
    let path = dk.path.strip_prefix("?\\").unwrap_or(&dk.path);
    let name = dk.key.name.clone();
    let text = |n: &str| dk.values.iter().find(|v| v.name.eq_ignore_ascii_case(n)).and_then(|v| v.text.clone()).unwrap_or_default();
    if contains_ci(path, "\\Services\\") && !contains_ci(path, "\\bam\\") {
        let image = text("ImagePath");
        let parent_is_services = path.to_ascii_lowercase().ends_with(&format!("\\services\\{}", name.to_ascii_lowercase()));
        if parent_is_services {
            return Some((
                "registry:services",
                if image.is_empty() { name.clone() } else { image.clone() },
                format!("Service key deleted: {} ImagePath={} DisplayName={}", name, image, text("DisplayName")),
            ));
        }
    }
    if contains_ci(path, "\\CurrentVersion\\Run") {
        let cmds: Vec<String> = dk.values.iter().filter_map(|v| v.text.clone()).filter(|t| !t.trim().is_empty()).collect();
        return Some((
            "registry:runkeys",
            cmds.first().cloned().unwrap_or_else(|| name.clone()),
            format!("Run key deleted: {} values: {}", path, cmds.join(" | ")),
        ));
    }
    if contains_ci(path, "TaskCache\\Tree\\") {
        return Some(("registry:tasks", name.clone(), format!("Scheduled task deleted (TaskCache\\Tree): {} Id={}", path, text("Id"))));
    }
    if contains_ci(path, "TaskCache\\Tasks\\") {
        let task_path = text("Path");
        return Some((
            "registry:tasks",
            if task_path.is_empty() { name.clone() } else { task_path.clone() },
            format!("Scheduled task deleted (TaskCache\\Tasks): {} Author={} URI={}", task_path, text("Author"), text("URI")),
        ));
    }
    if contains_ci(path, "InventoryApplicationFile\\") {
        let p = text("LowerCaseLongPath");
        return Some(("registry:amcache:file", if p.is_empty() { name.clone() } else { p }, format!("Amcache file entry deleted: {} {}", name, text("ProductName"))));
    }
    if contains_ci(path, "InventoryApplication\\") {
        return Some(("registry:amcache:program", text("Name"), format!("Amcache program entry deleted: {} {} {}", text("Name"), text("Version"), text("Publisher"))));
    }
    if contains_ci(path, "\\UserAssist\\") && contains_ci(path, "\\Count") {
        return Some(("registry:userassist", name.clone(), format!("UserAssist key deleted: {}", path)));
    }
    if contains_ci(path, "\\Shell\\MuiCache") {
        return Some(("registry:muicache", name.clone(), format!("MUICache key deleted: {}", path)));
    }
    if contains_ci(path, "Compatibility Assistant\\Store") {
        return Some(("registry:pca_store", name.clone(), format!("PCA store key deleted: {}", path)));
    }
    // generic: any deleted key holding something that looks like a command
    let exec_values: Vec<String> = dk
        .values
        .iter()
        .filter_map(|v| v.text.as_ref().map(|t| format!("{}={}", v.name, t)))
        .filter(|t| looks_executable(t))
        .collect();
    if !exec_values.is_empty() {
        return Some(("registry:deleted_key", exec_values[0].split_once('=').map(|(_, v)| v.to_string()).unwrap_or_default(), format!("Deleted key {}: {}", path, exec_values.join(" | "))));
    }
    None
}

/// Rows for one hive. `user` and `computer` are the ones the live parse decided.
pub fn events_for_hive(bytes: &[u8], computer: &str, user: &str, source: &str) -> (Vec<Event>, usize, usize) {
    let Some(image) = HiveImage::new(bytes) else { return (Vec::new(), 0, 0) };
    let scan = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| image.scan())) {
        Ok(s) => s,
        Err(_) => return (Vec::new(), 0, 0),
    };
    let deleted = Provenance::new(Origin::Deleted, "");
    let hive_time = filetime_to_iso(image.hive_timestamp());
    let mut events = Vec::new();
    let mk = |ts: String, artifact: &str, user: String, proc: String, details: String| Event {
        timestamp: ts,
        computer: computer.to_string(),
        artifact: deleted.apply(artifact),
        event_id: 0,
        pid: 0,
        subject_username: user.clone(),
        target_username: user,
        processname: proc,
        commandline: Some(details),
        parentprocessname: source.to_string(),
    };

    for dk in &scan.deleted_keys {
        let lower = dk.path.to_ascii_lowercase();
        // BAM: the deleted key is a user's SID folder; its values are the executions
        if lower.contains("\\bam\\state\\usersettings\\") {
            let sid = after(&dk.path, "UserSettings\\").unwrap_or("").split('\\').next().unwrap_or("").to_string();
            let who = if sid.starts_with("S-1-") { resolve_sid(&sid) } else { user.to_string() };
            for v in &dk.values {
                if let Some(bin) = &v.binary {
                    if bin.len() >= 8 {
                        let ft = u64::from_le_bytes(bin[..8].try_into().unwrap());
                        if plausible_filetime(ft) {
                            if let Some(ts) = filetime_to_iso(ft) {
                                events.push(mk(ts, "registry:bam", who.clone(), v.name.clone(), format!("BAM entry recovered from deleted key {}", dk.path)));
                            }
                        }
                    }
                }
            }
            continue;
        }
        let Some((artifact, proc, details)) = classify_key(dk) else { continue };
        let Some(ts) = filetime_to_iso(dk.key.timestamp_filetime) else { continue };
        events.push(mk(ts, artifact, user.to_string(), proc, format!("{} (key last written)", details)));
    }

    // Orphan values: freed vk cells no deleted key points to. BAM executions carry their own
    // FILETIME; Run-style commands only have the hive's last write as an upper bound.
    for v in &scan.orphan_values {
        if let Some(bin) = &v.binary {
            if bin.len() >= 8 && (v.name.contains(":\\") || v.name.to_ascii_lowercase().starts_with("\\device\\")) {
                let ft = u64::from_le_bytes(bin[..8].try_into().unwrap());
                if plausible_filetime(ft) {
                    if let Some(ts) = filetime_to_iso(ft) {
                        events.push(mk(ts, "registry:bam", user.to_string(), v.name.clone(), "BAM entry recovered from a freed value (key unknown)".to_string()));
                    }
                }
            }
            continue;
        }
        if let Some(text) = &v.text {
            if looks_executable(text) && !text.trim().is_empty() {
                if let Some(ts) = hive_time.clone() {
                    events.push(mk(
                        ts,
                        "registry:deleted_value",
                        user.to_string(),
                        text.clone(),
                        format!("Freed value {} = {} (key unknown; time is the hive's last write)", v.name, text),
                    ));
                }
            }
        }
    }
    (events, scan.deleted_keys.len(), scan.orphan_values.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a tiny hive: root key "ROOT", live child "Run" with a freed value, a freed key
    /// "Evil" under Services with an ImagePath, and a freed BAM user key with one entry.
    fn synthetic_hive() -> Vec<u8> {
        let mut h = vec![0u8; 4096 + 8192];
        h[0..4].copy_from_slice(b"regf");
        h[0x0c..0x14].copy_from_slice(&133_552_399_310_000_000u64.to_le_bytes());
        h[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes()); // root cell offset
        let bins = 4096;
        h[bins..bins + 4].copy_from_slice(b"hbin");
        h[bins + 8..bins + 12].copy_from_slice(&8192u32.to_le_bytes());
        let mut cursor = 0x20usize; // relative to bins

        // helper closures write cells and return their relative offset
        let put_nk = |h: &mut Vec<u8>, cursor: &mut usize, allocated: bool, name: &str, parent: u32, root: bool, ts: u64, vcount: u32, vlist: u32| -> u32 {
            let size = (4 + NK_FIXED + name.len()).div_ceil(8) * 8;
            let off = *cursor;
            let abs = bins + off;
            let s = if allocated { -(size as i32) } else { size as i32 };
            h[abs..abs + 4].copy_from_slice(&s.to_le_bytes());
            let p = abs + 4;
            h[p..p + 2].copy_from_slice(b"nk");
            let flags: u16 = 0x20 | if root { 0x04 } else { 0 };
            h[p + 2..p + 4].copy_from_slice(&flags.to_le_bytes());
            h[p + 4..p + 12].copy_from_slice(&ts.to_le_bytes());
            h[p + 0x10..p + 0x14].copy_from_slice(&parent.to_le_bytes());
            h[p + 0x24..p + 0x28].copy_from_slice(&vcount.to_le_bytes());
            h[p + 0x28..p + 0x2c].copy_from_slice(&vlist.to_le_bytes());
            h[p + 0x48..p + 0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
            h[p + NK_FIXED..p + NK_FIXED + name.len()].copy_from_slice(name.as_bytes());
            *cursor += size;
            off as u32
        };
        let put_vk = |h: &mut Vec<u8>, cursor: &mut usize, allocated: bool, name: &str, data: &[u8], dtype: u32| -> u32 {
            // data cell
            let dsize = (4 + data.len()).div_ceil(8) * 8;
            let doff = *cursor;
            h[bins + doff..bins + doff + 4].copy_from_slice(&(-(dsize as i32)).to_le_bytes());
            h[bins + doff + 4..bins + doff + 4 + data.len()].copy_from_slice(data);
            *cursor += dsize;
            let size = (4 + VK_FIXED + name.len()).div_ceil(8) * 8;
            let off = *cursor;
            let abs = bins + off;
            let s = if allocated { -(size as i32) } else { size as i32 };
            h[abs..abs + 4].copy_from_slice(&s.to_le_bytes());
            let p = abs + 4;
            h[p..p + 2].copy_from_slice(b"vk");
            h[p + 2..p + 4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            h[p + 4..p + 8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            h[p + 8..p + 12].copy_from_slice(&(doff as u32).to_le_bytes());
            h[p + 12..p + 16].copy_from_slice(&dtype.to_le_bytes());
            h[p + 16..p + 18].copy_from_slice(&1u16.to_le_bytes());
            h[p + VK_FIXED..p + VK_FIXED + name.len()].copy_from_slice(name.as_bytes());
            *cursor += size;
            off as u32
        };
        let put_list = |h: &mut Vec<u8>, cursor: &mut usize, offs: &[u32]| -> u32 {
            let size = (4 + offs.len() * 4).div_ceil(8) * 8;
            let off = *cursor;
            h[bins + off..bins + off + 4].copy_from_slice(&(-(size as i32)).to_le_bytes());
            for (i, o) in offs.iter().enumerate() {
                h[bins + off + 4 + i * 4..bins + off + 8 + i * 4].copy_from_slice(&o.to_le_bytes());
            }
            *cursor += size;
            off as u32
        };

        let ts = 133_552_399_310_000_000u64;
        let root = put_nk(&mut h, &mut cursor, true, "ROOT", 0, true, ts, 0, 0xffff_ffff);
        assert_eq!(root, 0x20);
        let cs = put_nk(&mut h, &mut cursor, true, "ControlSet001", root, false, ts, 0, 0xffff_ffff);
        let services = put_nk(&mut h, &mut cursor, true, "Services", cs, false, ts, 0, 0xffff_ffff);
        let image: Vec<u8> = "C:\\Temp\\evil.exe -svc\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let vk_image = put_vk(&mut h, &mut cursor, false, "ImagePath", &image, 1);
        let list = put_list(&mut h, &mut cursor, &[vk_image]);
        put_nk(&mut h, &mut cursor, false, "EvilSvc", services, false, ts + 10_000_000, 1, list);
        // BAM user key, deleted, with one binary entry
        let bam = put_nk(&mut h, &mut cursor, true, "bam", services, false, ts, 0, 0xffff_ffff);
        let state = put_nk(&mut h, &mut cursor, true, "State", bam, false, ts, 0, 0xffff_ffff);
        let us = put_nk(&mut h, &mut cursor, true, "UserSettings", state, false, ts, 0, 0xffff_ffff);
        let mut entry = (ts + 20_000_000).to_le_bytes().to_vec();
        entry.extend_from_slice(&[0u8; 16]);
        let vk_bam = put_vk(&mut h, &mut cursor, false, "\\Device\\HarddiskVolume3\\Temp\\evil.exe", &entry, 3);
        let list2 = put_list(&mut h, &mut cursor, &[vk_bam]);
        put_nk(&mut h, &mut cursor, false, "S-1-5-18", us, false, ts, 1, list2);
        // orphan Run value
        let cmd: Vec<u8> = "cmd.exe /c evil\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        put_vk(&mut h, &mut cursor, false, "Updater", &cmd, 1);
        h
    }

    #[test]
    fn recovers_service_bam_and_orphan_value() {
        let hive = synthetic_hive();
        let (events, dkeys, orphans) = events_for_hive(&hive, "H", "SYSTEM", "SYSTEM");
        assert_eq!(dkeys, 2);
        assert_eq!(orphans, 1);
        let arts: Vec<&str> = events.iter().map(|e| e.artifact.as_str()).collect();
        assert!(arts.contains(&"registry:services:deleted"), "{:?}", arts);
        assert!(arts.contains(&"registry:bam:deleted"), "{:?}", arts);
        assert!(arts.contains(&"registry:deleted_value:deleted"), "{:?}", arts);
        let svc = events.iter().find(|e| e.artifact == "registry:services:deleted").unwrap();
        assert_eq!(svc.processname, "C:\\Temp\\evil.exe -svc");
        assert_eq!(svc.timestamp, "2024-03-18T12:52:12.000000Z");
        let bam = events.iter().find(|e| e.artifact == "registry:bam:deleted").unwrap();
        assert_eq!(bam.subject_username, "NT AUTHORITY\\SYSTEM");
        assert_eq!(bam.timestamp, "2024-03-18T12:52:13.000000Z");
        let orphan = events.iter().find(|e| e.artifact == "registry:deleted_value:deleted").unwrap();
        assert_eq!(orphan.processname, "cmd.exe /c evil");
        assert_eq!(orphan.timestamp, "2024-03-18T12:52:11.000000Z");
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(HiveImage::new(&[0u8; 100]).is_none());
        let mut junk = vec![0u8; 4096 + 4096];
        junk[..4].copy_from_slice(b"regf");
        let (events, k, o) = events_for_hive(&junk, "H", "u", "s");
        assert!(events.is_empty() && k == 0 && o == 0);
    }
}
