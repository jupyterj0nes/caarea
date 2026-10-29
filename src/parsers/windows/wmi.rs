//! WMI repository `OBJECTS.DATA` (`Windows\System32\wbem\Repository`): permanent event
//! subscriptions, the persistence that runs a command line or a script when a filter
//! fires. Instances are found by their class name in the raw pages (the same approach as
//! PyWMIPersistenceFinder), so deleted subscriptions still in unused page space come back
//! too. Every instance record starts with the class-name hash, two FILETIMEs (the WMI
//! service start at the time of the write, with a sequence counter in the low digits, and
//! the class definition's time) and the block size; when that header is found around a
//! hit the row takes the first stamp (a lower bound for the write) and its strings stop at
//! the block's end, otherwise the file time and a bounded window.

use std::collections::HashSet;
use std::path::Path;

use memchr::memmem;

use super::text::file_mtime_iso;
use crate::parsers::evtx::Event;
use crate::utils::filetime_to_iso;

const MARKERS: &[(&[u8], &str)] = &[
    (b"CommandLineEventConsumer", "wmi:commandline_consumer"),
    (b"ActiveScriptEventConsumer", "wmi:script_consumer"),
    (b"__EventFilter", "wmi:event_filter"),
    (b"__FilterToConsumerBinding", "wmi:binding"),
];

/// Strings that only class definitions hold (property names and CIM type names): a hit
/// followed by these is the class itself, present on every Windows installation.
const DEFINITION_WORDS: &[&str] = &[
    "CommandLineTemplate",
    "ScriptText",
    "QueryLanguage",
    "EventNamespace",
    "DeliveryQoS",
    "MaintainSecurityContext",
    "boolean",
    "uint32",
    "sint32",
    "uint64",
    "uint16",
    "uint8",
    "string",
    "datetime",
    "abstract",
    "not_null",
    "Description",
];

const WINDOW: usize = 4096;

pub fn is_objects_data(name: &str) -> bool {
    name.eq_ignore_ascii_case("OBJECTS.DATA")
}

/// A record found at `hit`: the strings that follow it and its own time.
#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub artifact: &'static str,
    pub strings: Vec<String>,
    pub filetime: Option<u64>,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}

/// Length of a binary SID at `pos` (`01 <count> 00 00 00 00 00 05 ...`), if one starts there.
fn sid_len(data: &[u8], pos: usize) -> Option<usize> {
    let b = data.get(pos..pos + 8)?;
    if b[0] == 1 && (1..=15).contains(&b[1]) && b[2..7] == [0, 0, 0, 0, 0] && (b[7] == 5 || b[7] == 1 || b[7] == 0) {
        Some(8 + 4 * b[1] as usize)
    } else {
        None
    }
}

/// True when a UTF-16 run (`char 00` pairs) of at least `n` printable characters starts here:
/// the hash header of the next instance record or a class name of the next definition.
fn utf16_run(data: &[u8], pos: usize, n: usize) -> bool {
    data.get(pos..pos + 2 * n).is_some_and(|w| w.chunks_exact(2).all(|c| printable(c[0]) && c[1] == 0))
}

/// Nul-separated printable ASCII strings after the marker, up to `end`.
fn strings_after(data: &[u8], from: usize, end: usize) -> Vec<String> {
    let end = end.min(data.len());
    let mut out = Vec::new();
    let mut pos = from;
    let mut gap = 0usize;
    while pos < end && out.len() < 12 {
        if let Some(n) = sid_len(data, pos) {
            pos += n;
            continue;
        }
        if utf16_run(data, pos, 4) {
            break;
        }
        if printable(data[pos]) {
            let start = pos;
            while pos < end && printable(data[pos]) {
                pos += 1;
            }
            let s = std::str::from_utf8(&data[start..pos]).unwrap_or_default();
            let hashy = s.len() >= 32 && s.bytes().all(|b| b.is_ascii_hexdigit());
            let wordy = s.bytes().filter(|b| b.is_ascii_alphanumeric()).count() >= 3;
            if s.len() >= 3 && !hashy && wordy {
                if MARKERS.iter().any(|(m, _)| s.as_bytes().starts_with(m)) && !out.is_empty() && !s.contains(".Name=") {
                    break;
                }
                out.push(s.to_string());
            }
            gap = 0;
        } else {
            pos += 1;
            gap += 1;
            if gap > 256 && !out.is_empty() {
                break;
            }
        }
    }
    out
}

fn plausible(ft: u64) -> bool {
    // 2000-01-01 .. 2100-01-01
    (125_911_584_000_000_000..157_469_184_000_000_000).contains(&ft)
}

/// The header of the instance record containing `hit`: its FILETIME and the end of its
/// block. The header is the class-name hash (32 or 64 hex digits, UTF-16 on Vista and
/// later, ASCII before), a FILETIME and the block size.
fn record_header(data: &[u8], hit: usize) -> Option<(u64, usize)> {
    let floor = hit.saturating_sub(2048);
    let mut pos = hit.saturating_sub(12);
    while pos > floor {
        for (hash_len, utf16) in [(128usize, true), (64, true), (64, false), (32, false)] {
            if pos < hash_len + floor {
                continue;
            }
            let run = &data[pos - hash_len..pos];
            let ok = if utf16 {
                run.chunks_exact(2).all(|c| c[0].is_ascii_hexdigit() && c[1] == 0)
            } else {
                run.iter().all(|b| b.is_ascii_hexdigit())
            };
            // hash | FILETIME of the record | FILETIME of the class definition | u32 block size
            if ok && pos + 20 <= data.len() {
                let ft = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                let size = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap()) as usize;
                let block_start = pos + 20;
                if plausible(ft) && size > 0 && size < 1 << 20 && hit >= block_start && hit < block_start + size {
                    return Some((ft, block_start + size));
                }
                return None;
            }
        }
        pos -= 1;
    }
    None
}

pub fn scan(data: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut seen: HashSet<(&'static str, Vec<String>)> = HashSet::new();
    for (marker, artifact) in MARKERS {
        for pos in memmem::find_iter(data, marker) {
            let after = pos + marker.len();
            // `CommandLineEventConsumer.Name="x"`: a reference inside a binding, not an instance
            if data.get(after).is_some_and(|&b| printable(b)) {
                continue;
            }
            let header = record_header(data, pos);
            let end = header.map(|(_, e)| e).unwrap_or(after + WINDOW);
            let strings = strings_after(data, after, end);
            if strings.is_empty() || strings.iter().any(|s| DEFINITION_WORDS.contains(&s.as_str())) {
                continue;
            }
            // `\\.\root\subscription:__Win32Provider.Name="..."`: the provider registration
            // of the consumer class, present on every installation
            if strings[0].starts_with("\\\\.\\") {
                continue;
            }
            let key = (*artifact, strings.clone());
            if !seen.insert(key) {
                continue;
            }
            hits.push(Hit { artifact, strings, filetime: header.map(|(ft, _)| ft) });
        }
    }
    hits
}

/// The `Name="..."` part of a WMI object reference.
fn ref_name(s: &str) -> Option<&str> {
    let i = s.find(".Name=\"")? + 7;
    let rest = &s[i..];
    Some(&rest[..rest.find('"').unwrap_or(rest.len())])
}

/// What to put in the process column for a hit: the command line for consumers, the
/// filter name for filters, `filter -> consumer` for bindings.
fn subject(hit: &Hit) -> String {
    match hit.artifact {
        "wmi:event_filter" => {
            let q = hit.strings.iter().position(|s| s.to_ascii_lowercase().starts_with("select"));
            match q {
                Some(i) if i > 0 => hit.strings[i - 1].clone(),
                _ => hit.strings[0].clone(),
            }
        }
        "wmi:binding" => {
            let filter = hit.strings.iter().filter(|s| s.starts_with("__EventFilter")).find_map(|s| ref_name(s));
            let consumer = hit.strings.iter().filter(|s| !s.starts_with("__EventFilter")).find_map(|s| ref_name(s));
            match (filter, consumer) {
                (Some(f), Some(c)) => format!("{} -> {}", f, c),
                _ => hit.strings[0].clone(),
            }
        }
        _ => hit.strings[0].clone(),
    }
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    let mtime = file_mtime_iso(path);
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut events = Vec::new();
    for hit in scan(&data) {
        // The record stamp is the WMI service's start time with a sequence counter in the
        // low digits (checked against System 7036 on a lab host): the instance was written
        // after that moment, during that service lifetime.
        let (ts, when) = match hit.filetime.and_then(filetime_to_iso) {
            Some(t) => (t, "written after the WMI service start stamped on the record"),
            None if !mtime.is_empty() => (mtime.clone(), "file time"),
            None => continue,
        };
        let what = match hit.artifact {
            "wmi:commandline_consumer" => "WMI CommandLineEventConsumer",
            "wmi:script_consumer" => "WMI ActiveScriptEventConsumer",
            "wmi:event_filter" => "WMI __EventFilter",
            _ => "WMI __FilterToConsumerBinding",
        };
        events.push(Event {
            timestamp: ts,
            computer: computer.to_string(),
            artifact: hit.artifact.to_string(),
            event_id: 0,
            pid: 0,
            subject_username: String::new(),
            target_username: String::new(),
            processname: subject(&hit),
            commandline: Some(format!("{} ({}): {}", what, when, hit.strings.join(" | "))),
            parentprocessname: source.clone(),
        });
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_hex(n: usize) -> Vec<u8> {
        "ABCDEF0123456789".bytes().cycle().take(n).flat_map(|b| [b, 0]).collect()
    }

    #[test]
    fn finds_consumer_with_record_time_and_skips_sid() {
        // 28-byte SID (5 sub-authorities) whose bytes happen to spell printable runs
        let body = b"\0CommandLineEventConsumer\0\x01\x05\0\0\0\0\0\x05\x15\0\0\0Ekk\0abcdefghijkl\0\0cmd.exe /c calc.exe\0\0Evil\0\0";
        let mut d = vec![0u8; 100];
        d.extend(utf16_hex(64));
        d.extend_from_slice(&133_000_000_000_000_000u64.to_le_bytes()); // 2022-06-28
        d.extend_from_slice(&131_800_000_000_000_000u64.to_le_bytes()); // class definition time
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(body);
        d.extend_from_slice(b"\0junk after the block\0");
        d.extend(vec![0u8; 100]);
        let hits = scan(&d);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].artifact, "wmi:commandline_consumer");
        assert_eq!(hits[0].strings, vec!["cmd.exe /c calc.exe", "Evil"]);
        assert_eq!(hits[0].filetime, Some(133_000_000_000_000_000));
    }

    #[test]
    fn skips_definitions_and_references() {
        let d = b"\0CommandLineEventConsumer\0\0CommandLineTemplate\0\0ExecutablePath\0 \0__FilterToConsumerBinding\0\0__EventFilter.Name=\"F\"\0\0CommandLineEventConsumer.Name=\"C\"\0\0".to_vec();
        let hits = scan(&d);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].artifact, "wmi:binding");
        assert_eq!(hits[0].strings, vec!["__EventFilter.Name=\"F\"", "CommandLineEventConsumer.Name=\"C\""]);
        assert!(hits[0].filetime.is_none());
        assert_eq!(subject(&hits[0]), "F -> C");
    }

    #[test]
    fn filter_subject_is_the_name_before_the_query() {
        let hit = Hit { artifact: "wmi:event_filter", strings: vec!["root\\cimv2".into(), "Bad".into(), "SELECT * FROM X".into(), "WQL".into()], filetime: None };
        assert_eq!(subject(&hit), "Bad");
    }
}
