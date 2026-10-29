//! Linux structures carved from raw bytes: process-accounting records (64 bytes, strongly
//! typed), utmp session records (384 bytes), systemd journal files (`LPKSHHRH` header with
//! the file size inside), auditd lines (`type=... msg=audit(<epoch>.<ms>:<serial>)`, time
//! embedded) and shell history blocks with `#<epoch>` stamps. Everything here carries its own
//! time; classic syslog lines without a year are not carved on purpose.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::parsers::evtx::Event;
use crate::parsers::linux::{pacct, utmp};

pub use blockcarve::linux::{journal_size, JOURNAL_MAGIC};
const AUDIT_NEEDLE: &[u8] = b" msg=audit(";
const MAX_LINE: usize = 8192;

/// Text lines collected by the block scanner, written out once as files the Linux parsers
/// read: audit records keep their own time; history commands take the `#epoch` before them.
#[derive(Default)]
pub struct TextCarve {
    pub audit_lines: Vec<String>,
    pub history_lines: Vec<String>,
    seen: HashSet<u64>,
    pub first_audit: Option<u64>,
    pub first_history: Option<u64>,
}

fn is_text_byte(b: u8) -> bool {
    b >= 0x20 || b == b'\t'
}

/// The text line starting at `start`: up to a newline or the first binary byte.
fn line_at(block: &[u8], start: usize) -> Option<&[u8]> {
    let rest = &block[start..];
    let end = rest.iter().take(MAX_LINE).position(|&b| !is_text_byte(b)).unwrap_or(rest.len().min(MAX_LINE));
    let line = &rest[..end];
    if line.is_empty() || line.len() >= MAX_LINE {
        return None;
    }
    Some(line)
}

/// Start of the text run that contains `pos`: after the previous newline or binary byte,
/// at most `max_back` bytes before `pos`.
fn run_start(block: &[u8], pos: usize, max_back: usize) -> usize {
    let mut ls = pos;
    while ls > 0 && pos - ls < max_back && is_text_byte(block[ls - 1]) && block[ls - 1] != b'\n' {
        ls -= 1;
    }
    ls
}

fn hash(bytes: &[u8]) -> u64 {
    blockcarve::content_hash(bytes)
}

impl TextCarve {
    /// Scans one block for audit lines and `#epoch` history pairs.
    pub fn scan_block(&mut self, base: u64, block: &[u8]) {
        // audit: " msg=audit(" preceded on the same line by "type=<WORD>"
        for pos in memchr::memmem::find_iter(block, AUDIT_NEEDLE) {
            let line_start = run_start(block, pos, 64);
            if !block[line_start..].starts_with(b"type=") {
                continue;
            }
            let Some(line) = line_at(block, line_start) else { continue };
            // epoch sanity: audit(1234567890.123:456)
            let after = &line[pos - line_start + AUDIT_NEEDLE.len()..];
            let digits = after.iter().take_while(|b| b.is_ascii_digit()).count();
            if digits != 10 {
                continue;
            }
            let h = hash(line);
            if self.seen.insert(h) {
                self.audit_lines.push(String::from_utf8_lossy(line).to_string());
                self.first_audit.get_or_insert(base + line_start as u64);
            }
        }
        // history: "#<10 digits>\n<command>"
        for pos in memchr::memmem::find_iter(block, b"#1") {
            if pos > 0 && is_text_byte(block[pos - 1]) && block[pos - 1] != b'\n' {
                continue;
            }
            let Some(stamp) = line_at(block, pos) else { continue };
            if stamp.len() != 11 || !stamp[1..].iter().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let cmd_start = pos + stamp.len() + 1;
            if cmd_start >= block.len() {
                continue;
            }
            let Some(cmd) = line_at(block, cmd_start) else { continue };
            if cmd.starts_with(b"#") || cmd.len() < 2 {
                continue;
            }
            let h = hash(&block[pos..cmd_start + cmd.len()]);
            if self.seen.insert(h) {
                self.history_lines.push(String::from_utf8_lossy(stamp).to_string());
                self.history_lines.push(String::from_utf8_lossy(cmd).to_string());
                self.first_history.get_or_insert(base + pos as u64);
            }
        }
    }

    /// Writes `audit.log` and `home/carved/.bash_history` under `out_dir`; returns the
    /// directories to parse with the offset of their first line.
    pub fn write(&self, out_dir: &Path) -> Vec<(PathBuf, u64, usize)> {
        let mut out = Vec::new();
        if !self.audit_lines.is_empty() {
            let dir = out_dir.join("audit_carved").join("var").join("log").join("audit");
            if std::fs::create_dir_all(&dir).is_ok() && std::fs::write(dir.join("audit.log"), self.audit_lines.join("\n") + "\n").is_ok() {
                out.push((out_dir.join("audit_carved"), self.first_audit.unwrap_or(0), self.audit_lines.len()));
            }
        }
        if !self.history_lines.is_empty() {
            let dir = out_dir.join("history_carved").join("home").join("carved");
            if std::fs::create_dir_all(&dir).is_ok() && std::fs::write(dir.join(".bash_history"), self.history_lines.join("\n") + "\n").is_ok() {
                out.push((out_dir.join("history_carved"), self.first_history.unwrap_or(0), self.history_lines.len() / 2));
            }
        }
        out
    }
}

/// Row for a process-accounting record at `buf`, if it passes the strict checks.
pub fn pacct_event(buf: &[u8], computer: &str) -> Option<Event> {
    let rec = pacct::carved_candidate(buf)?;
    pacct::record_event(&rec, computer)
}

/// Row for a utmp record at `buf`, if it passes the strict checks.
pub fn utmp_event(buf: &[u8], computer: &str) -> Option<Event> {
    let (big, _) = utmp::carved_candidate(buf)?;
    utmp::record_event(&buf[..384], big, false, computer, "carved utmp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_carving_finds_audit_and_history() {
        let block = b"garbage\x00\x00type=SYSCALL msg=audit(1710766331.243:24287): arch=c000003e syscall=59 success=yes pid=10 comm=\"nc\" exe=\"/usr/bin/nc\"\ntype=EXECVE msg=audit(1710766331.243:24287): argc=1 a0=\"nc\"\n\x00\x00#1710766400\nwhoami /all\n#1710766401\ncat /etc/shadow\n#notadate\nx\n";
        let mut t = TextCarve::default();
        t.scan_block(1000, block);
        assert_eq!(t.audit_lines.len(), 2);
        assert_eq!(t.history_lines, vec!["#1710766400", "whoami /all", "#1710766401", "cat /etc/shadow"]);
        assert_eq!(t.first_audit, Some(1009));
        // the same block again adds nothing
        t.scan_block(1000, block);
        assert_eq!(t.audit_lines.len(), 2);
        assert_eq!(t.history_lines.len(), 4);
    }

    #[test]
    fn journal_header_size() {
        let mut h = vec![0u8; 0x100];
        h[..8].copy_from_slice(JOURNAL_MAGIC);
        h[0x58..0x60].copy_from_slice(&0xf0u64.to_le_bytes());
        h[0x60..0x68].copy_from_slice(&(8u64 << 20).to_le_bytes());
        assert_eq!(journal_size(&h), Some(0xf0 + (8 << 20)));
        assert!(journal_size(&[0u8; 0x100]).is_none());
    }
}
