//! Windows file-based execution artifacts that are neither event logs nor registry hives:
//! Prefetch, PowerShell console history, scheduled task XML, Windows Error Reporting,
//! Defender support logs, Program Compatibility Assistant logs.

pub mod mplog;
pub mod pca;
pub mod prefetch;
pub mod psreadline;
pub mod tasks_xml;
pub mod text;
pub mod wer;
pub mod xpress;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::Local;
use walkdir::WalkDir;

use crate::parsers::evtx::Event;
use crate::parsers::registry;
use crate::utils::is_registry_hive;

fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Host name for a Windows evidence tree: the ingestion hint, else the ComputerName of a
/// SYSTEM hive found under the tree, else "Unknown".
pub fn detect_hostname(target: &Path, hint: Option<&str>) -> String {
    if let Some(h) = hint {
        return h.to_string();
    }
    for entry in WalkDir::new(target).max_depth(8).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        let looks_system = name == "system" || name.ends_with("_system") || name.ends_with("-system");
        if looks_system && is_registry_hive(&head(entry.path(), 4)) {
            if let Some(c) = registry::detect_computer_name(entry.path()) {
                return c;
            }
        }
    }
    "Unknown".to_string()
}

fn head(path: &Path, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let got = std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)).unwrap_or(0);
    buf.truncate(got);
    buf
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Prefetch,
    History,
    TaskXml,
    Wer,
    MpLog,
    Pca,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Prefetch => "Prefetch",
            Kind::History => "PowerShell history",
            Kind::TaskXml => "Task XML",
            Kind::Wer => "WER reports",
            Kind::MpLog => "Defender logs",
            Kind::Pca => "PCA logs",
        }
    }
}

/// Classifies a file by name, and by content for the extension-less task definitions.
fn classify(path: &Path) -> Option<Kind> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".pf") {
        return Some(Kind::Prefetch);
    }
    if psreadline::is_history_file(&name) {
        return Some(Kind::History);
    }
    if wer::is_report(&name) {
        return Some(Kind::Wer);
    }
    if mplog::is_mplog(&name) {
        return Some(Kind::MpLog);
    }
    if pca::is_pca_file(&name) {
        return Some(Kind::Pca);
    }
    // Task definitions have no extension; only look at files under a "Tasks" folder (or
    // any file called *.xml) to keep the content sniff cheap.
    let under_tasks = path
        .components()
        .any(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case("tasks"));
    if (under_tasks && !lower.contains('.')) || lower.ends_with(".xml") {
        let h = head(path, 600);
        if tasks_xml::is_task_xml(&h) {
            return Some(Kind::TaskXml);
        }
    }
    None
}

fn parse_kind(kind: Kind, path: &Path, computer: &str, silent: bool) -> Vec<Event> {
    match kind {
        Kind::Prefetch => match prefetch::parse_file(path, computer) {
            Ok(rows) => rows,
            Err(e) => {
                log_message(silent, &format!("  ⚠️ Prefetch {}: {}", path.display(), e));
                Vec::new()
            }
        },
        Kind::History => psreadline::parse_file(path, computer),
        Kind::TaskXml => tasks_xml::parse_file(path, computer),
        Kind::Wer => wer::parse_file(path, computer),
        Kind::MpLog => mplog::parse_file(path, computer),
        Kind::Pca => pca::parse_file(path, computer),
    }
}

/// Walks `target` for Windows file artifacts and returns their timeline rows.
pub fn process_windows_target(target: &Path, silent: bool, hint: Option<&str>) -> Vec<Event> {
    let mut found: BTreeMap<Kind, Vec<PathBuf>> = BTreeMap::new();
    for entry in WalkDir::new(target).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(kind) = classify(entry.path()) {
            found.entry(kind).or_default().push(entry.into_path());
        }
    }
    if found.is_empty() {
        return Vec::new();
    }
    let computer = detect_hostname(target, hint);
    let mut events = Vec::new();
    let mut summary = Vec::new();
    for (kind, paths) in &found {
        let before = events.len();
        for path in paths {
            events.extend(parse_kind(*kind, path, &computer, silent));
        }
        summary.push(format!("{} {} file(s) -> {} rows", paths.len(), kind.label(), events.len() - before));
    }
    log_message(silent, &format!("🗂️ Windows artifacts [host: {}]: {}", computer, summary.join("; ")));
    events
}

/// Parses a single Windows file artifact given with `-f`. `None` when the file is not one.
pub fn process_windows_file(path: &Path, header: &[u8], silent: bool) -> Option<Vec<Event>> {
    let kind = if prefetch::is_prefetch(header) { Some(Kind::Prefetch) } else { classify(path) }?;
    let computer = path.parent().map(|p| detect_hostname(p, None)).unwrap_or_else(|| "Unknown".to_string());
    Some(parse_kind(kind, path, &computer, silent))
}
