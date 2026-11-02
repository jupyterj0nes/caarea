//! Process hunting over the finished timeline: rules that mark rows an analyst should read
//! first, each with a score, an ATT&CK technique and an explanation in words.
//!
//! The hunt never touches the ten timeline columns. Findings go to their own CSV next to the
//! timeline (`<output>.hunt.csv`), one row per rule hit, with the lineage of the process and
//! the rows it was correlated with.

pub mod genealogy;
pub mod tree;

use crate::parsers::evtx::Event;
use crate::utils::escape_csv;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};

/// One rule hit on one timeline row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub timestamp: String,
    pub computer: String,
    pub rule_id: &'static str,
    pub category: &'static str,
    /// 0 to 100; above 80 is worth reading before anything else.
    pub score: u8,
    pub mitre: &'static str,
    pub title: String,
    pub explanation: String,
    /// `wininit.exe > services.exe > cmd.exe > powershell.exe`
    pub lineage: String,
    pub pid: u32,
    pub processname: String,
    pub commandline: String,
    pub parentprocessname: String,
    pub subject_username: String,
    pub artifact: String,
    /// Timestamps and names of the rows the finding was correlated with.
    pub related: String,
}

/// Runs every rule family over the timeline (sorted by time). `start`/`end` are canonical
/// timestamps: rows outside the window still feed the process tree but produce no finding.
pub fn run(events: &[Event], start: Option<&str>, end: Option<&str>) -> Vec<Finding> {
    let tree = tree::ProcessTree::build(events);
    let mut findings = genealogy::run(events, &tree);
    findings.retain(|f| start.map(|s| f.timestamp.as_str() >= s).unwrap_or(true) && end.map(|e| f.timestamp.as_str() <= e).unwrap_or(true));
    findings.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then(b.score.cmp(&a.score)).then(a.rule_id.cmp(b.rule_id)));
    findings
}

/// Hits per rule, for the run summary.
pub fn summary(findings: &[Finding]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        *m.entry(f.rule_id).or_insert(0) += 1;
    }
    m
}

pub const FINDINGS_HEADER: &str = "\"timestamp\",\"computer\",\"rule_id\",\"category\",\"score\",\"mitre\",\"title\",\"explanation\",\"lineage\",\"pid\",\"processname\",\"commandline\",\"parentprocessname\",\"subject_username\",\"artifact\",\"related\"";

/// Writes the findings CSV (RFC 4180, same quoting as the timeline).
pub fn export_findings(findings: &[Finding], path: &str) -> std::io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    writeln!(w, "{}", FINDINGS_HEADER)?;
    for f in findings {
        writeln!(
            w,
            "\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            escape_csv(&f.timestamp),
            escape_csv(&f.computer),
            f.rule_id,
            f.category,
            f.score,
            f.mitre,
            escape_csv(&f.title),
            escape_csv(&f.explanation),
            escape_csv(&f.lineage),
            f.pid,
            escape_csv(&f.processname),
            escape_csv(&f.commandline),
            escape_csv(&f.parentprocessname),
            escape_csv(&f.subject_username),
            escape_csv(&f.artifact),
            escape_csv(&f.related),
        )?;
    }
    w.flush()
}

/// Default findings path: `host.csv` becomes `host.hunt.csv`.
pub fn default_findings_path(output: &str) -> String {
    let p = std::path::Path::new(output);
    match (p.file_stem(), p.extension()) {
        (Some(stem), Some(ext)) => p
            .with_file_name(format!("{}.hunt.{}", stem.to_string_lossy(), ext.to_string_lossy()))
            .to_string_lossy()
            .into_owned(),
        _ => format!("{}.hunt.csv", output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::evtx::ProcMeta;

    #[test]
    fn test_default_findings_path() {
        assert_eq!(default_findings_path("host.csv"), "host.hunt.csv");
        assert!(default_findings_path(r"C:\case\out.csv").ends_with(r"\out.hunt.csv"));
        assert_eq!(default_findings_path("timeline"), "timeline.hunt.csv");
    }

    #[test]
    fn test_run_respects_window_and_writes_csv() {
        let mk = |ts: &str, pid: u32, ppid: u32, name: &str, parent: &str| Event {
            timestamp: ts.to_string(),
            computer: "PC".to_string(),
            artifact: "evtx:4688".to_string(),
            event_id: 4688,
            pid,
            subject_username: "LAB\\bob".to_string(),
            target_username: String::new(),
            processname: name.to_string(),
            commandline: Some(format!("\"{}\" /c \"quoted\"", name)),
            parentprocessname: parent.to_string(),
            meta: Some(Box::new(ProcMeta { ppid, ..Default::default() })),
        };
        let events = vec![
            mk("2026-01-01T00:00:00.000000Z", 10, 1, r"C:\Program Files\Microsoft Office\WINWORD.EXE", ""),
            mk("2026-01-01T00:00:01.000000Z", 11, 10, r"C:\Windows\System32\cmd.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
            mk("2026-01-02T00:00:00.000000Z", 12, 10, r"C:\Windows\System32\mshta.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
        ];
        let all = run(&events, None, None);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].lineage, "WINWORD.EXE > cmd.exe");
        let windowed = run(&events, Some("2026-01-01T12:00:00.000000Z"), None);
        assert_eq!(windowed.len(), 1);
        assert_eq!(windowed[0].processname, r"C:\Windows\System32\mshta.exe");

        let dir = std::env::temp_dir().join(format!("caarea_hunt_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.csv");
        export_findings(&all, path.to_str().unwrap()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], FINDINGS_HEADER);
        assert!(lines[1].contains("\"GEN-OFFICE-SHELL\",\"genealogy\",85,\"T1566.001\""));
        assert!(lines[1].contains(r#"/c ""quoted"""#), "quotes doubled: {}", lines[1]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
