//! Process hunting over the finished timeline: rules that mark rows an analyst should read
//! first, each with a score, an ATT&CK technique and an explanation in words.
//!
//! The hunt never touches the ten event columns. Its verdict goes into the analysis tail
//! every timeline carries (`hunt`, `hunt_score`, `hunt_why`, `verdict`, `notes`: the five
//! columns that close masstin's CSV, so a case tool maps them once), and the detailed
//! findings go to their own CSV next to the timeline (`<output>.hunt.csv`), one row per
//! rule hit, with the lineage of the process and the rows it was correlated with.

pub mod genealogy;
pub mod tree;

use crate::parsers::evtx::Event;
use crate::utils::escape_csv;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};

/// The five columns that close every timeline, after the ten event columns.
pub const TAIL_COLUMNS: [&str; 5] = ["hunt", "hunt_score", "hunt_why", "verdict", "notes"];

/// The tail of a row nothing has judged, written bare.
pub const EMPTY_TAIL: &str = ",,,,,";

/// Values of `hunt`. The first four are faramir's severity words (both tools judge rows,
/// not connections); `baseline` is masstin's and means "reference, not judged".
pub const HUNT_MALICIOUS: &str = "malicious";
pub const HUNT_SUSPICIOUS: &str = "suspicious";
pub const HUNT_ANOMALOUS: &str = "anomalous";
pub const HUNT_REVIEW: &str = "review";
pub const HUNT_BASELINE: &str = "baseline";

/// Score at or above which a finding is `malicious`.
pub const MALICIOUS_FROM: u8 = 85;
/// Score at or above which a finding is `suspicious` (and `significant` in the table).
pub const SUSPICIOUS_FROM: u8 = 60;

/// Top of the `hunt_score` scale.
pub const SCORE_MAX: u8 = 100;

/// The `hunt_score` of a statistical test's q-value, masstin's scale: `-10 log10 q`,
/// rounded, 0 to 100. 0 is no rarer than chance (q = 1), 13 one in twenty, 20 one in a
/// hundred, 30 one in a thousand, 60 one in a million, 100 one in ten thousand million
/// or rarer. None for NaN (no test). Reserved for the correlation and rarity rules (H4),
/// which take the larger of this and the rule score when both apply.
pub fn score_of_q(q: f64) -> Option<u8> {
    if q.is_nan() {
        return None;
    }
    if q <= 0.0 {
        return Some(SCORE_MAX);
    }
    let s = (-10.0 * q.log10()).round();
    Some(s.clamp(0.0, SCORE_MAX as f64) as u8)
}

/// The `hunt` word for a rule score.
pub fn state_for_score(score: u8) -> &'static str {
    if score >= MALICIOUS_FROM {
        HUNT_MALICIOUS
    } else if score >= SUSPICIOUS_FROM {
        HUNT_SUSPICIOUS
    } else {
        HUNT_REVIEW
    }
}

/// The analysis tail of one timeline row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tail {
    pub hunt: &'static str,
    /// How much the row deserves reading, 0 to 100: the score of its best rule, or from
    /// H4 the rarity of a statistical test on masstin's scale when that is larger. None
    /// when nothing judged the row.
    pub hunt_score: Option<u8>,
    /// `GEN-OFFICE-SHELL winword.exe launched cmd.exe [T1566.001]; GEN-PARENT-GONE ...
    /// (score 55); lineage: explorer.exe > WINWORD.EXE > cmd.exe`
    pub hunt_why: String,
    /// The analyst's: kept, never written by the hunt.
    pub verdict: String,
    pub notes: String,
}

impl Tail {
    pub fn is_empty(&self) -> bool {
        self.hunt.is_empty() && self.hunt_score.is_none() && self.hunt_why.is_empty() && self.verdict.is_empty() && self.notes.is_empty()
    }

    /// The tail as it closes a CSV line: bare when empty, each filled text field quoted,
    /// the score bare.
    pub fn csv(&self) -> String {
        if self.is_empty() {
            return EMPTY_TAIL.to_string();
        }
        let q = |s: &str| if s.is_empty() { String::new() } else { format!("\"{}\"", escape_csv(s)) };
        let score = self.hunt_score.map(|s| s.to_string()).unwrap_or_default();
        format!(",{},{},{},{},{}", q(self.hunt), score, q(&self.hunt_why), q(&self.verdict), q(&self.notes))
    }
}

/// One rule hit on one timeline row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Index of the row in the timeline the hunt ran over.
    pub row: usize,
    pub timestamp: String,
    pub computer: String,
    pub rule_id: &'static str,
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

impl Finding {
    /// `yes` from `suspicious` up: the rows the table lists first.
    pub fn significant(&self) -> bool {
        self.score >= SUSPICIOUS_FROM
    }

    /// One clause of `hunt_why`, faramir's shape: rule, title, technique, and the score
    /// when asked (the first clause of a row leaves it out: `hunt_score` already says it).
    pub fn clause(&self, with_score: bool) -> String {
        if with_score {
            format!("{} {} [{}] (score {})", self.rule_id, self.title, self.mitre, self.score)
        } else {
            format!("{} {} [{}]", self.rule_id, self.title, self.mitre)
        }
    }
}

/// Runs every rule family over the timeline (sorted by time). `start`/`end` are canonical
/// timestamps: rows outside the window still feed the process tree but produce no finding.
/// Findings come back ranked: score first, then time, then rule.
pub fn run(events: &[Event], start: Option<&str>, end: Option<&str>) -> Vec<Finding> {
    let tree = tree::ProcessTree::build(events);
    let mut findings = genealogy::run(events, &tree);
    findings.retain(|f| start.map(|s| f.timestamp.as_str() >= s).unwrap_or(true) && end.map(|e| f.timestamp.as_str() <= e).unwrap_or(true));
    findings.sort_by(|a, b| b.score.cmp(&a.score).then(a.timestamp.cmp(&b.timestamp)).then(a.rule_id.cmp(b.rule_id)));
    findings
}

/// The tail of every row of a timeline of `rows` rows: the best finding of the row gives
/// `hunt` and `hunt_score`, every finding gives a clause of `hunt_why`, highest score
/// first, the lineage closes it. Rows without a finding get an empty tail.
pub fn tails(rows: usize, findings: &[Finding]) -> Vec<Tail> {
    let mut by_row: BTreeMap<usize, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_row.entry(f.row).or_default().push(f);
    }
    let mut out = vec![Tail::default(); rows];
    for (row, mut fs) in by_row {
        if row >= rows {
            continue;
        }
        fs.sort_by(|a, b| b.score.cmp(&a.score).then(a.rule_id.cmp(b.rule_id)));
        let mut why: Vec<String> = fs.iter().enumerate().map(|(k, f)| f.clause(k > 0)).collect();
        if !fs[0].lineage.is_empty() {
            why.push(format!("lineage: {}", fs[0].lineage));
        }
        out[row] = Tail { hunt: state_for_score(fs[0].score), hunt_score: Some(fs[0].score), hunt_why: why.join("; "), ..Default::default() };
    }
    out
}

/// Hits per rule, for the run summary.
pub fn summary(findings: &[Finding]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        *m.entry(f.rule_id).or_insert(0) += 1;
    }
    m
}

/// Header of the findings table. `rank, significant, p_value, q_value` open it and
/// `signature, ..., why_unusual, evidence` close it as in masstin's and allymacb's hunt
/// tables; the middle names the row the way the timeline does.
pub const FINDINGS_HEADER: &str = "rank,significant,p_value,q_value,score,signature,mitre,title,time_created,computer,pid,processname,commandline,parentprocessname,subject_username,artifact,lineage,why_unusual,evidence";

/// Writes the findings table (RFC 4180, same quoting as the timeline; `p_value` and
/// `q_value` stay empty until a statistical test fills them).
pub fn export_findings(findings: &[Finding], path: &str) -> std::io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    writeln!(w, "{}", FINDINGS_HEADER)?;
    for (i, f) in findings.iter().enumerate() {
        writeln!(
            w,
            "{},{},,,{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            i + 1,
            if f.significant() { "yes" } else { "no" },
            f.score,
            f.rule_id,
            f.mitre,
            escape_csv(&f.title),
            escape_csv(&f.timestamp),
            escape_csv(&f.computer),
            f.pid,
            escape_csv(&f.processname),
            escape_csv(&f.commandline),
            escape_csv(&f.parentprocessname),
            escape_csv(&f.subject_username),
            escape_csv(&f.artifact),
            escape_csv(&f.lineage),
            escape_csv(&f.explanation),
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
    fn test_state_words_and_tail_csv() {
        assert_eq!(state_for_score(95), HUNT_MALICIOUS);
        assert_eq!(state_for_score(85), HUNT_MALICIOUS);
        assert_eq!(state_for_score(70), HUNT_SUSPICIOUS);
        assert_eq!(state_for_score(35), HUNT_REVIEW);
        assert_eq!(Tail::default().csv(), EMPTY_TAIL);
        assert_eq!(EMPTY_TAIL.len(), TAIL_COLUMNS.len());
        let t = Tail { hunt: HUNT_SUSPICIOUS, hunt_score: Some(70), hunt_why: "A \"b\", c".to_string(), ..Default::default() };
        assert_eq!(t.csv(), ",\"suspicious\",70,\"A \"\"b\"\", c\",,");
        let t = Tail { verdict: "benign".to_string(), ..Default::default() };
        assert_eq!(t.csv(), ",,,,\"benign\",");
    }

    #[test]
    fn test_score_of_q_is_masstins_scale() {
        assert_eq!(score_of_q(f64::NAN), None);
        assert_eq!(score_of_q(1.0), Some(0));
        assert_eq!(score_of_q(2.0), Some(0));
        assert_eq!(score_of_q(0.05), Some(13));
        assert_eq!(score_of_q(0.01), Some(20));
        assert_eq!(score_of_q(0.001), Some(30));
        assert_eq!(score_of_q(1e-6), Some(60));
        assert_eq!(score_of_q(1e-10), Some(100));
        assert_eq!(score_of_q(1e-12), Some(100));
        assert_eq!(score_of_q(0.0), Some(100));
    }

    fn mk(ts: &str, pid: u32, ppid: u32, name: &str, parent: &str) -> Event {
        Event {
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
        }
    }

    #[test]
    fn test_run_respects_window_and_writes_csv() {
        let events = vec![
            mk("2026-01-01T00:00:00.000000Z", 10, 1, r"C:\Program Files\Microsoft Office\WINWORD.EXE", ""),
            mk("2026-01-01T00:00:01.000000Z", 11, 10, r"C:\Windows\System32\cmd.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
            mk("2026-01-02T00:00:00.000000Z", 12, 10, r"C:\Windows\System32\mshta.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
        ];
        let all = run(&events, None, None);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].row, 1);
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
        assert!(lines[1].starts_with("1,yes,,,85,\"GEN-OFFICE-SHELL\",\"T1566.001\","), "{}", lines[1]);
        assert!(lines[2].starts_with("2,yes,,,85,"), "{}", lines[2]);
        assert!(lines[1].contains(r#"/c ""quoted"""#), "quotes doubled: {}", lines[1]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_tails_follow_the_best_finding_of_the_row() {
        let events = vec![
            mk("2026-01-01T00:00:00.000000Z", 10, 1, r"C:\Program Files\Microsoft Office\WINWORD.EXE", ""),
            mk("2026-01-01T00:00:01.000000Z", 11, 10, r"C:\Windows\System32\cmd.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
        ];
        let findings = run(&events, None, None);
        let t = tails(events.len(), &findings);
        assert_eq!(t.len(), 2);
        assert!(t[0].is_empty());
        assert_eq!(t[1].hunt, HUNT_MALICIOUS);
        assert_eq!(t[1].hunt_score, Some(85));
        assert_eq!(t[1].hunt_why, "GEN-OFFICE-SHELL winword.exe launched cmd.exe [T1566.001]; lineage: WINWORD.EXE > cmd.exe");

        // two rules on one row: highest score first, one lineage
        let mut two = findings.clone();
        let mut extra = findings[0].clone();
        extra.rule_id = "GEN-PARENT-GONE";
        extra.score = 55;
        extra.mitre = "T1134.004";
        extra.title = "creator gone".to_string();
        two.push(extra);
        let t = tails(events.len(), &two);
        assert_eq!(t[1].hunt, HUNT_MALICIOUS);
        assert_eq!(t[1].hunt_score, Some(85));
        assert!(t[1].hunt_why.starts_with("GEN-OFFICE-SHELL winword.exe launched cmd.exe [T1566.001]; "), "{}", t[1].hunt_why);
        assert!(t[1].hunt_why.contains("; GEN-PARENT-GONE creator gone [T1134.004] (score 55); lineage: "), "{}", t[1].hunt_why);
        assert_eq!(t[1].hunt_why.matches("lineage:").count(), 1);
    }
}
