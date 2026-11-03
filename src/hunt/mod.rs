//! Process hunting over the finished timeline: rules that mark rows an analyst should read
//! first, each with an ATT&CK technique and an explanation in words.
//!
//! The hunt never touches the ten event columns. Its verdict goes into the analysis tail
//! every timeline carries (`hunt`, `hunt_score`, `hunt_why`, `verdict`, `notes`: the five
//! columns that close the CSVs of masstin, faramir and allymacb, one convention for the four
//! tools; masstin's `docs/csv-format.md` is the reference), and the detailed findings go to
//! their own CSV next to the timeline (`<output>.hunt.csv`), one row per rule hit, with the
//! rule's level and catalogue score, the lineage of the process and the rows it was
//! correlated with.
//!
//! What a rule writes to the tail, column by column:
//! - `hunt` is the state, from the strongest evidence on the row. A high rule gives
//!   `significant`, a medium rule `candidate`, a low rule leaves the state as it is. A
//!   statistical test (phase H4) gives `significant` when q ≤ alpha, `candidate` when not,
//!   and owns the other words: `habitual`, `not_evaluated`, `baseline`. When a test and a
//!   rule both speak, the stronger state wins. No other word goes into `hunt`: `suspicious`
//!   is the analyst's, in `verdict`.
//! - `hunt_score` is rarity, not the author's confidence: every rule contributes the points
//!   measured for its pattern on the stock reference timelines (`rarity`), on masstin's scale
//!   (`-10 · log10` of a probability); a test contributes `-10 · log10(q)`. Contributions
//!   add, capped at 100. A rule not measured yet contributes 0 and says so in `hunt_why`.
//! - `hunt_why` names the source: `rule GEN-OFFICE-SHELL (high): winword.exe launched
//!   cmd.exe [T1566.001]`, the strongest rule first, clauses separated by `; `, the lineage
//!   last. A test's clause is in words, without the `rule ` prefix, so a reader that wants
//!   only the rules filters `hunt_why` on `rule `.
//!
//! The catalogue score of a rule (0 to 100, how sure the author is of the pattern) lives in
//! the code and in the findings table; it sets the level and ranks the table, and never goes
//! into the timeline.

pub mod genealogy;
pub mod names;
pub mod naming;
pub mod rarity;
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

/// The words of `hunt`, masstin's. Rules write the first two; the statistical tests of H4
/// write all five. Empty means the row did not enter the hunt.
pub const HUNT_SIGNIFICANT: &str = "significant";
pub const HUNT_CANDIDATE: &str = "candidate";
pub const HUNT_HABITUAL: &str = "habitual";
pub const HUNT_NOT_EVALUATED: &str = "not_evaluated";
pub const HUNT_BASELINE: &str = "baseline";
pub const HUNT_WORDS: [&str; 5] = [HUNT_SIGNIFICANT, HUNT_CANDIDATE, HUNT_HABITUAL, HUNT_NOT_EVALUATED, HUNT_BASELINE];

/// How strong a `hunt` state is, for "the stronger state wins": empty is the weakest.
pub fn state_rank(state: &str) -> u8 {
    match state {
        HUNT_SIGNIFICANT => 5,
        HUNT_CANDIDATE => 4,
        HUNT_HABITUAL => 3,
        HUNT_NOT_EVALUATED => 2,
        HUNT_BASELINE => 1,
        _ => 0,
    }
}

/// Catalogue score at or above which a rule is `high`.
pub const HIGH_FROM: u8 = 85;
/// Catalogue score at or above which a rule is `medium`; below it is `low`.
pub const MEDIUM_FROM: u8 = 60;

/// Top of the `hunt_score` scale.
pub const SCORE_MAX: u8 = 100;

/// The level of a rule, from its catalogue score: the one thing the author's confidence
/// decides in the tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Low,
    Medium,
    High,
}

impl Level {
    pub fn of(score: u8) -> Level {
        if score >= HIGH_FROM {
            Level::High
        } else if score >= MEDIUM_FROM {
            Level::Medium
        } else {
            Level::Low
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Level::High => "high",
            Level::Medium => "medium",
            Level::Low => "low",
        }
    }

    /// The `hunt` state the level gives on its own: high `significant`, medium `candidate`,
    /// low none (the state stays as it is).
    pub fn state(self) -> Option<&'static str> {
        match self {
            Level::High => Some(HUNT_SIGNIFICANT),
            Level::Medium => Some(HUNT_CANDIDATE),
            Level::Low => None,
        }
    }
}

/// The `hunt_score` of a statistical test's q-value, masstin's scale: `-10 log10 q`,
/// rounded, 0 to 100. 0 is no rarer than chance (q = 1), 13 one in twenty, 20 one in a
/// hundred, 30 one in a thousand, 60 one in a million, 100 one in ten thousand million
/// or rarer. None for NaN (no test). For the correlation and rarity tests of H4, whose
/// contribution adds to the rules' like any other.
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

/// The analysis tail of one timeline row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tail {
    /// One of `HUNT_WORDS`, or empty.
    pub hunt: &'static str,
    /// Rarity, 0 to 100: the sum of what every rule and test on the row contributes.
    /// None when nothing judged the row.
    pub hunt_score: Option<u8>,
    /// `rule GEN-OFFICE-SHELL (high): winword.exe launched cmd.exe [T1566.001]; rule
    /// GEN-PARENT-GONE (low): creator had exited [T1134.004]; lineage: explorer.exe >
    /// WINWORD.EXE > cmd.exe`
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
    /// The pattern of the rule, when the rule has several measured apart (`temp` for
    /// `PATH-SCRATCH`, `hex` for `NAM-RANDOM`); empty otherwise.
    pub variant: &'static str,
    /// Catalogue score, 0 to 100: how sure the author is of the pattern. Sets the level
    /// and ranks the findings table; never written to `hunt_score`.
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
    pub fn level(&self) -> Level {
        Level::of(self.score)
    }

    /// `yes` when the rule is high: on its own it makes the row `significant`.
    pub fn significant(&self) -> bool {
        self.level() == Level::High
    }

    /// The key of the rule in the rarity table: `PATH-SCRATCH/temp`, `GEN-OFFICE-SHELL`.
    pub fn key(&self) -> String {
        if self.variant.is_empty() {
            self.rule_id.to_string()
        } else {
            format!("{}/{}", self.rule_id, self.variant)
        }
    }

    /// The points the finding adds to `hunt_score`: the measured rarity of its pattern.
    /// None when the pattern has not been measured (it then contributes 0).
    pub fn rarity(&self) -> Option<u8> {
        rarity::points(&self.key())
    }

    /// One clause of `hunt_why`: `rule GEN-OFFICE-SHELL (high): winword.exe launched
    /// cmd.exe [T1566.001]`, and `, rarity not measured` when the rule adds nothing yet.
    pub fn clause(&self) -> String {
        let mut s = format!("rule {} ({}): {} [{}]", self.rule_id, self.level().word(), self.title, self.mitre);
        if self.rarity().is_none() {
            s.push_str(", rarity not measured");
        }
        s
    }
}

/// Runs every rule family over the timeline (sorted by time). `start`/`end` are canonical
/// timestamps: rows outside the window still feed the process tree but produce no finding.
/// Findings come back ranked: catalogue score first, then time, then rule.
pub fn run(events: &[Event], start: Option<&str>, end: Option<&str>) -> Vec<Finding> {
    let tree = tree::ProcessTree::build(events);
    let mut findings = genealogy::run(events, &tree);
    findings.extend(naming::run(events, &tree));
    findings.retain(|f| start.map(|s| f.timestamp.as_str() >= s).unwrap_or(true) && end.map(|e| f.timestamp.as_str() <= e).unwrap_or(true));
    findings.sort_by(|a, b| b.score.cmp(&a.score).then(a.timestamp.cmp(&b.timestamp)).then(a.rule_id.cmp(b.rule_id)));
    findings
}

/// The tail of every row of a timeline of `rows` rows. The strongest rule of the row gives
/// `hunt` (high `significant`, medium `candidate`, low nothing), every rule adds its
/// measured rarity to `hunt_score` (capped at 100), every rule gives a clause of
/// `hunt_why`, strongest first, and the lineage closes it. Rows without a finding get an
/// empty tail.
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
        fs.sort_by(|a, b| b.level().cmp(&a.level()).then(b.score.cmp(&a.score)).then(a.rule_id.cmp(b.rule_id)));
        let hunt = fs[0].level().state().unwrap_or("");
        let score: u32 = fs.iter().map(|f| f.rarity().unwrap_or(0) as u32).sum();
        let mut why: Vec<String> = fs.iter().map(|f| f.clause()).collect();
        if !fs[0].lineage.is_empty() {
            why.push(format!("lineage: {}", fs[0].lineage));
        }
        out[row] = Tail { hunt, hunt_score: Some(score.min(SCORE_MAX as u32) as u8), hunt_why: why.join("; "), ..Default::default() };
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
/// tables; the middle names the row the way the timeline does. `score` is the catalogue
/// score, `level` its word, `rarity` what the hit added to `hunt_score` (empty when not
/// measured), `pattern` the measured variant of the rule.
pub const FINDINGS_HEADER: &str = "rank,significant,p_value,q_value,score,level,rarity,signature,pattern,mitre,title,time_created,computer,pid,processname,commandline,parentprocessname,subject_username,artifact,lineage,why_unusual,evidence";

/// Writes the findings table (RFC 4180, same quoting as the timeline; `p_value` and
/// `q_value` stay empty until a statistical test fills them).
pub fn export_findings(findings: &[Finding], path: &str) -> std::io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    writeln!(w, "{}", FINDINGS_HEADER)?;
    for (i, f) in findings.iter().enumerate() {
        writeln!(
            w,
            "{},{},,,{},{},{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            i + 1,
            if f.significant() { "yes" } else { "no" },
            f.score,
            f.level().word(),
            f.rarity().map(|r| r.to_string()).unwrap_or_default(),
            f.rule_id,
            f.variant,
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
    fn test_levels_states_and_tail_csv() {
        assert_eq!(Level::of(95), Level::High);
        assert_eq!(Level::of(85), Level::High);
        assert_eq!(Level::of(70), Level::Medium);
        assert_eq!(Level::of(60), Level::Medium);
        assert_eq!(Level::of(35), Level::Low);
        assert_eq!(Level::High.state(), Some(HUNT_SIGNIFICANT));
        assert_eq!(Level::Medium.state(), Some(HUNT_CANDIDATE));
        assert_eq!(Level::Low.state(), None);
        assert!(Level::High > Level::Medium && Level::Medium > Level::Low);
        assert!(state_rank(HUNT_SIGNIFICANT) > state_rank(HUNT_CANDIDATE));
        assert!(state_rank(HUNT_CANDIDATE) > state_rank(HUNT_HABITUAL));
        assert!(state_rank(HUNT_BASELINE) > state_rank(""));
        assert!(HUNT_WORDS.iter().all(|w| state_rank(w) > 0));
        assert_eq!(Tail::default().csv(), EMPTY_TAIL);
        assert_eq!(EMPTY_TAIL.len(), TAIL_COLUMNS.len());
        let t = Tail { hunt: HUNT_CANDIDATE, hunt_score: Some(70), hunt_why: "A \"b\", c".to_string(), ..Default::default() };
        assert_eq!(t.csv(), ",\"candidate\",70,\"A \"\"b\"\", c\",,");
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
        assert_eq!(all[0].key(), "GEN-OFFICE-SHELL");
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
        let rarity = rarity::points("GEN-OFFICE-SHELL").expect("measured");
        let head = format!("1,yes,,,85,high,{},\"GEN-OFFICE-SHELL\",\"\",\"T1566.001\",", rarity);
        assert!(lines[1].starts_with(&head), "{}", lines[1]);
        assert!(lines[2].starts_with("2,yes,,,85,high,"), "{}", lines[2]);
        assert!(lines[1].contains(r#"/c ""quoted"""#), "quotes doubled: {}", lines[1]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_tails_state_from_the_strongest_rule_and_score_is_rarity() {
        let events = vec![
            mk("2026-01-01T00:00:00.000000Z", 10, 1, r"C:\Program Files\Microsoft Office\WINWORD.EXE", ""),
            mk("2026-01-01T00:00:01.000000Z", 11, 10, r"C:\Windows\System32\cmd.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
        ];
        let findings = run(&events, None, None);
        let office = rarity::points("GEN-OFFICE-SHELL").expect("measured");
        let t = tails(events.len(), &findings);
        assert_eq!(t.len(), 2);
        assert!(t[0].is_empty());
        assert_eq!(t[1].hunt, HUNT_SIGNIFICANT);
        assert_eq!(t[1].hunt_score, Some(office));
        assert_eq!(t[1].hunt_why, "rule GEN-OFFICE-SHELL (high): winword.exe launched cmd.exe [T1566.001]; lineage: WINWORD.EXE > cmd.exe");

        // a low rule on the same row: the state stays, its rarity adds, its clause follows
        let mut two = findings.clone();
        let mut low = findings[0].clone();
        low.rule_id = "GEN-PARENT-GONE";
        low.score = 55;
        low.mitre = "T1134.004";
        low.title = "creator gone".to_string();
        two.push(low.clone());
        let gone = rarity::points("GEN-PARENT-GONE").expect("measured");
        let t = tails(events.len(), &two);
        assert_eq!(t[1].hunt, HUNT_SIGNIFICANT);
        assert_eq!(t[1].hunt_score, Some((office as u32 + gone as u32).min(100) as u8));
        assert!(t[1].hunt_why.starts_with("rule GEN-OFFICE-SHELL (high): winword.exe launched cmd.exe [T1566.001]; rule GEN-PARENT-GONE (low): creator gone [T1134.004]; lineage: "), "{}", t[1].hunt_why);
        assert_eq!(t[1].hunt_why.matches("lineage:").count(), 1);

        // a medium rule first, a low one after: `candidate`
        let mut medium = low.clone();
        medium.rule_id = "GEN-SERVICES-SHELL";
        medium.score = 70;
        let t = tails(events.len(), &[low.clone(), medium.clone()]);
        assert_eq!(t[1].hunt, HUNT_CANDIDATE);
        assert!(t[1].hunt_why.starts_with("rule GEN-SERVICES-SHELL (medium): "), "{}", t[1].hunt_why);

        // a low rule alone: no state, but the clause and the rarity are there
        let t = tails(events.len(), std::slice::from_ref(&low));
        assert_eq!(t[1].hunt, "");
        assert_eq!(t[1].hunt_score, Some(gone));
        assert!(t[1].hunt_why.starts_with("rule GEN-PARENT-GONE (low): "), "{}", t[1].hunt_why);
        assert!(!t[1].is_empty());

        // a rule not in the rarity table contributes nothing and says so
        let mut unmeasured = medium.clone();
        unmeasured.rule_id = "CMD-FUTURE-RULE";
        assert_eq!(unmeasured.rarity(), None);
        let t = tails(events.len(), std::slice::from_ref(&unmeasured));
        assert_eq!(t[1].hunt, HUNT_CANDIDATE);
        assert_eq!(t[1].hunt_score, Some(0));
        assert!(t[1].hunt_why.starts_with("rule CMD-FUTURE-RULE (medium): creator gone [T1134.004], rarity not measured; "), "{}", t[1].hunt_why);

        // contributions add and cap at 100
        let mut a = findings[0].clone();
        a.rule_id = "GEN-WEBSERVER-SHELL";
        let mut b = findings[0].clone();
        b.rule_id = "GEN-ACCESSIBILITY-BACKDOOR";
        let mut c = findings[0].clone();
        c.rule_id = "GEN-BROWSER-SHELL";
        let two = rarity::points("GEN-WEBSERVER-SHELL").unwrap() as u32 + rarity::points("GEN-ACCESSIBILITY-BACKDOOR").unwrap() as u32;
        let t = tails(events.len(), &[a.clone(), b.clone()]);
        assert_eq!(t[1].hunt_score, Some(two.min(100) as u8));
        let t = tails(events.len(), &[a, b, c]);
        assert_eq!(t[1].hunt_score, Some(100));
    }
}
