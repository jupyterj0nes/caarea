//! Process tree rebuilt from the timeline: which row created which, per host.
//!
//! Sources: Security 4688 (creator PID in `ProcessId`), Sysmon 1 (`ParentProcessId` and the
//! GUID pair, immune to PID reuse), auditd `execve` and `pacct` (`ppid`). Exits come from
//! 4689 and Sysmon 5. A parent is the latest start of the parent PID on the same host that
//! precedes the child; when that start had already exited, the lookup says so instead of
//! guessing, because a dead parent is either PID reuse the logs did not cover or a spoofed
//! parent (T1134.004).
//!
//! Timestamps are the canonical fixed-width UTC strings, so string order is time order.

use crate::parsers::evtx::Event;
use crate::provenance::artifact_base;
use std::collections::{HashMap, HashSet};

/// Rows that mark the start of a process and carry a PID.
pub fn is_process_start(artifact: &str) -> bool {
    matches!(
        artifact_base(artifact),
        "evtx:4688" | "evtx:sysmon:1" | "linux:audit:execve" | "linux:process:pacct"
    )
}

/// Rows that mark the end of a process.
pub fn is_process_exit(artifact: &str) -> bool {
    matches!(artifact_base(artifact), "evtx:4689" | "evtx:sysmon:5")
}

/// Host key: computer names differ in case between channels.
pub fn host_key(e: &Event) -> String {
    e.computer.to_ascii_lowercase()
}

/// File name of a process path, lowercased: `C:\Windows\System32\cmd.exe` and
/// `/usr/bin/bash` become `cmd.exe` and `bash`. A resolved parent (`bash (PID: 12)`) and the
/// synthetic labels (`svchost.exe (BITS)`) lose their suffix. Empty for `N/A` and `PID: n`.
pub fn base_name(path: &str) -> String {
    let p = path.trim();
    let p = p.split(" (").next().unwrap_or(p).trim();
    if p.is_empty() || p == "N/A" || p.starts_with("PID: ") {
        return String::new();
    }
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_ascii_lowercase()
}

#[derive(Debug, Clone)]
struct Start {
    ts: String,
    idx: usize,
    end: Option<String>,
}

/// Result of looking up the creator of a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentLookup {
    /// Index of the parent's start row.
    Found(usize),
    /// The latest start of the parent PID had already exited at `exit_ts`.
    Exited { parent: usize, exit_ts: String },
    /// No start of that PID precedes the child (log gap, boot before the log, no PID).
    Unknown,
}

#[derive(Debug, Default)]
pub struct ProcessTree {
    /// (host, pid) -> starts in time order
    by_pid: HashMap<(String, u32), Vec<Start>>,
    /// (host, sysmon guid) -> start row
    by_guid: HashMap<(String, String), usize>,
    /// start row -> lookup of its creator
    parents: HashMap<usize, ParentLookup>,
    /// start row -> children start rows
    children: HashMap<usize, Vec<usize>>,
}

impl ProcessTree {
    /// Builds the tree. `events` must be sorted by timestamp (the timeline is).
    pub fn build(events: &[Event]) -> Self {
        let mut tree = ProcessTree::default();
        for (i, e) in events.iter().enumerate() {
            if is_process_start(&e.artifact) {
                let host = host_key(e);
                if e.pid > 0 {
                    tree.by_pid
                        .entry((host.clone(), e.pid))
                        .or_default()
                        .push(Start { ts: e.timestamp.clone(), idx: i, end: None });
                }
                if let Some(guid) = e.meta.as_ref().map(|m| m.guid.as_str()).filter(|g| !g.is_empty()) {
                    tree.by_guid.insert((host, guid.to_string()), i);
                }
            } else if is_process_exit(&e.artifact) {
                let host = host_key(e);
                let guid = e.meta.as_ref().map(|m| m.guid.as_str()).unwrap_or("");
                let target = if !guid.is_empty() {
                    tree.by_guid.get(&(host.clone(), guid.to_string())).copied()
                } else {
                    None
                };
                if let Some(idx) = target {
                    let pid = events[idx].pid;
                    if let Some(starts) = tree.by_pid.get_mut(&(host, pid)) {
                        if let Some(s) = starts.iter_mut().find(|s| s.idx == idx) {
                            s.end = Some(e.timestamp.clone());
                        }
                    }
                } else if e.pid > 0 {
                    if let Some(starts) = tree.by_pid.get_mut(&(host, e.pid)) {
                        // Latest start at or before the exit that is still open.
                        if let Some(s) = starts.iter_mut().rev().find(|s| s.ts <= e.timestamp && s.end.is_none()) {
                            s.end = Some(e.timestamp.clone());
                        }
                    }
                }
            }
        }
        for starts in tree.by_pid.values_mut() {
            starts.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.idx.cmp(&b.idx)));
        }
        for (i, e) in events.iter().enumerate() {
            if !is_process_start(&e.artifact) {
                continue;
            }
            let lookup = tree.lookup_parent(events, i);
            if let ParentLookup::Found(p) = lookup {
                tree.children.entry(p).or_default().push(i);
            }
            tree.parents.insert(i, lookup);
        }
        tree
    }

    fn lookup_parent(&self, events: &[Event], idx: usize) -> ParentLookup {
        let e = &events[idx];
        let Some(meta) = e.meta.as_ref() else {
            return ParentLookup::Unknown;
        };
        let host = host_key(e);
        if !meta.parent_guid.is_empty() {
            if let Some(&p) = self.by_guid.get(&(host.clone(), meta.parent_guid.clone())) {
                if p != idx {
                    return ParentLookup::Found(p);
                }
            }
        }
        if meta.ppid == 0 || meta.ppid == e.pid {
            return ParentLookup::Unknown;
        }
        let Some(starts) = self.by_pid.get(&(host, meta.ppid)) else {
            return ParentLookup::Unknown;
        };
        // Latest start of the parent PID at or before the child (a parent can create a child
        // in the same microsecond, and Sysmon/4688 twins share the instant).
        let pos = starts.partition_point(|s| s.ts <= e.timestamp);
        let Some(cand) = starts[..pos].iter().rev().find(|s| s.idx != idx) else {
            return ParentLookup::Unknown;
        };
        match &cand.end {
            Some(end) if end < &e.timestamp => ParentLookup::Exited { parent: cand.idx, exit_ts: end.clone() },
            _ => ParentLookup::Found(cand.idx),
        }
    }

    /// Creator lookup of a start row.
    pub fn parent(&self, idx: usize) -> ParentLookup {
        self.parents.get(&idx).cloned().unwrap_or(ParentLookup::Unknown)
    }

    /// Start rows created by `idx`, in time order.
    pub fn children(&self, idx: usize) -> &[usize] {
        self.children.get(&idx).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Ancestors of a start row, nearest first, at most `max_depth`, cycle-safe.
    pub fn ancestors(&self, idx: usize, max_depth: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut seen: HashSet<usize> = HashSet::new();
        seen.insert(idx);
        let mut cur = idx;
        while out.len() < max_depth {
            match self.parent(cur) {
                ParentLookup::Found(p) if seen.insert(p) => {
                    out.push(p);
                    cur = p;
                }
                _ => break,
            }
        }
        out
    }

    /// Lineage as names from the oldest known ancestor down to the row itself:
    /// `services.exe > cmd.exe > powershell.exe`. When the oldest ancestor names a parent the
    /// tree could not resolve, that name opens the chain.
    pub fn lineage(&self, events: &[Event], idx: usize) -> String {
        let mut chain: Vec<String> = Vec::new();
        let ancestors = self.ancestors(idx, 8);
        let top = ancestors.last().copied().unwrap_or(idx);
        let top_parent = base_name(&events[top].parentprocessname);
        if !top_parent.is_empty() {
            chain.push(top_parent);
        }
        for &a in ancestors.iter().rev() {
            chain.push(display_name(&events[a].processname));
        }
        chain.push(display_name(&events[idx].processname));
        chain.join(" > ")
    }
}

/// File name as logged (case kept), for display.
fn display_name(path: &str) -> String {
    let p = path.trim();
    let p = p.split(" (").next().unwrap_or(p).trim();
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
}

/// Fills `parentprocessname` where the parser could only give a number (`PID: 2686` from
/// auditd and pacct) or nothing at all (Security 4688 before Windows 10 has no
/// `ParentProcessName`). The resolved name keeps the PID so it can be told from a logged
/// one: `/usr/bin/bash (PID: 2686)`. Returns how many rows were completed.
pub fn resolve_parents(events: &mut [Event]) -> usize {
    let tree = ProcessTree::build(events);
    let mut updates: Vec<(usize, String)> = Vec::new();
    for (i, e) in events.iter().enumerate() {
        if !is_process_start(&e.artifact) {
            continue;
        }
        let current = e.parentprocessname.trim();
        let missing = current.is_empty() || current == "N/A" || current.starts_with("PID: ");
        if !missing {
            continue;
        }
        let ppid = e.meta.as_ref().map(|m| m.ppid).unwrap_or(0);
        if let ParentLookup::Found(p) = tree.parent(i) {
            let name = events[p].processname.trim();
            if !name.is_empty() {
                updates.push((i, format!("{} (PID: {})", name, ppid)));
            }
        }
    }
    let n = updates.len();
    for (i, name) in updates {
        events[i].parentprocessname = name;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::evtx::ProcMeta;

    fn start(ts: &str, host: &str, pid: u32, ppid: u32, name: &str, parent: &str) -> Event {
        Event {
            timestamp: ts.to_string(),
            computer: host.to_string(),
            artifact: "evtx:4688".to_string(),
            event_id: 4688,
            pid,
            subject_username: "LAB\\bob".to_string(),
            target_username: String::new(),
            processname: name.to_string(),
            commandline: Some(name.to_string()),
            parentprocessname: parent.to_string(),
            meta: Some(Box::new(ProcMeta { ppid, ..Default::default() })),
        }
    }

    fn exit(ts: &str, host: &str, pid: u32, name: &str) -> Event {
        let mut e = start(ts, host, pid, 0, name, "");
        e.artifact = "evtx:4689".to_string();
        e.event_id = 4689;
        e.meta = None;
        e
    }

    #[test]
    fn test_base_name_strips_paths_and_suffixes() {
        assert_eq!(base_name(r"C:\Windows\System32\cmd.exe"), "cmd.exe");
        assert_eq!(base_name("/usr/bin/bash (PID: 12)"), "bash");
        assert_eq!(base_name("svchost.exe (BITS)"), "svchost.exe");
        assert_eq!(base_name("PID: 2686"), "");
        assert_eq!(base_name("N/A"), "");
        assert_eq!(base_name(""), "");
    }

    #[test]
    fn test_lineage_follows_creator_pids() {
        let events = vec![
            start("2026-01-01T00:00:00.000000Z", "PC", 600, 500, r"C:\Windows\System32\services.exe", r"C:\Windows\System32\wininit.exe"),
            start("2026-01-01T00:00:01.000000Z", "PC", 700, 600, r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\services.exe"),
            start("2026-01-01T00:00:02.000000Z", "PC", 800, 700, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Windows\System32\cmd.exe"),
        ];
        let tree = ProcessTree::build(&events);
        assert_eq!(tree.parent(2), ParentLookup::Found(1));
        assert_eq!(tree.parent(1), ParentLookup::Found(0));
        assert_eq!(tree.parent(0), ParentLookup::Unknown);
        assert_eq!(tree.ancestors(2, 8), vec![1, 0]);
        assert_eq!(tree.lineage(&events, 2), "wininit.exe > services.exe > cmd.exe > powershell.exe");
        assert_eq!(tree.children(1), &[2]);
    }

    #[test]
    fn test_pid_reuse_picks_latest_start_and_notices_exited_parent() {
        let events = vec![
            start("2026-01-01T00:00:00.000000Z", "PC", 100, 1, "old.exe", ""),
            exit("2026-01-01T00:00:05.000000Z", "PC", 100, "old.exe"),
            start("2026-01-01T00:00:10.000000Z", "PC", 100, 1, "new.exe", ""),
            start("2026-01-01T00:00:11.000000Z", "PC", 200, 100, "child.exe", "new.exe"),
            exit("2026-01-01T00:00:12.000000Z", "PC", 100, "new.exe"),
            start("2026-01-01T00:00:13.000000Z", "PC", 300, 100, "orphan.exe", "new.exe"),
        ];
        let tree = ProcessTree::build(&events);
        assert_eq!(tree.parent(3), ParentLookup::Found(2), "child of the second life of PID 100");
        assert_eq!(
            tree.parent(5),
            ParentLookup::Exited { parent: 2, exit_ts: "2026-01-01T00:00:12.000000Z".to_string() }
        );
    }

    #[test]
    fn test_sysmon_guid_wins_over_pid() {
        let mut parent = start("2026-01-01T00:00:00.000000Z", "PC", 100, 1, "p.exe", "");
        parent.artifact = "evtx:sysmon:1".to_string();
        parent.meta = Some(Box::new(ProcMeta { ppid: 1, guid: "{A}".to_string(), ..Default::default() }));
        let mut imposter = start("2026-01-01T00:00:01.000000Z", "PC", 100, 1, "imposter.exe", "");
        imposter.artifact = "evtx:sysmon:1".to_string();
        imposter.meta = Some(Box::new(ProcMeta { ppid: 1, guid: "{B}".to_string(), ..Default::default() }));
        let mut child = start("2026-01-01T00:00:02.000000Z", "PC", 200, 100, "c.exe", "p.exe");
        child.artifact = "evtx:sysmon:1".to_string();
        child.meta = Some(Box::new(ProcMeta {
            ppid: 100,
            guid: "{C}".to_string(),
            parent_guid: "{A}".to_string(),
            ..Default::default()
        }));
        let events = vec![parent, imposter, child];
        let tree = ProcessTree::build(&events);
        assert_eq!(tree.parent(2), ParentLookup::Found(0));
    }

    #[test]
    fn test_hosts_do_not_mix() {
        let events = vec![
            start("2026-01-01T00:00:00.000000Z", "A", 100, 1, "a.exe", ""),
            start("2026-01-01T00:00:01.000000Z", "B", 200, 100, "b.exe", ""),
        ];
        let tree = ProcessTree::build(&events);
        assert_eq!(tree.parent(1), ParentLookup::Unknown);
    }

    #[test]
    fn test_resolve_parents_fills_pid_labels_only() {
        let mut events = vec![
            start("2026-01-01T00:00:00.000000Z", "lnx", 10, 1, "/usr/bin/bash", "PID: 1"),
            start("2026-01-01T00:00:01.000000Z", "lnx", 11, 10, "/usr/bin/nc", "PID: 10"),
            start("2026-01-01T00:00:02.000000Z", "PC", 50, 10, r"C:\x.exe", r"C:\Windows\explorer.exe"),
        ];
        events[0].artifact = "linux:audit:execve".to_string();
        events[1].artifact = "linux:audit:execve".to_string();
        let n = resolve_parents(&mut events);
        assert_eq!(n, 1);
        assert_eq!(events[1].parentprocessname, "/usr/bin/bash (PID: 10)");
        assert_eq!(events[0].parentprocessname, "PID: 1", "no start for PID 1: left as logged");
        assert_eq!(events[2].parentprocessname, r"C:\Windows\explorer.exe", "logged names are never replaced");
    }
}
