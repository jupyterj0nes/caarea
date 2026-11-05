//! Genealogy rules: a process whose parent contradicts what Windows or Linux does at boot and
//! logon, a sensitive parent creating something it never creates, parent-child pairs that
//! only make sense in an intrusion, and creators that were already dead.
//!
//! The expected-parent and allowed-children tables are the SANS "Hunt Evil" poster (Lee and
//! Pilkington, 2018) cross-checked with Elastic's "Unusual Parent-Child Relationship" rule,
//! which adds the field exceptions (Defender, Citrix, VMware, Omnissa, Sophos). Only what a
//! documented source states is in a table; a pair the tables do not mention gets no opinion.

use super::tree::{base_name, is_process_start, ParentLookup, ProcessTree};
use super::Finding;
use crate::parsers::evtx::Event;
use crate::provenance::artifact_base;


/// Core Windows processes and the only parents that create them.
const EXPECTED_PARENTS: &[(&str, &[&str])] = &[
    ("smss.exe", &["system"]),
    ("csrss.exe", &["smss.exe", "svchost.exe"]),
    ("wininit.exe", &["smss.exe"]),
    ("winlogon.exe", &["smss.exe"]),
    ("services.exe", &["wininit.exe"]),
    ("lsass.exe", &["wininit.exe"]),
    ("lsaiso.exe", &["wininit.exe"]),
    ("logonui.exe", &["wininit.exe", "winlogon.exe"]),
    ("svchost.exe", &["services.exe", "msmpeng.exe"]),
    ("spoolsv.exe", &["services.exe", "workplace starter.exe"]),
    ("searchindexer.exe", &["services.exe"]),
    ("searchprotocolhost.exe", &["searchindexer.exe", "dllhost.exe"]),
    ("dllhost.exe", &["services.exe", "svchost.exe"]),
    ("taskhost.exe", &["services.exe", "svchost.exe", "ngentask.exe"]),
    ("taskhostw.exe", &["services.exe", "svchost.exe"]),
    ("sihost.exe", &["svchost.exe"]),
    ("userinit.exe", &["winlogon.exe", "dwm.exe", "kusrinit.exe"]),
    ("wmiprvse.exe", &["svchost.exe"]),
    ("wsmprovhost.exe", &["svchost.exe"]),
    ("winrshost.exe", &["svchost.exe"]),
    ("fontdrvhost.exe", &["wininit.exe", "winlogon.exe", "dwm.exe"]),
    // Windows 7 starts dwm from the UxSms service (svchost); Windows 8 and later from winlogon
    ("dwm.exe", &["wininit.exe", "winlogon.exe", "dwm.exe", "svchost.exe"]),
    ("consent.exe", &["svchost.exe", "workplace container helper.exe"]),
    ("runtimebroker.exe", &["svchost.exe", "workplace container helper.exe"]),
    ("tiworker.exe", &["svchost.exe", "workplace container helper.exe"]),
    ("autochk.exe", &["smss.exe"]),
];

/// Parents whose children are a closed list. Anything else they create is a finding.
const ALLOWED_CHILDREN: &[(&str, &[&str])] = &[
    (
        "smss.exe",
        &[
            "smss.exe", "autochk.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "setupcl.exe", "werfault.exe",
            "wpbbin.exe", "pvsvmboot.exe", "sophosna.exe", "omnissa-ic-nga.exe", "vmware-svi-nga.exe",
            "icarus_rvrt.exe", "poqexec.exe",
        ],
    ),
    (
        "wininit.exe",
        &["services.exe", "lsass.exe", "lsaiso.exe", "lsm.exe", "fontdrvhost.exe", "logonui.exe", "dwm.exe", "werfault.exe"],
    ),
    (
        "winlogon.exe",
        &[
            "userinit.exe", "logonui.exe", "dwm.exe", "fontdrvhost.exe", "mpnotify.exe", "werfault.exe", "utilman.exe",
            "sethc.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe",
            "tabtip.exe", "consent.exe",
        ],
    ),
    ("lsass.exe", &["werfault.exe"]),
    ("csrss.exe", &["werfault.exe", "wermgr.exe", "werfaultsecure.exe", "conhost.exe", "ngentask.exe", "searchprotocolhost.exe"]),
    ("searchprotocolhost.exe", &["werfault.exe", "wermgr.exe", "werfaultsecure.exe", "conhost.exe", "ngentask.exe", "searchprotocolhost.exe"]),
    ("taskhost.exe", &["werfault.exe", "wermgr.exe", "werfaultsecure.exe", "conhost.exe", "ngentask.exe", "searchprotocolhost.exe", "winsat.exe"]),
    ("autochk.exe", &["chkdsk.exe", "doskey.exe", "werfault.exe"]),
    ("wermgr.exe", &["werfaultsecure.exe", "werfault.exe", "rundll32.exe"]),
    ("conhost.exe", &["mscorsvw.exe", "wermgr.exe", "werfault.exe", "werfaultsecure.exe"]),
];

/// Shells, script hosts and LOLBins that an exploited application launches.
const SHELLS_AND_LOLBINS: &[&str] = &[
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "schtasks.exe", "wmic.exe",
    "curl.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "hh.exe",
    "forfiles.exe", "scriptrunner.exe", "bash.exe", "wsl.exe", "net.exe", "net1.exe", "whoami.exe",
];

const OFFICE_AND_READERS: &[&str] = &[
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "visio.exe",
    "onenote.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitphantompdf.exe", "wordpad.exe",
];

const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"];

const WEB_SERVERS: &[&str] = &["w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "php.exe", "caddy.exe"];

const DATABASES: &[&str] = &["sqlservr.exe", "mysqld.exe", "postgres.exe", "oracle.exe"];

const REMOTE_EXEC_SERVICES: &[&str] = &["psexesvc.exe", "paexec.exe", "winexesvc.exe", "remcomsvc.exe", "csexecsvc.exe"];

const ACCESSIBILITY: &[&str] =
    &["utilman.exe", "sethc.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe"];

const LINUX_SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "nc", "ncat", "netcat", "socat", "python", "python2", "python3", "perl",
    "ruby", "curl", "wget", "telnet", "busybox",
];

const LINUX_SERVICE_ACCOUNTS: &[&str] = &[
    "www-data", "apache", "httpd", "nginx", "mysql", "postgres", "tomcat", "redis", "mongodb", "elasticsearch",
    "daemon", "nobody", "_www",
];

const LINUX_SERVERS: &[&str] = &["apache2", "httpd", "nginx", "php-fpm", "mysqld", "mariadbd", "postgres", "tomcat"];

const CRON: &[&str] = &["cron", "crond", "anacron", "atd"];

const SCRATCH_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"];

fn in_list(name: &str, list: &[&str]) -> bool {
    list.contains(&name)
}

fn in_table<'a>(name: &str, table: &'a [(&str, &[&str])]) -> Option<&'a [&'a str]> {
    table.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

fn is_windows_row(e: &Event) -> bool {
    artifact_base(&e.artifact).starts_with("evtx:")
}

fn is_system_account(user: &str) -> bool {
    let u = user.to_ascii_lowercase();
    u.ends_with('$') || u.ends_with("\\system") || u == "system" || u == "nt authority\\system" || u.ends_with("\\local service") || u.ends_with("\\network service")
}

/// Seconds between two canonical timestamps, or 0 when either cannot be parsed.
fn seconds_between(a: &str, b: &str) -> i64 {
    match (crate::utils::parse_flexible_time(a), crate::utils::parse_flexible_time(b)) {
        (Some(x), Some(y)) => (y - x).num_seconds(),
        _ => 0,
    }
}

pub fn run(events: &[Event], tree: &ProcessTree) -> Vec<Finding> {
    let mut out = Vec::new();
    // Boot markers per host, to count core process instances per boot.
    let mut core_starts: std::collections::HashMap<(String, String), Vec<usize>> = std::collections::HashMap::new();
    let mut boots: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for (i, e) in events.iter().enumerate() {
        if !is_process_start(&e.artifact) {
            continue;
        }
        let child = base_name(&e.processname);
        let parent = base_name(&e.parentprocessname);
        if child.is_empty() {
            continue;
        }
        let win = is_windows_row(e);

        if win {
            let host = super::tree::host_key(e);
            if child == "wininit.exe" {
                boots.entry(host.clone()).or_default().push(e.timestamp.clone());
            }
            if matches!(child.as_str(), "lsass.exe" | "services.exe" | "wininit.exe" | "lsaiso.exe") {
                core_starts.entry((host, child.clone())).or_default().push(i);
            }
        }

        // Self-spawns (svchost from svchost, dwm from dwm) are excluded, as Elastic does.
        if !parent.is_empty() && parent != child {
            if win {
                if let Some(allowed) = in_table(&child, EXPECTED_PARENTS) {
                    if !in_list(&parent, allowed) {
                        out.push(finding(
                            events, tree, i, "GEN-CORE-PARENT", 85, "T1036.005",
                            format!("{} created by {} instead of {}", child, parent, allowed.join(" or ")),
                            format!(
                                "{} is a core Windows process that only {} creates; here it was created by {}. A malicious program named like a system binary, or an injected creator, is the usual cause.",
                                child, allowed.join(" or "), parent
                            ),
                        ));
                    }
                }
                if let Some(allowed) = in_table(&parent, ALLOWED_CHILDREN) {
                    if !in_list(&child, allowed) {
                        // the parents that run with the system's secrets are measured apart
                        let critical = matches!(parent.as_str(), "lsass.exe" | "winlogon.exe" | "smss.exe" | "wininit.exe" | "csrss.exe");
                        let mut f = finding(
                            events, tree, i, "GEN-RESTRICTED-PARENT", if critical { 90 } else { 70 }, "T1055",
                            format!("{} created {}", parent, child),
                            format!(
                                "{} never creates {}; its only children are {}. Code running inside {} (injection, an image hijack of an accessibility tool, a debugger set in IFEO) launches processes this way.",
                                parent, child, allowed.join(", "), parent
                            ),
                        );
                        if critical {
                            f.variant = "critical";
                        }
                        out.push(f);
                    }
                }
                if in_list(&parent, OFFICE_AND_READERS) && in_list(&child, SHELLS_AND_LOLBINS) {
                    out.push(finding(
                        events, tree, i, "GEN-OFFICE-SHELL", 85, "T1566.001",
                        format!("{} launched {}", parent, child),
                        format!("A document reader launched a shell or script host. Macros and exploited documents run their payload this way; {} has no legitimate reason to start {}.", parent, child),
                    ));
                }
                if in_list(&parent, BROWSERS) && in_list(&child, SHELLS_AND_LOLBINS) {
                    out.push(finding(
                        events, tree, i, "GEN-BROWSER-SHELL", 75, "T1189",
                        format!("{} launched {}", parent, child),
                        format!("A browser launched a shell or script host, the shape of a drive-by exploit or a malicious download run from the browser. Check what {} did next.", child),
                    ));
                }
                if (in_list(&parent, WEB_SERVERS) || parent.starts_with("tomcat")) && (in_list(&child, SHELLS_AND_LOLBINS) || matches!(child.as_str(), "nltest.exe" | "ipconfig.exe" | "systeminfo.exe" | "tasklist.exe" | "ping.exe" | "nslookup.exe" | "hostname.exe")) {
                    out.push(finding(
                        events, tree, i, "GEN-WEBSERVER-SHELL", 95, "T1505.003",
                        format!("web server {} launched {}", parent, child),
                        format!("A web server worker launched {}. That is a web shell or a command injection in the application it serves: the request that caused it is in the web logs at this time.", child),
                    ));
                }
                if in_list(&parent, DATABASES) && in_list(&child, SHELLS_AND_LOLBINS) {
                    out.push(finding(
                        events, tree, i, "GEN-DATABASE-SHELL", 85, "T1505.001",
                        format!("database engine {} launched {}", parent, child),
                        format!("A database engine launched {}; xp_cmdshell, UDF or external procedure abuse after a SQL compromise looks exactly like this.", child),
                    ));
                }
                if in_list(&parent, REMOTE_EXEC_SERVICES) {
                    out.push(finding(
                        events, tree, i, "GEN-REMOTE-EXEC", 80, "T1569.002",
                        format!("{} launched {} (remote execution service)", parent, child),
                        format!("{} is the service side of PsExec or a clone; {} ran on this host at the request of another machine. Pair it with the 7045 installation and the network logon.", parent, child),
                    ));
                }
                if parent == "services.exe" && in_list(&child, SHELLS_AND_LOLBINS) {
                    out.push(finding(
                        events, tree, i, "GEN-SERVICES-SHELL", 70, "T1569.002",
                        format!("services.exe launched {} directly", child),
                        "The Service Control Manager started a shell or script host as a service binary. Services installed with a cmd or PowerShell command line (sc create, PsExec-style tools, some ransomware) do this; look for the matching 7045.".to_string(),
                    ));
                }
                let from_logon_screen = in_list(&parent, ACCESSIBILITY)
                    || (parent == "winlogon.exe" && matches!(child.as_str(), "cmd.exe" | "powershell.exe" | "pwsh.exe" | "taskmgr.exe" | "explorer.exe"));
                let accessibility_tool = in_list(&child, &["osk.exe", "narrator.exe", "magnify.exe", "atbroker.exe", "werfault.exe", "sethc.exe", "utilman.exe", "displayswitch.exe"]);
                if from_logon_screen && !accessibility_tool {
                    out.push(finding(
                        events, tree, i, "GEN-ACCESSIBILITY-BACKDOOR", 95, "T1546.008",
                        format!("{} launched {} from the logon screen", parent, child),
                        format!("{} runs at the logon screen as SYSTEM; it launched {}, which is the sticky-keys / Utilman backdoor: a shell as SYSTEM without credentials.", parent, child),
                    ));
                }
                if parent == "wmiprvse.exe" && in_list(&child, SHELLS_AND_LOLBINS) {
                    out.push(finding(
                        events, tree, i, "GEN-WMI-EXEC", 60, "T1047",
                        format!("WMI provider host launched {}", child),
                        format!("WmiPrvSE.exe launched {}: a Win32_Process.Create call, typically remote (wmic /node, Invoke-WmiMethod, impacket wmiexec). SCCM and monitoring agents also do it; check the user and the command line.", child),
                    ));
                }
                if parent == "spoolsv.exe" && in_list(&child, SHELLS_AND_LOLBINS) {
                    out.push(finding(
                        events, tree, i, "GEN-SPOOLER-SHELL", 85, "T1068",
                        format!("print spooler launched {}", child),
                        format!("spoolsv.exe launched {}. The spooler runs as SYSTEM and only loads print drivers; a shell under it is a spooler exploit (PrintNightmare family) or a malicious port monitor.", child),
                    ));
                }
                if parent == "svchost.exe" && matches!(child.as_str(), "cmd.exe" | "powershell.exe" | "pwsh.exe" | "mshta.exe" | "wscript.exe" | "cscript.exe" | "certutil.exe" | "bitsadmin.exe") {
                    out.push(finding(
                        events, tree, i, "GEN-SVCHOST-SHELL", 35, "T1053.005",
                        format!("svchost.exe launched {}", child),
                        format!("A service host launched {}. The Task Scheduler and some services legitimately do this, so the finding is only a pointer: find the task or service behind it and judge its command line.", child),
                    ));
                }
                // A token anomaly needs a parent the log named: a parent resolved by PID on a
                // host without exit records (Windows 7 with 4688 only) is where explorer's
                // recycled PID lands, and the token mismatch is then the symptom of that.
                if parent == "explorer.exe" && is_system_account(&e.subject_username) && !e.parentprocessname.contains(" (PID: ") {
                    out.push(finding(
                        events, tree, i, "GEN-EXPLORER-SYSTEM", 65, "T1134",
                        format!("{} created under explorer.exe but as {}", child, e.subject_username),
                        "explorer.exe runs as the logged-on user, yet this child was created by a SYSTEM or service token. A stolen token or a spoofed parent (an attacker hiding under the shell) explains it.".to_string(),
                    ));
                }
            } else {
                // Linux: parents are resolved names or nothing.
                let parent_is_server = LINUX_SERVERS.iter().any(|s| parent.starts_with(s));
                if parent_is_server && in_list(&child, LINUX_SHELLS) {
                    out.push(finding(
                        events, tree, i, "GEN-WEBSERVER-SHELL", 95, "T1505.003",
                        format!("{} launched {}", parent, child),
                        format!("A server daemon launched {}. A web shell, a command injection or a database UDF abuse runs its commands under the daemon; the triggering request is in the service logs at this time.", child),
                    ));
                }
                if in_list(&parent, CRON) && SCRATCH_DIRS.iter().any(|d| e.processname.starts_with(d)) {
                    out.push(finding(
                        events, tree, i, "GEN-CRON-SCRATCH", 75, "T1053.003",
                        format!("cron ran {} from a scratch directory", child),
                        format!("A cron job executed {} from a world-writable scratch directory. Persistence dropped by an intruder lives there; the crontab or cron.d entry that references it is the next artifact to pull.", e.processname),
                    ));
                }
            }
        }

        // Linux service accounts spawning shells, whether or not the parent resolved.
        if !win {
            let user = e.subject_username.to_ascii_lowercase();
            if in_list(&user, LINUX_SERVICE_ACCOUNTS) && in_list(&child, LINUX_SHELLS) {
                let parent_is_server = LINUX_SERVERS.iter().any(|s| parent.starts_with(s));
                if !parent_is_server {
                    out.push(finding(
                        events, tree, i, "GEN-SVCACCT-SHELL", 80, "T1505.003",
                        format!("service account {} ran {}", user, child),
                        format!("The service account {} ran {}. Service accounts do not open shells or fetch files by themselves; this is the first command of a web shell or an exploited daemon.", user, child),
                    ));
                }
            }
        }

        // Creator already gone.
        if let ParentLookup::Exited { parent: p, exit_ts } = tree.parent(i) {
            let gap = seconds_between(&exit_ts, &e.timestamp);
            let parent_name = base_name(&events[p].processname);
            out.push(finding_related(
                events, tree, i, "GEN-PARENT-GONE", 55, "T1134.004",
                format!("{} created by PID {} ({}) which had exited {} s earlier", child, events[p].pid, parent_name, gap),
                format!(
                    "The creator PID points to {} which exited at {}, before this process started. Either the PID was reused by a process whose creation the logs do not hold, or the parent was spoofed to hide the real creator.",
                    parent_name, exit_ts
                ),
                format!("{} {} start; {} exit", events[p].timestamp, parent_name, exit_ts),
            ));
        }
    }

    // More than one lsass / services / wininit per boot.
    for ((host, name), starts) in core_starts {
        let markers = boots.get(&host).cloned().unwrap_or_default();
        if markers.is_empty() {
            continue;
        }
        let mut per_boot: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
        for &i in &starts {
            let ts = &events[i].timestamp;
            let boot = markers.partition_point(|m| m <= ts);
            per_boot.entry(boot).or_default().push(i);
        }
        for (_, rows) in per_boot {
            if rows.len() < 2 {
                continue;
            }
            for &i in rows.iter().skip(1) {
                out.push(finding_related(
                    events, tree, i, "GEN-DUPLICATE-CORE", 75, "T1036.005",
                    format!("second {} in the same boot", name),
                    format!("Windows runs exactly one {} per boot; this is instance {} since the last wininit.exe start on {}. A look-alike binary or a renamed tool is running under that name.", name, rows.iter().position(|r| *r == i).unwrap_or(0) + 1, events[i].computer),
                    format!("first instance {}", events[rows[0]].timestamp),
                ));
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn finding(events: &[Event], tree: &ProcessTree, i: usize, rule: &'static str, score: u8, mitre: &'static str, title: String, explanation: String) -> Finding {
    finding_related(events, tree, i, rule, score, mitre, title, explanation, String::new())
}

#[allow(clippy::too_many_arguments)]
fn finding_related(events: &[Event], tree: &ProcessTree, i: usize, rule: &'static str, score: u8, mitre: &'static str, title: String, explanation: String, related: String) -> Finding {
    let e = &events[i];
    Finding {
        row: i,
        timestamp: e.timestamp.clone(),
        computer: e.computer.clone(),
        rule_id: rule,
        variant: "",
        score,
        mitre,
        title,
        explanation,
        lineage: tree.lineage(events, i),
        pid: e.pid,
        processname: e.processname.clone(),
        commandline: e.commandline.clone().unwrap_or_default(),
        parentprocessname: e.parentprocessname.clone(),
        subject_username: e.subject_username.clone(),
        artifact: e.artifact.clone(),
        related,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::evtx::ProcMeta;

    fn win(ts: &str, pid: u32, ppid: u32, name: &str, parent: &str, user: &str) -> Event {
        Event {
            source_file: String::new(),
            timestamp: ts.to_string(),
            computer: "PC".to_string(),
            artifact: "evtx:4688".to_string(),
            event_id: 4688,
            pid,
            subject_username: user.to_string(),
            target_username: String::new(),
            processname: name.to_string(),
            commandline: Some(name.to_string()),
            parentprocessname: parent.to_string(),
            meta: Some(Box::new(ProcMeta { ppid, ..Default::default() })),
        }
    }

    fn lnx(ts: &str, pid: u32, ppid: u32, name: &str, parent: &str, user: &str) -> Event {
        let mut e = win(ts, pid, ppid, name, parent, user);
        e.artifact = "linux:audit:execve".to_string();
        e.event_id = 0;
        e
    }

    fn rules(events: &[Event]) -> Vec<&'static str> {
        let tree = ProcessTree::build(events);
        run(events, &tree).into_iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn test_normal_boot_tree_is_silent() {
        let events = vec![
            win("2026-01-01T00:00:00.000000Z", 300, 4, r"C:\Windows\System32\smss.exe", "", "SYSTEM"),
            win("2026-01-01T00:00:01.000000Z", 400, 300, r"C:\Windows\System32\csrss.exe", r"C:\Windows\System32\smss.exe", "SYSTEM"),
            win("2026-01-01T00:00:01.000000Z", 500, 300, r"C:\Windows\System32\wininit.exe", r"C:\Windows\System32\smss.exe", "SYSTEM"),
            win("2026-01-01T00:00:02.000000Z", 600, 500, r"C:\Windows\System32\services.exe", r"C:\Windows\System32\wininit.exe", "SYSTEM"),
            win("2026-01-01T00:00:02.000000Z", 610, 500, r"C:\Windows\System32\lsass.exe", r"C:\Windows\System32\wininit.exe", "SYSTEM"),
            win("2026-01-01T00:00:03.000000Z", 700, 600, r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe", "SYSTEM"),
            win("2026-01-01T00:00:03.000000Z", 701, 700, r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\svchost.exe", "SYSTEM"),
            win("2026-01-01T00:00:04.000000Z", 800, 700, r"C:\Windows\System32\RuntimeBroker.exe", r"C:\Windows\System32\svchost.exe", "LAB\\bob"),
            win("2026-01-01T00:00:05.000000Z", 900, 300, r"C:\Windows\System32\winlogon.exe", r"C:\Windows\System32\smss.exe", "SYSTEM"),
            win("2026-01-01T00:00:06.000000Z", 910, 900, r"C:\Windows\System32\userinit.exe", r"C:\Windows\System32\winlogon.exe", "LAB\\bob"),
            win("2026-01-01T00:00:07.000000Z", 920, 910, r"C:\Windows\explorer.exe", r"C:\Windows\System32\userinit.exe", "LAB\\bob"),
            win("2026-01-01T00:00:08.000000Z", 930, 920, r"C:\Windows\System32\cmd.exe", r"C:\Windows\explorer.exe", "LAB\\bob"),
            win("2026-01-01T00:00:09.000000Z", 940, 700, r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\svchost.exe", "SYSTEM"),
        ];
        let r = rules(&events);
        assert_eq!(r, vec!["GEN-SVCHOST-SHELL"], "only the low-score pointer for svchost > cmd");
    }

    #[test]
    fn test_core_process_with_wrong_parent() {
        let events = vec![
            win("2026-01-01T00:00:00.000000Z", 100, 1, r"C:\Windows\explorer.exe", "", "LAB\\bob"),
            win("2026-01-01T00:00:01.000000Z", 200, 100, r"C:\Users\bob\AppData\Local\Temp\svchost.exe", r"C:\Windows\explorer.exe", "LAB\\bob"),
        ];
        assert_eq!(rules(&events), vec!["GEN-CORE-PARENT"]);
    }

    #[test]
    fn test_restricted_parents_and_backdoors() {
        let events = vec![
            win("2026-01-01T00:00:00.000000Z", 100, 1, r"C:\Windows\System32\lsass.exe", "", "SYSTEM"),
            win("2026-01-01T00:00:01.000000Z", 200, 100, r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\lsass.exe", "SYSTEM"),
            win("2026-01-01T00:00:02.000000Z", 300, 1, r"C:\Windows\System32\winlogon.exe", "", "SYSTEM"),
            win("2026-01-01T00:00:03.000000Z", 310, 300, r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\winlogon.exe", "SYSTEM"),
            win("2026-01-01T00:00:04.000000Z", 320, 300, r"C:\Windows\System32\utilman.exe", r"C:\Windows\System32\winlogon.exe", "SYSTEM"),
            win("2026-01-01T00:00:05.000000Z", 330, 320, r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\utilman.exe", "SYSTEM"),
        ];
        let r = rules(&events);
        assert!(r.contains(&"GEN-RESTRICTED-PARENT"));
        assert_eq!(r.iter().filter(|x| **x == "GEN-ACCESSIBILITY-BACKDOOR").count(), 2, "winlogon > cmd and utilman > cmd");
        assert_eq!(r.iter().filter(|x| **x == "GEN-RESTRICTED-PARENT").count(), 2, "lsass > cmd and winlogon > cmd");
    }

    #[test]
    fn test_office_web_and_remote_exec_pairs() {
        let events = vec![
            win("2026-01-01T00:00:00.000000Z", 10, 1, r"C:\Program Files\Microsoft Office\WINWORD.EXE", "", "LAB\\bob"),
            win("2026-01-01T00:00:01.000000Z", 11, 10, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE", "LAB\\bob"),
            win("2026-01-01T00:00:02.000000Z", 20, 1, r"c:\windows\system32\inetsrv\w3wp.exe", "", "IIS APPPOOL\\DefaultAppPool"),
            win("2026-01-01T00:00:03.000000Z", 21, 20, r"C:\Windows\System32\cmd.exe", r"c:\windows\system32\inetsrv\w3wp.exe", "IIS APPPOOL\\DefaultAppPool"),
            win("2026-01-01T00:00:04.000000Z", 30, 1, r"C:\Windows\PSEXESVC.exe", r"C:\Windows\System32\services.exe", "SYSTEM"),
            win("2026-01-01T00:00:05.000000Z", 31, 30, r"C:\Windows\System32\cmd.exe", r"C:\Windows\PSEXESVC.exe", "LAB\\admin"),
            win("2026-01-01T00:00:06.000000Z", 40, 1, r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\services.exe", "SYSTEM"),
        ];
        let r = rules(&events);
        assert_eq!(r, vec!["GEN-OFFICE-SHELL", "GEN-WEBSERVER-SHELL", "GEN-REMOTE-EXEC", "GEN-SERVICES-SHELL"]);
    }

    #[test]
    fn test_parent_gone_and_duplicate_core() {
        let mut events = vec![
            win("2026-01-01T00:00:00.000000Z", 500, 300, r"C:\Windows\System32\wininit.exe", r"C:\Windows\System32\smss.exe", "SYSTEM"),
            win("2026-01-01T00:00:01.000000Z", 610, 500, r"C:\Windows\System32\lsass.exe", r"C:\Windows\System32\wininit.exe", "SYSTEM"),
            win("2026-01-01T00:00:02.000000Z", 100, 1, r"C:\Windows\explorer.exe", "", "LAB\\bob"),
            win("2026-01-01T00:00:03.000000Z", 100, 0, r"C:\Windows\explorer.exe", "", "LAB\\bob"),
            win("2026-01-01T00:00:04.000000Z", 200, 100, r"C:\Users\bob\evil.exe", r"C:\Windows\explorer.exe", "LAB\\bob"),
            win("2026-01-01T00:01:00.000000Z", 999, 500, r"C:\Users\bob\lsass.exe", r"C:\Windows\System32\wininit.exe", "SYSTEM"),
        ];
        events[3].artifact = "evtx:4689".to_string();
        events[3].meta = None;
        let r = rules(&events);
        assert!(r.contains(&"GEN-PARENT-GONE"), "{:?}", r);
        assert!(r.contains(&"GEN-DUPLICATE-CORE"), "{:?}", r);
    }

    #[test]
    fn test_linux_service_account_and_server_shells() {
        let events = vec![
            lnx("2026-01-01T00:00:00.000000Z", 100, 1, "/usr/sbin/apache2", "PID: 1", "www-data"),
            lnx("2026-01-01T00:00:01.000000Z", 101, 100, "/usr/bin/dash", "/usr/sbin/apache2 (PID: 100)", "www-data"),
            lnx("2026-01-01T00:00:02.000000Z", 102, 50, "/usr/bin/nc", "PID: 50", "www-data"),
            lnx("2026-01-01T00:00:03.000000Z", 103, 60, "/usr/bin/php8.1", "PID: 60", "www-data"),
            lnx("2026-01-01T00:00:04.000000Z", 104, 70, "/tmp/.x/miner", "/usr/sbin/cron (PID: 70)", "root"),
            lnx("2026-01-01T00:00:05.000000Z", 105, 80, "/usr/bin/bash", "/usr/sbin/sshd (PID: 80)", "alice"),
        ];
        let r = rules(&events);
        assert_eq!(r, vec!["GEN-WEBSERVER-SHELL", "GEN-SVCACCT-SHELL", "GEN-CRON-SCRATCH"]);
    }
}
