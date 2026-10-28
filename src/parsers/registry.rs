use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use sootmark_registry::{amcache, bam, mru, persistence, programs, shimcache, system, tasks, userassist, Data, Hive};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::utils::{filetime_to_iso, is_registry_hive, resolve_sid};

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Helper to infer a probable username from the hive path (e.g. "C:\Users\john\NTUSER.DAT" -> "john")
fn infer_user_from_path(path: &Path) -> Option<String> {
    let filename = path.file_name()?.to_string_lossy().to_string();
    let lower_name = filename.to_lowercase();

    // Check parent directory if filename is standard NTUSER.DAT or UsrClass.dat
    if lower_name == "ntuser.dat" || lower_name == "usrclass.dat" {
        if let Some(parent) = path.parent() {
            let parent_name = parent.file_name()?.to_string_lossy().to_string();
            if !parent_name.eq_ignore_ascii_case("Users") {
                return Some(parent_name);
            }
        }
    }

    // Check prefixes/suffixes in reconstructed hive names, e.g. "anita-NTUSER.DAT" or "E_anitkuma_NTUSER.DAT"
    if lower_name.contains("ntuser") || lower_name.contains("usrclass") {
        let clean = filename
            .replace(".DAT", "")
            .replace(".dat", "")
            .replace(".hve", "")
            .replace(".HVE", "");
        let parts: Vec<&str> = clean.split(['-', '_']).collect();
        for part in parts {
            let part_lower = part.to_lowercase();
            if part_lower != "ntuser" && part_lower != "usrclass" && part_lower != "e" && part_lower != "c" && !part_lower.is_empty() {
                return Some(part.to_string());
            }
        }
    }

    None
}

/// True for the SYSTEM hive (also in reconstructed names such as `HOST_SYSTEM`)
fn is_system_hive_name(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_uppercase())
        .unwrap_or_default();
    name == "SYSTEM" || name.ends_with("_SYSTEM") || name.ends_with("-SYSTEM")
}

/// Reads the computer name stored in a SYSTEM hive, if any
pub fn detect_computer_name(path: &Path) -> Option<String> {
    let raw = fs::read(path).ok()?;
    if !is_registry_hive(&raw) {
        return None;
    }
    let data = crate::parsers::tx_log::replay_hive_logs(path, &raw, true);
    let hive = Hive::parse(&data[..]).ok()?;
    let identity = system::identity(&hive);
    identity
        .entries
        .first()
        .and_then(|id| id.computer_name.as_ref().map(|c| c.name.clone()))
        .filter(|n| !n.trim().is_empty())
}

/// Parses an offline Windows Registry hive file and extracts forensic execution artifacts
pub fn parse_registry_file(file_path: &Path, silent: bool) -> Result<Vec<Event>, Box<dyn Error>> {
    parse_registry_file_with_defaults(file_path, silent, None)
}

/// Same as [`parse_registry_file`] with a fallback computer name for hives that do not carry
/// one themselves (NTUSER.DAT, UsrClass.dat, SOFTWARE, Amcache.hve), typically taken from the
/// SYSTEM hive collected alongside.
pub fn parse_registry_file_with_defaults(
    file_path: &Path,
    silent: bool,
    default_computer: Option<&str>,
) -> Result<Vec<Event>, Box<dyn Error>> {
    let raw_data = fs::read(file_path)?;
    if !is_registry_hive(&raw_data) {
        return Ok(vec![]);
    }

    // 🔄 Automatically detect and replay transaction logs (.LOG, .LOG1, .LOG2) in memory
    let data = crate::parsers::tx_log::replay_hive_logs(file_path, &raw_data, silent);

    let hive = Hive::parse(&data[..]).map_err(|e| format!("Failed to parse registry hive: {}", e))?;
    let mut events = Vec::new();

    // Determine computer name and user SID mappings from SYSTEM / SOFTWARE identity if available
    let identity_found = system::identity(&hive);
    let id_opt = identity_found.entries.first();

    let mut computer_name = default_computer.unwrap_or("Unknown").to_string();
    let mut sid_to_user: HashMap<String, String> = HashMap::new();

    if let Some(id) = id_opt {
        if let Some(ref comp) = id.computer_name {
            computer_name = comp.name.clone();
        }

        // Map user profile SIDs to username from ProfileImagePath (e.g. C:\Users\anitkuma -> anitkuma)
        for profile in &id.profiles {
            let mut username = profile.sid.clone();
            if let Some(ref img_path) = profile.image_path {
                if let Some(inferred) = img_path.rsplit('\\').next() {
                    if !inferred.is_empty() {
                        username = inferred.to_string();
                    }
                }
            }
            sid_to_user.insert(profile.sid.clone(), username.clone());

            // Extract logon event if available
            if let Some(loaded_ft) = profile.loaded {
                if let Some(ts) = filetime_to_iso(loaded_ft) {
                    events.push(Event {
                        timestamp: ts,
                        computer: computer_name.clone(),
                        artifact: "registry:profile_logon".to_string(),
                        event_id: 0,
                        pid: 0,
                        subject_username: username.clone(),
                        target_username: username.clone(),
                        processname: "UserLogon".to_string(),
                        commandline: Some(format!("Profile SID: {}, Path: {:?}", profile.sid, profile.image_path)),
                        parentprocessname: "winlogon.exe".to_string(),
                    });
                }
            }

            // Extract logoff event if available
            if let Some(unloaded_ft) = profile.unloaded {
                if let Some(ts) = filetime_to_iso(unloaded_ft) {
                    events.push(Event {
                        timestamp: ts,
                        computer: computer_name.clone(),
                        artifact: "registry:profile_logoff".to_string(),
                        event_id: 0,
                        pid: 0,
                        subject_username: username.clone(),
                        target_username: username,
                        processname: "UserLogoff".to_string(),
                        commandline: Some(format!("Profile SID: {}, Path: {:?}", profile.sid, profile.image_path)),
                        parentprocessname: "winlogon.exe".to_string(),
                    });
                }
            }
        }
    }

    let user_from_filename = infer_user_from_path(file_path);

    // ==========================================
    // 1. BAM / DAM (Background / Desktop Activity Moderator)
    // ==========================================
    if let Ok(Some(current_cs)) = hive.current_control_set() {
        if let Ok(bam_entries) = bam::entries(&hive, &current_cs) {
            for entry in bam_entries {
                if let Some(timestamp) = filetime_to_iso(entry.last_run) {
                    let user = sid_to_user
                        .get(&entry.sid)
                        .cloned()
                        .unwrap_or_else(|| resolve_sid(&entry.sid));

                    events.push(Event {
                        timestamp,
                        computer: computer_name.clone(),
                        artifact: format!("registry:{}", entry.service), // "registry:bam" or "registry:dam"
                        event_id: 0,
                        pid: 0,
                        subject_username: user.clone(),
                        target_username: user,
                        processname: entry.program.clone(),
                        commandline: Some(format!("Key: {}", entry.key)),
                        parentprocessname: "N/A".to_string(),
                    });
                }
            }
        }

        // ==========================================
        // 2. ShimCache / AppCompatCache
        // ==========================================
        let appcompat_path = format!(r"{}\Control\Session Manager\AppCompatCache", current_cs);
        if let Ok(Some(key)) = hive.open(&appcompat_path) {
            if let Ok(Some(val)) = key.value("AppCompatCache") {
                if let Data::Bytes(bytes) = val.data() {
                    if let Ok((_format, shim_entries)) = shimcache::parse(&bytes) {
                        for entry in shim_entries {
                            if let Some(timestamp) = filetime_to_iso(entry.last_modified) {
                                let exec_str = match entry.executed {
                                    Some(true) => "Executed: True",
                                    Some(false) => "Executed: False",
                                    None => "Executed: Unknown/NotRecorded",
                                };
                                events.push(Event {
                                    timestamp,
                                    computer: computer_name.clone(),
                                    artifact: "registry:shimcache".to_string(),
                                    event_id: 0,
                                    pid: 0,
                                    subject_username: "SYSTEM".to_string(),
                                    target_username: "N/A".to_string(),
                                    processname: entry.path.clone(),
                                    commandline: Some(format!("Position: {}, {}", entry.position, exec_str)),
                                    parentprocessname: "N/A".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // ==========================================
        // 3. Services Execution / Persistence
        // ==========================================
        let services_path = format!(r"{}\Services", current_cs);
        if let Ok(Some(services_key)) = hive.open(&services_path) {
            if let Ok(subkeys) = services_key.subkeys() {
                for svc_key in subkeys {
                    let svc_name = svc_key.name.clone();
                    let mut image_path = None;
                    let mut service_dll = None;
                    let mut display_name = None;

                    if let Ok(Some(val)) = svc_key.value("ImagePath") {
                        if let Data::String(s) = val.data() {
                            image_path = Some(s);
                        }
                    }
                    if let Ok(Some(val)) = svc_key.value("DisplayName") {
                        if let Data::String(s) = val.data() {
                            display_name = Some(s);
                        }
                    }
                    if let Ok(Some(params)) = svc_key.subkey("Parameters") {
                        if let Ok(Some(val)) = params.value("ServiceDll") {
                            if let Data::String(s) = val.data() {
                                service_dll = Some(s);
                            }
                        }
                    }

                    if image_path.is_some() || service_dll.is_some() {
                        if let Some(timestamp) = filetime_to_iso(svc_key.last_written) {
                            let proc_name = image_path.unwrap_or_else(|| service_dll.clone().unwrap_or_default());
                            let details = format!(
                                "Service: {}, Display: {}, Dll: {}",
                                svc_name,
                                display_name.as_deref().unwrap_or("N/A"),
                                service_dll.as_deref().unwrap_or("N/A")
                            );
                            events.push(Event {
                                timestamp,
                                computer: computer_name.clone(),
                                artifact: "registry:services".to_string(),
                                event_id: 0,
                                pid: 0,
                                subject_username: "SYSTEM".to_string(),
                                target_username: "N/A".to_string(),
                                processname: proc_name,
                                commandline: Some(details),
                                parentprocessname: "services.exe".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // ==========================================
    // 4. UserAssist (NTUSER.DAT)
    // ==========================================
    let is_user_hive = file_path
        .file_name()
        .map(|n| {
            let l = n.to_string_lossy().to_lowercase();
            l.contains("ntuser") || l.contains("usrclass")
        })
        .unwrap_or(false);
    let user_name = user_from_filename
        .clone()
        .unwrap_or_else(|| if is_user_hive { "User".to_string() } else { "SYSTEM".to_string() });
    if let Ok(Some(ua_key)) = hive.open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist") {
        if let Ok(guid_keys) = ua_key.subkeys() {
            for guid_key in guid_keys {
                if let Ok(Some(count_key)) = guid_key.subkey("Count") {
                    if let Ok(values) = count_key.values() {
                        for val in values.into_iter().flatten() {
                            if let Data::Bytes(bytes) = val.data() {
                                if let Some(counts) = userassist::counts(&bytes) {
                                    if counts.last_run > 0 {
                                        if let Some(timestamp) = filetime_to_iso(counts.last_run) {
                                            let decoded = userassist::decode(&val.name);
                                            let resolved_path = userassist::path(&decoded);
                                            let details = format!(
                                                "RunCount: {}, FocusCount: {:?}, FocusMs: {:?}",
                                                counts.run_count, counts.focus_count, counts.focus_ms
                                            );

                                            events.push(Event {
                                                timestamp,
                                                computer: computer_name.clone(),
                                                artifact: "registry:userassist".to_string(),
                                                event_id: 0,
                                                pid: 0,
                                                subject_username: user_name.clone(),
                                                target_username: user_name.clone(),
                                                processname: resolved_path,
                                                commandline: Some(details),
                                                parentprocessname: "explorer.exe".to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ==========================================
    // 5. MRU (RunMRU, RecentDocs, TypedPaths)
    // ==========================================
    let mru_found = mru::entries(&hive);
    for entry in mru_found.entries {
        if let Some(timestamp) = filetime_to_iso(entry.key_last_written) {
            let artifact_name = match entry.list {
                mru::List::RunMru => "registry:runmru",
                mru::List::RecentDocs => "registry:recentdocs",
                mru::List::TypedPaths => "registry:typedpaths",
                mru::List::WordWheelQuery => "registry:wordwheelquery",
            };
            events.push(Event {
                timestamp,
                computer: computer_name.clone(),
                artifact: artifact_name.to_string(),
                event_id: 0,
                pid: 0,
                subject_username: user_name.clone(),
                target_username: user_name.clone(),
                processname: entry.text.clone(),
                commandline: Some(format!("List: {:?}, Position: {:?}, Key: {}", entry.list, entry.position, entry.key)),
                parentprocessname: "explorer.exe".to_string(),
            });
        }
    }

    // ==========================================
    // 6. Run & RunOnce Keys (SOFTWARE / NTUSER.DAT)
    // ==========================================
    let run_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    for path in run_paths {
        if let Ok(Some(key)) = hive.open(path) {
            if let Some(timestamp) = filetime_to_iso(key.last_written) {
                if let Ok(values) = key.values() {
                    for val in values.into_iter().flatten() {
                        let mut cmd_str = String::new();
                        if let Data::String(s) = val.data() {
                            cmd_str = s;
                        }
                        if !cmd_str.is_empty() {
                            events.push(Event {
                                timestamp: timestamp.clone(),
                                computer: computer_name.clone(),
                                artifact: "registry:runkeys".to_string(),
                                event_id: 0,
                                pid: 0,
                                subject_username: user_name.clone(),
                                target_username: user_name.clone(),
                                processname: val.name.clone(),
                                commandline: Some(format!("Key: {}\\{}, Cmd: {}", path, val.name, cmd_str)),
                                parentprocessname: "explorer.exe".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // ==========================================
    // 6b. MUICache (UsrClass.dat) and the Program Compatibility Assistant store (NTUSER.DAT):
    //     programs launched by the user, keyed by path. Only the key time is known.
    // ==========================================
    let mui_paths = [
        r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    ];
    for path in mui_paths {
        if let Ok(Some(key)) = hive.open(path) {
            if let (Some(timestamp), Ok(values)) = (filetime_to_iso(key.last_written), key.values()) {
                let mut seen: HashSet<String> = HashSet::new();
                for val in values.into_iter().flatten() {
                    let name = val.name.clone();
                    let lower = name.to_ascii_lowercase();
                    let (exe, what) = if let Some(p) = lower.strip_suffix(".friendlyappname") {
                        (name[..p.len()].to_string(), "FriendlyAppName")
                    } else if let Some(p) = lower.strip_suffix(".applicationcompany") {
                        (name[..p.len()].to_string(), "ApplicationCompany")
                    } else {
                        continue;
                    };
                    if !seen.insert(exe.to_ascii_lowercase()) {
                        continue;
                    }
                    let label = match val.data() {
                        Data::String(s) => s,
                        _ => String::new(),
                    };
                    events.push(Event {
                        timestamp: timestamp.clone(),
                        computer: computer_name.clone(),
                        artifact: "registry:muicache".to_string(),
                        event_id: 0,
                        pid: 0,
                        subject_username: user_name.clone(),
                        target_username: user_name.clone(),
                        processname: exe,
                        commandline: Some(format!("MUICache {}: {} (key time)", what, label)),
                        parentprocessname: "explorer.exe".to_string(),
                    });
                }
            }
        }
    }
    let pca_store = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store";
    if let Ok(Some(key)) = hive.open(pca_store) {
        if let (Some(timestamp), Ok(values)) = (filetime_to_iso(key.last_written), key.values()) {
            for val in values.into_iter().flatten() {
                let name = val.name.clone();
                if name.is_empty() {
                    continue;
                }
                events.push(Event {
                    timestamp: timestamp.clone(),
                    computer: computer_name.clone(),
                    artifact: "registry:pca_store".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: user_name.clone(),
                    target_username: user_name.clone(),
                    processname: name,
                    commandline: Some("Program Compatibility Assistant store entry (key time)".to_string()),
                    parentprocessname: "PcaSvc".to_string(),
                });
            }
        }
    }

    // ==========================================
    // 7. Scheduled Tasks (TaskCache in SOFTWARE)
    // ==========================================
    let tasks_found = tasks::tasks(&hive);
    for task in tasks_found.entries {
        let mut action_cmd = String::new();
        let mut action_prog = String::new();

        if let Some(tasks::Actions::Decoded { actions, .. }) = &task.actions {
            for action in actions {
                if let tasks::Action::Exec { command, arguments, .. } = action {
                    action_prog = command.clone();
                    action_cmd = format!("{} {}", command, arguments);
                }
            }
        }

        if let Some(dyn_info) = task.dynamic {
            if let Some(ts) = filetime_to_iso(dyn_info.last_start) {
                let proc = if !action_prog.is_empty() { action_prog.clone() } else { task.path.clone() };
                events.push(Event {
                    timestamp: ts,
                    computer: computer_name.clone(),
                    artifact: "registry:tasks:last_start".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: task.author.clone().unwrap_or_else(|| "SYSTEM".to_string()),
                    target_username: "N/A".to_string(),
                    processname: proc,
                    commandline: Some(format!("Task: {}, Actions: {}", task.path, action_cmd)),
                    parentprocessname: "taskeng.exe".to_string(),
                });
            }

            if let Some(ts_reg) = filetime_to_iso(dyn_info.registered) {
                let proc = if !action_prog.is_empty() { action_prog } else { task.path.clone() };
                events.push(Event {
                    timestamp: ts_reg,
                    computer: computer_name.clone(),
                    artifact: "registry:tasks:registered".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: task.author.unwrap_or_else(|| "SYSTEM".to_string()),
                    target_username: "N/A".to_string(),
                    processname: proc,
                    commandline: Some(format!("Task: {}, Actions: {}", task.path, action_cmd)),
                    parentprocessname: "schtasks.exe".to_string(),
                });
            }
        }
    }

    // ==========================================
    // 8. Persistence (Winlogon, IFEO, SilentProcessExit, AppInit)
    // ==========================================
    let pers_found = persistence::entries(&hive);
    for entry in pers_found.entries {
        if entry.deviates {
            if let Some(timestamp) = filetime_to_iso(entry.key_last_written) {
                events.push(Event {
                    timestamp,
                    computer: computer_name.clone(),
                    artifact: format!("registry:persistence:{}", entry.mechanism.name()),
                    event_id: 0,
                    pid: 0,
                    subject_username: "SYSTEM".to_string(),
                    target_username: "N/A".to_string(),
                    processname: entry.value.clone(),
                    commandline: Some(format!("Key: {}, Data: {}", entry.key, entry.data)),
                    parentprocessname: "N/A".to_string(),
                });
            }
        }
    }

    // ==========================================
    // 9. Installed Programs (Uninstall in SOFTWARE / NTUSER.DAT)
    // ==========================================
    let progs_found = programs::programs(&hive);
    for prog in progs_found.entries {
        let ft = prog
            .install_date()
            .and_then(|st| st.wall_clock_filetime())
            .unwrap_or(prog.key_last_written);

        if let Some(timestamp) = filetime_to_iso(ft) {
            let proc_name = prog
                .display_name
                .clone()
                .unwrap_or_else(|| prog.key_name.clone());
            let details = format!(
                "Version: {}, Publisher: {}, Uninstall: {}",
                prog.display_version.as_deref().unwrap_or("N/A"),
                prog.publisher.as_deref().unwrap_or("N/A"),
                prog.uninstall_string.as_deref().unwrap_or("N/A")
            );

            events.push(Event {
                timestamp,
                computer: computer_name.clone(),
                artifact: "registry:installed_program".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: if prog.user { user_name.clone() } else { "SYSTEM".to_string() },
                target_username: "N/A".to_string(),
                processname: proc_name,
                commandline: Some(details),
                parentprocessname: "installer".to_string(),
            });
        }
    }

    // ==========================================
    // 10. Amcache.hve (Applications, Executables & SHA-1)
    // ==========================================
    if let Ok(Some(amcache_data)) = amcache::read(&hive) {
        for entry in amcache_data.entries {
            let ft = entry
                .filetime("FileModified")
                .or_else(|| entry.filetime("FileCreated"))
                .or_else(|| entry.filetime("LinkDate"))
                .unwrap_or(entry.last_written);

            if let Some(timestamp) = filetime_to_iso(ft) {
                let path_str = entry
                    .get("LowerCaseLongPath")
                    .or_else(|| entry.get("FullPath"))
                    .or_else(|| entry.get("FilePaths"))
                    .unwrap_or(&entry.key);

                let sha1_str = entry.get("SHA1").or_else(|| entry.get("FileId")).unwrap_or("N/A");

                events.push(Event {
                    timestamp,
                    computer: computer_name.clone(),
                    artifact: format!("registry:amcache:{}", entry.class.name()),
                    event_id: 0,
                    pid: 0,
                    subject_username: "SYSTEM".to_string(),
                    target_username: "N/A".to_string(),
                    processname: path_str.to_string(),
                    commandline: Some(format!("SHA1: {}, Class: {}", sha1_str, entry.class.name())),
                    parentprocessname: "Amcache.hve".to_string(),
                });
            }
        }
    }

    // ==========================================
    // 11. Microsoft Office TrustRecords (Macros / Trusted Documents)
    // ==========================================
    if let Ok(Some(office_key)) = hive.open(r"Software\Microsoft\Office") {
        if let Ok(versions) = office_key.subkeys() {
            for ver_key in versions {
                if let Ok(apps) = ver_key.subkeys() {
                    for app_key in apps {
                        let tr_path = format!(
                            r"Software\Microsoft\Office\{}\{}\Security\Trusted Documents\TrustRecords",
                            ver_key.name, app_key.name
                        );
                        if let Ok(Some(tr_key)) = hive.open(&tr_path) {
                            if let Some(timestamp) = filetime_to_iso(tr_key.last_written) {
                                if let Ok(values) = tr_key.values() {
                                    for val in values.into_iter().flatten() {
                                        events.push(Event {
                                            timestamp: timestamp.clone(),
                                            computer: computer_name.clone(),
                                            artifact: "registry:msoffice:trustrecords".to_string(),
                                            event_id: 0,
                                            pid: 0,
                                            subject_username: user_name.clone(),
                                            target_username: user_name.clone(),
                                            processname: val.name.clone(),
                                            commandline: Some(format!(
                                                "Office: {}/{} Trusted Document / Macro Execution Enabled",
                                                ver_key.name, app_key.name
                                            )),
                                            parentprocessname: format!("{}.exe", app_key.name),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    print_registry_statistics(file_path, &events, silent);

    Ok(events)
}

/// Recursively scans a directory for Windows Registry hive files
pub fn find_registry_files(target: &Path) -> Vec<String> {
    let mut reg_files = vec![];

    if target.is_file() {
        if is_likely_registry_file(target) {
            reg_files.push(target.to_string_lossy().to_string());
        }
    } else if target.is_dir() {
        if let Ok(entries) = fs::read_dir(target) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    reg_files.extend(find_registry_files(&path));
                } else if is_likely_registry_file(&path) {
                    reg_files.push(path.to_string_lossy().to_string());
                }
            }
        }
    }

    reg_files
}

/// Quick check if a file might be a Windows Registry hive by name or header signature
fn is_likely_registry_file(path: &Path) -> bool {
    let filename = match path.file_name() {
        Some(name) => name.to_string_lossy().to_uppercase(),
        None => return false,
    };

    // Ignore known transaction logs and backup files
    if filename.contains(".LOG") || filename.ends_with(".LOG1") || filename.ends_with(".LOG2") || filename.ends_with(".SAV") {
        return false;
    }

    // Check standard registry hive names
    let is_standard = filename == "SYSTEM"
        || filename == "SOFTWARE"
        || filename == "SAM"
        || filename == "SECURITY"
        || filename == "DEFAULT"
        || filename.ends_with("NTUSER.DAT")
        || filename.ends_with("USRCLASS.DAT")
        || filename.ends_with("AMCACHE.HVE")
        || filename.ends_with(".HVE")
        || filename.contains("NTUSER")
        || filename.contains("USRCLASS");

    if is_standard {
        return true;
    }

    // Fallback: Check magic bytes if file can be opened and read
    if let Ok(mut file) = fs::File::open(path) {
        use std::io::Read;
        let mut header = [0u8; 4];
        if file.read_exact(&mut header).is_ok() && &header == b"regf" {
            return true;
        }
    }

    false
}

/// Processes a Registry target (single file or recursive directory) and returns extracted events
pub fn process_registry_target(target: &Path, silent: bool) -> Result<Vec<Event>, Box<dyn Error>> {
    process_registry_target_with_hint(target, silent, None)
}

/// Same as [`process_registry_target`] with a hostname hint discovered during ingestion (triage
/// package name). The computer name stored in a SYSTEM hive found alongside still wins.
pub fn process_registry_target_with_hint(
    target: &Path,
    silent: bool,
    hint: Option<&str>,
) -> Result<Vec<Event>, Box<dyn Error>> {
    let mut all_events = Vec::new();

    if target.is_dir() {
        log_message(silent, &format!("Scanning directory for Registry hives: {}", target.display()));
        let reg_files = find_registry_files(target);
        log_message(silent, &format!("Found {} Registry hive files", reg_files.len()));

        if reg_files.is_empty() {
            return Ok(all_events);
        }

        // The SYSTEM hive is the only one that knows the computer name: resolve it first so the
        // events of NTUSER.DAT / SOFTWARE / Amcache collected alongside are attributed to the host.
        let default_computer = reg_files
            .iter()
            .filter(|f| is_system_hive_name(Path::new(f)))
            .find_map(|f| detect_computer_name(Path::new(f)))
            .or_else(|| hint.map(|h| h.to_string()));
        if let Some(ref name) = default_computer {
            log_message(silent, &format!("🖥️ Computer name for hives in this target: {}", name));
        }

        let pb = ProgressBar::new(reg_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.green/blue} {pos}/{len} {msg}")
                .unwrap(),
        );

        let processed: Vec<Vec<Event>> = reg_files
            .par_iter()
            .filter_map(|file| {
                let path = Path::new(file);
                log_message(silent, &format!("Processing Registry hive: {}", path.display()));
                let res = match parse_registry_file_with_defaults(path, silent, default_computer.as_deref()) {
                    Ok(events) => Some(events),
                    Err(e) => {
                        log_message(silent, &format!("⚠️ Warning: cannot parse hive {}: {}", path.display(), e));
                        None
                    }
                };
                pb.inc(1);
                res
            })
            .collect();

        pb.finish_and_clear();
        all_events = processed.into_iter().flatten().collect();
    } else if target.is_file() {
        all_events = parse_registry_file_with_defaults(target, silent, hint)?;
    }

    Ok(all_events)
}

/// Backward compatibility entry point
pub fn parse_registry(file_path: &str, silent: bool) -> Result<Vec<Event>, Box<dyn Error>> {
    parse_registry_file(Path::new(file_path), silent)
}

/// Prints statistics for a processed Registry hive
fn print_registry_statistics(file_path: &Path, events: &[Event], silent: bool) {
    if events.is_empty() {
        log_message(silent, &format!("No relevant execution events found in: {}", file_path.display()));
        return;
    }

    let first_event = &events.first().unwrap().timestamp;
    let last_event = &events.last().unwrap().timestamp;
    let total_events = events.len();

    let unique_artifacts: HashSet<_> = events.iter().map(|e| e.artifact.clone()).collect();
    let unique_users: HashSet<_> = events.iter().map(|e| e.subject_username.clone()).collect();

    log_message(silent, &format!(
        "\nSTATS Registry Analysis: {}\n\
        ├─ First Event: {}\n\
        ├─ Last Event: {}\n\
        ├─ Total Events: {}\n\
        ├─ Unique Users: {}\n\
        ├─ Unique Artifacts: {:?}\n\
        └─────────────────────────\n",
        file_path.display(),
        first_event,
        last_event,
        total_events,
        unique_users.len(),
        unique_artifacts
    ));
}
