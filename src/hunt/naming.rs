//! Naming and path rules: what the executable's name and folder say on their own. These
//! are the first rules that judge a row without a parent, so they reach Prefetch,
//! Amcache, BAM, ShimCache, UserAssist, services, tasks and the NTFS drops as well as
//! the process-creation logs.
//!
//! A rule fires only on rows whose `processname` is an executable: a Windows path or name
//! with a code extension, a Linux absolute path, or a Linux process record. Task names,
//! service display names, WMI consumers and package names are left alone. Where the
//! source only gave a bare name (Defender's MpLog, `linux:audit:user_cmd`) the path rules
//! have nothing to say and only the name rules run.

use super::names::{self, DirFamily, NameClass, Os};
use super::tree::{self, ProcessTree};
use super::Finding;
use crate::parsers::evtx::Event;

const T_MASQ: &str = "T1036";
const T_MASQ_NAME_LOC: &str = "T1036.005";
const T_RTLO: &str = "T1036.002";
const T_DOUBLE_EXT: &str = "T1036.007";
const T_ADS: &str = "T1564.004";
const T_USER_EXEC: &str = "T1204.002";
const T_INGRESS: &str = "T1105";

/// Runs the naming and path rules over every row.
pub fn run(events: &[Event], tree: &ProcessTree) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, e) in events.iter().enumerate() {
        if tree::is_process_exit(&e.artifact) || e.processname.trim().is_empty() {
            continue;
        }
        match names::os_of(&e.artifact) {
            Os::Windows => windows_rules(events, tree, i, &mut out),
            Os::Linux => linux_rules(events, tree, i, &mut out),
        }
    }
    out
}

/// What the row says the file did: an NTFS row is a write, anything else a run.
fn verb(e: &Event) -> &'static str {
    if e.artifact.starts_with("ntfs:") {
        "was written to"
    } else {
        "ran from"
    }
}

/// The last component of the path as the source spelled it.
fn raw_name(e: &Event) -> String {
    let p = e.processname.trim().trim_matches('"');
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
}

fn windows_rules(events: &[Event], tree: &ProcessTree, i: usize, out: &mut Vec<Finding>) {
    let e = &events[i];
    let raw = raw_name(e);
    let expanded = names::expand_windows_path(&e.processname);
    let (dir, name) = names::split_path(Os::Windows, &expanded);
    if !names::is_windows_executable_name(&name) {
        return;
    }
    let fam = if dir.is_empty() { DirFamily::Bare } else { names::windows_family(&format!("{}\\", dir)) };
    let shown_dir = if dir.is_empty() { String::new() } else { e.processname.trim().trim_matches('"').rsplit_once(['\\', '/']).map(|(d, _)| d.to_string()).unwrap_or_default() };
    // Stock Windows behaviour that lands in the scratch folders: Defender's signature stub
    // and Chrome's updater under \Windows\Temp, PowerShell's AppLocker policy probe.
    let stock_in_scratch = (name == "mpsigstub.exe" && dir.contains("\\windows\\temp\\"))
        || (name == "setup.exe" && dir.contains("\\windows\\temp\\cr_"))
        || name.starts_with("__psscriptpolicytest_");
    if stock_in_scratch {
        return;
    }
    let in_vendor_folder = matches!(fam, DirFamily::System32 | DirFamily::SysWow64 | DirFamily::ProgramFiles) || dir.contains("\\winsxs\\");
    let mut push = |rule: &'static str, variant: &'static str, score: u8, mitre: &'static str, title: String, explanation: String| {
        out.push(mk(events, tree, i, rule, variant, score, mitre, title, explanation));
    };

    // the name as written
    if names::has_bidi_or_zero_width(&raw) {
        push(
            "NAM-RTLO",
            "",
            95,
            T_RTLO,
            format!("{} carries a right-to-left override or a zero-width character", raw.escape_default()),
            "The name is displayed differently from how it is spelled, the trick that shows an executable as a document. Nothing legitimate ships with one.".to_string(),
        );
    }
    if names::has_padding(&raw) {
        push(
            "NAM-PADDED",
            "",
            80,
            T_MASQ,
            format!("{} pads its name with spaces before the extension", raw.trim()),
            "The run of spaces pushes the real extension out of sight in a file dialog or an email attachment.".to_string(),
        );
    }
    if let Some(stream) = names::ads_stream(&expanded) {
        push(
            "PATH-ADS",
            "",
            90,
            T_ADS,
            format!("{} {} an alternate data stream ({})", raw, verb(e), stream),
            "An executable stored in an NTFS alternate data stream is invisible to a directory listing. Nothing legitimate runs from one.".to_string(),
        );
    }
    if let Some((inner, last)) = names::double_extension(&name) {
        push(
            "NAM-DOUBLE-EXT",
            "",
            85,
            T_DOUBLE_EXT,
            format!("{} looks like a {} file but is {}", raw, inner, last),
            "A document extension in front of an executable one is how an attachment gets opened. Check where it came from and what it spawned.".to_string(),
        );
    }

    // the name against the system's: a homoglyph anywhere, one edit away only outside the
    // system and vendor folders (where `net1`, `gpasswd`-style real neighbours live)
    if let Some((sys, how)) = names::lookalike_of(Os::Windows, &name) {
        let (variant, score, explanation) = if how == "homoglyph" {
            ("homoglyph", 90, format!("The name reads as {} but is spelled with look-alike characters. The real {} never runs under another spelling.", sys, sys))
        } else {
            ("edit", 75, format!("The name is one edit away from {}. Transposed or dropped letters are how a copy is made to pass at a glance.", sys))
        };
        if how == "homoglyph" || !in_vendor_folder {
            push("NAM-LOOKALIKE", variant, score, T_MASQ_NAME_LOC, format!("{} imitates {} ({})", raw, sys, how), explanation);
        }
    }
    if !dir.is_empty() {
        if let Some(false) = names::windows_system_binary_ok(&dir, &name) {
            let expected = if names::WINDOWS_SYSTEM_BINARIES_ELSEWHERE.iter().any(|(n, _)| *n == name) { "its own folder" } else { "System32" };
            push(
                "NAM-SYSTEM-PATH",
                "",
                90,
                T_MASQ_NAME_LOC,
                format!("{} {} {}, not {}", raw, verb(e), fam.label(), expected),
                format!(
                    "A binary with the name of a Windows system process lives in {} (and its WinSxS and servicing copies). One in {} is a copy or an impostor; compare its hash with the real one and read what it spawned.",
                    expected,
                    fam.label()
                ),
            );
        }
    }

    // the folder
    if !dir.is_empty() {
        if fam == DirFamily::WindowsDir && dir == "c:\\windows" && !names::WINDOWS_ROOT_BINARIES.contains(&name.as_str()) {
            push(
                "PATH-WINDOWS-ROOT",
                "",
                70,
                T_MASQ_NAME_LOC,
                format!("{} {} the root of C:\\Windows", raw, verb(e)),
                "Only a handful of executables belong directly in C:\\Windows (explorer, notepad, regedit, hh, write, splwow64). PsExec-style tools and droppers put theirs there because the folder looks trustworthy.".to_string(),
            );
        }
        let scratch: Option<(&'static str, u8, &'static str)> = match fam {
            DirFamily::Recycle => Some(("recycle", 85, "the Recycle Bin holds deleted files, not programs; running from it hides the file from the user who emptied it")),
            DirFamily::WindowsWritable => Some(("windows-writable", 80, "a folder under C:\\Windows that ordinary users can write to (Temp, Tasks, Debug, Tracing, Fonts, PerfLogs, spool\\drivers): the classic place to stage a binary that looks like it belongs to the system")),
            DirFamily::Public => Some(("public", 70, "Users\\Public is writable by everyone and readable by everyone, so it is where tooling is dropped for every account on the host")),
            DirFamily::ProgramData if dir == "c:\\programdata" => Some(("programdata", 65, "an executable directly in ProgramData, not in a vendor's subfolder, was put there by hand or by a dropper")),
            DirFamily::DriveRoot => Some(("drive-root", 60, "an executable in the root of the drive was put there by hand or by a dropper; installers do not do that")),
            DirFamily::UserAppData if dir.ends_with("\\appdata\\roaming") => Some(("roaming", 60, "an executable directly in AppData\\Roaming, not in a vendor's subfolder, is the default drop location of commodity malware")),
            DirFamily::UserProfile if dir.matches('\\').count() == 2 => Some(("profile", 55, "an executable directly in the user's profile folder was put there by hand or by a dropper")),
            DirFamily::UserLocalAppData if dir.ends_with("\\appdata\\local") => Some(("local-appdata", 50, "an executable directly in AppData\\Local, not in a vendor's subfolder, was put there by hand or by a dropper")),
            DirFamily::UserProfile if dir.contains("\\downloads") || dir.contains("\\desktop") => Some(("downloads-desktop", 45, "a program run from Downloads or the Desktop is what the user fetched or received; worth a look when the rest of the row is odd")),
            DirFamily::Temp => Some(("temp", 40, "installers and updaters run from Temp all day, so on its own this is a pointer; it matters when the name or the command line is odd too")),
            _ => None,
        };
        if let Some((variant, score, why)) = scratch {
            push("PATH-SCRATCH", variant, score, T_MASQ, format!("{} {} {}", raw, verb(e), fam.label()), format!("{}: {}.", shown_dir, why));
        }
        const ARCHIVE_TEMP: &[&str] = &["\\temp\\rar$", "\\temp\\7z", "\\temp\\temp1_", "\\temp\\wz", "\\temp\\winzip", "\\temp\\bnz."];
        if ARCHIVE_TEMP.iter().any(|a| dir.contains(a)) {
            push(
                "PATH-ARCHIVE-TEMP",
                "",
                65,
                T_USER_EXEC,
                format!("{} {} the temporary extraction of an archive", raw, verb(e)),
                format!("{}: the user opened an archive (WinRAR, 7-Zip, Explorer's zip folder) and ran what was inside without extracting it first, which is how an attachment runs.", shown_dir),
            );
        }
        if fam == DirFamily::Unc {
            let webdav = dir.contains("davwwwroot") || dir.contains("@ssl") || dir.contains("@80");
            push(
                "PATH-REMOTE",
                if webdav { "webdav" } else { "share" },
                if webdav { 80 } else { 70 },
                T_INGRESS,
                format!("{} {} {}", raw, verb(e), if webdav { "a WebDAV share" } else { "a network share" }),
                format!("{}: the binary was never written to this disk. {}", shown_dir, if webdav { "WebDAV paths are how a link in a phishing mail runs a remote executable." } else { "Running from a share is what PsExec-style tooling and admins alike do; the share and the account decide which." }),
            );
        }
    }

    // the shape of the name: not in the vendor folders, not a system binary, not in the
    // update and package folders (hashes and GUIDs are the names there), not a KB package
    let is_system = names::WINDOWS_SYSTEM_BINARIES.contains(&name.as_str()) || names::WINDOWS_SYSTEM_BINARIES_ELSEWHERE.iter().any(|(n, _)| *n == name);
    const GENERATED_HOMES: &[&str] = &["\\softwaredistribution\\", "\\installer\\", "\\package cache\\", "\\windowsapps\\", "\\assembly\\", "\\winsxs\\", "\\servicing\\", "\\temp\\", "\\$windows.~bt\\", "\\windows.old\\"];
    let kb_package = name.contains("kb") && name.split("kb").nth(1).map(|r| r.chars().take(5).all(|c| c.is_ascii_digit()) && r.len() >= 5).unwrap_or(false);
    if !in_vendor_folder && !is_system && !kb_package && !GENERATED_HOMES.iter().any(|h| dir.contains(h)) {
        // the shape is read from the name as the source spelled it: case matters
        let stem = names::stem_of(&name);
        let guid = stem.len() == 38 && stem.starts_with('{') && stem.ends_with('}') || stem.len() == 36 && stem.matches('-').count() == 4;
        let class = names::classify_name(&raw);
        let hit: Option<(&'static str, u8, String)> = if guid {
            Some(("guid", 60, "a GUID for a name outside the Installer and update folders: generated, not chosen".to_string()))
        } else if class == NameClass::HexLike {
            Some(("hex", 60, "a hexadecimal name outside the update and package folders: a hash or a generated token, not a program's name".to_string()))
        } else if names::looks_generated(&raw) {
            Some(("generated", 55, "letters in a shape no one chooses: random case changes or no vowel at all, the output of a name generator".to_string()))
        } else if class == NameClass::Tiny {
            Some(("tiny", 55, "a one or two character name is typed in a hurry, by hand".to_string()))
        } else if class == NameClass::DigitHeavy {
            Some(("digits", 50, "a name that is mostly digits was generated, not chosen".to_string()))
        } else if class == NameClass::Odd && !names::has_bidi_or_zero_width(&raw) {
            Some(("odd", 45, "non-ASCII or unusual characters in an executable's name; localized installers do it, so this is a pointer".to_string()))
        } else {
            None
        };
        if let Some((variant, score, why)) = hit {
            let shape = if guid { "GUID" } else if class == NameClass::Alpha { "random letters" } else { class.label() };
            push("NAM-RANDOM", variant, score, T_MASQ, format!("{} has a generated-looking name ({})", raw, shape), format!("{}.", why));
        }
    }
}

fn linux_rules(events: &[Event], tree: &ProcessTree, i: usize, out: &mut Vec<Finding>) {
    let e = &events[i];
    let raw = e.processname.trim().to_string();
    let is_process_record = matches!(e.artifact.split(':').take(3).collect::<Vec<_>>().join(":").as_str(), "linux:audit:execve" | "linux:process:pacct" | "linux:process:ps_lstart");
    if !raw.starts_with('/') && !is_process_record {
        return;
    }
    // a bare name is a whole name even with a slash in it (`kworker/u8:2`); in a path a
    // bracketed name is one component (`/tmp/[kworker/0:1]`)
    let (dir, name) = if !raw.starts_with('/') {
        (String::new(), raw.clone())
    } else if let Some(b) = raw.find('[') {
        (raw[..b].trim_end_matches('/').to_string(), raw[b..].to_string())
    } else {
        names::split_path(Os::Linux, &raw)
    };
    if name.is_empty() {
        return;
    }
    let fam = if dir.is_empty() { DirFamily::Bare } else { names::linux_family(&raw) };
    let mut push = |rule: &'static str, variant: &'static str, score: u8, mitre: &'static str, title: String, explanation: String| {
        out.push(mk(events, tree, i, rule, variant, score, mitre, title, explanation));
    };

    if names::has_bidi_or_zero_width(&name) {
        push(
            "NAM-RTLO",
            "",
            95,
            T_RTLO,
            format!("{} carries a right-to-left override or a zero-width character", name.escape_default()),
            "The name is displayed differently from how it is spelled. Nothing legitimate ships with one.".to_string(),
        );
    }
    if names::is_kernel_thread_name(&name) && (e.artifact.starts_with("linux:audit:execve") || raw.starts_with('/')) {
        push(
            "NAM-FAKE-KERNEL",
            "",
            95,
            T_MASQ_NAME_LOC,
            format!("{} is a userland process named like a kernel thread", name),
            format!("Kernel threads never execve and have no path; a process called {} that does either is a user program hiding in the process list.", name),
        );
    }
    if let Some((sys, how)) = names::lookalike_of(Os::Linux, &name) {
        let (variant, score, explanation) = if how == "homoglyph" {
            ("homoglyph", 90, format!("The name reads as {} but is spelled with look-alike characters.", sys))
        } else {
            ("edit", 75, format!("The name is one edit away from {}.", sys))
        };
        // one edit away counts outside the system tree only: `gpasswd` is a real neighbour of `passwd`
        if how == "homoglyph" || (!fam.is_linux_system() && fam != DirFamily::Bare) {
            push("NAM-LOOKALIKE", variant, score, T_MASQ_NAME_LOC, format!("{} imitates {} ({})", name, sys, how), explanation);
        }
    }
    if !dir.is_empty() && names::LINUX_SYSTEM_BINARIES.contains(&name.as_str()) && !fam.is_linux_system() {
        let (variant, score, why) = match fam {
            DirFamily::UsrLocal | DirFamily::Opt => ("local", 60, "a locally built copy of a system binary; an admin's build or a trojaned one, the hash and the build date tell which"),
            _ => ("", 90, "a system binary outside the system tree is a copy or an impostor; a rootkit's ps, a backdoored sshd, a bash with a preload"),
        };
        push("NAM-SYSTEM-PATH", variant, score, T_MASQ_NAME_LOC, format!("{} {} {}, not the system tree", name, verb(e), fam.label()), format!("{}: {}.", dir, why));
    }
    if !dir.is_empty() {
        let scratch: Option<(&'static str, u8, &'static str)> = match fam {
            DirFamily::DevShm => Some(("dev-shm", 85, "/dev/shm is memory: a binary run from it leaves no trace on disk after a reboot")),
            DirFamily::Var if raw.starts_with("/var/www/") => Some(("web-root", 85, "the web root holds pages, not programs; a binary there came through the web application")),
            DirFamily::Hidden => Some(("hidden", 75, "a hidden folder outside the system tree is where tooling is kept out of a directory listing")),
            DirFamily::Tmp | DirFamily::VarTmp => Some(("tmp", 70, "world-writable scratch space: where a download is run from before it is installed anywhere, if ever")),
            DirFamily::Run => Some(("run", 60, "/run is tmpfs for sockets and pid files, not for programs")),
            DirFamily::Var => Some(("var", 55, "a binary under /var, outside the web root, is unusual: spool, lib and log folders hold data")),
            DirFamily::RootHome => Some(("root-home", 50, "a program run from root's home was put there by hand")),
            DirFamily::Mnt => Some(("mnt", 45, "a program run from a mounted volume: removable media or a share")),
            DirFamily::Home => Some(("home", 40, "a program run from a home directory: what the user built or downloaded; a pointer when the rest of the row is odd")),
            _ => None,
        };
        if let Some((variant, score, why)) = scratch {
            push("PATH-SCRATCH", variant, score, T_MASQ, format!("{} {} {}", name, verb(e), fam.label()), format!("{}: {}.", dir, why));
        }
    }
    if !fam.is_linux_system() && !names::LINUX_SYSTEM_BINARIES.contains(&name.as_str()) {
        let class = names::classify_name(&name);
        let hit: Option<(&'static str, u8, String)> = if class == NameClass::HexLike {
            Some(("hex", 60, "a hexadecimal name: a hash or a generated token, not a program's name".to_string()))
        } else if names::looks_generated(&name) {
            Some(("generated", 55, "letters in a shape no one chooses: random case changes or no vowel at all".to_string()))
        } else if class == NameClass::Tiny && !dir.is_empty() {
            Some(("tiny", 50, "a one or two character name is typed in a hurry, by hand".to_string()))
        } else if class == NameClass::DigitHeavy {
            Some(("digits", 50, "a name that is mostly digits was generated, not chosen".to_string()))
        } else {
            None
        };
        if let Some((variant, score, why)) = hit {
            let shape = if class == NameClass::Alpha { "random letters" } else { class.label() };
            push("NAM-RANDOM", variant, score, T_MASQ, format!("{} has a generated-looking name ({})", name, shape), format!("{}.", why));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn mk(events: &[Event], tree: &ProcessTree, i: usize, rule: &'static str, variant: &'static str, score: u8, mitre: &'static str, title: String, explanation: String) -> Finding {
    let e = &events[i];
    Finding {
        row: i,
        timestamp: e.timestamp.clone(),
        computer: e.computer.clone(),
        rule_id: rule,
        variant,
        score,
        mitre,
        title,
        explanation,
        lineage: if tree::is_process_start(&e.artifact) { tree.lineage(events, i) } else { String::new() },
        pid: e.pid,
        processname: e.processname.clone(),
        commandline: e.commandline.clone().unwrap_or_default(),
        parentprocessname: e.parentprocessname.clone(),
        subject_username: e.subject_username.clone(),
        artifact: e.artifact.clone(),
        related: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(artifact: &str, name: &str) -> Event {
        Event {
            source_file: String::new(),
            timestamp: "2026-01-01T00:00:00.000000Z".to_string(),
            computer: "PC".to_string(),
            artifact: artifact.to_string(),
            event_id: 0,
            pid: 0,
            subject_username: String::new(),
            target_username: String::new(),
            processname: name.to_string(),
            commandline: None,
            parentprocessname: String::new(),
            meta: None,
        }
    }

    fn hits(events: &[Event]) -> Vec<(&'static str, u8)> {
        let tree = ProcessTree::build(events);
        run(events, &tree).into_iter().map(|f| (f.rule_id, f.score)).collect()
    }

    #[test]
    fn test_stock_windows_is_silent() {
        let events = vec![
            ev("evtx:4688", r"C:\Windows\System32\svchost.exe"),
            ev("evtx:4688", r"C:\Windows\explorer.exe"),
            ev("evtx:4688", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            ev("evtx:4688", r"C:\Program Files\Acme\agent.exe"),
            ev("evtx:4688", r"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),
            ev("evtx:4688", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2\MsMpEng.exe"),
            ev("evtx:4688", r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"),
            ev("evtx:4688", r"C:\Windows\WinSxS\amd64_microsoft-windows-cmd_10.0.19041\cmd.exe"),
            ev("evtx:4688", r"C:\Windows\SoftwareDistribution\Download\3a2f1c9d8e7b6a5f4c3d2e1f0a9b8c7d\install.exe"),
            ev("evtx:4688", "Registry"),
            ev("evtx:4688", "System"),
            ev("evtx:taskscheduler:106", r"\RF-WPAD-Beacon"),
            ev("evtx:7045", "OpenSSH SSH Server"),
            ev("evtx:applocker:8002", r"%SYSTEM32%\CONHOST.EXE"),
            ev("prefetch", r"\VOLUME{01d8a1b2c3d4e5f6-a1b2c3d4}\WINDOWS\SYSTEM32\CMD.EXE"),
            ev("defender:mplog:process", "WmiPrvSE.exe"),
            ev("evtx:4689", r"C:\Users\Public\ignored-on-exit.exe"),
        ];
        assert!(hits(&events).is_empty(), "{:?}", hits(&events));
    }

    #[test]
    fn test_system_name_outside_system32_and_windows_root() {
        let events = vec![
            ev("evtx:4688", r"C:\Users\bob\AppData\Roaming\Microsoft\svchost.exe"),
            ev("registry:amcache", r"C:\Windows\duKhLYUX.exe"),
            ev("evtx:4688", r"\Device\HarddiskVolume2\Windows\Temp\lsass.exe"),
            ev("ntfs:mft:created", r"C:\Windows\svchost.exe"),
        ];
        let h = hits(&events);
        assert!(h.contains(&("NAM-SYSTEM-PATH", 90)), "{:?}", h);
        assert!(h.contains(&("PATH-WINDOWS-ROOT", 70)), "{:?}", h);
        assert!(h.contains(&("NAM-RANDOM", 55)), "{:?}", h);
        assert!(h.contains(&("PATH-SCRATCH", 80)), "{:?}", h);
        assert_eq!(h.iter().filter(|(r, _)| *r == "NAM-SYSTEM-PATH").count(), 3);
        let tree = ProcessTree::build(&events);
        let f = run(&events, &tree);
        let written = f.iter().find(|f| f.artifact == "ntfs:mft:created").unwrap();
        assert!(written.title.contains("was written to"), "{}", written.title);
        assert!(f.iter().all(|f| f.lineage.is_empty() || f.artifact == "evtx:4688"));
    }

    #[test]
    fn test_name_tricks() {
        let events = vec![
            ev("evtx:4688", r"C:\Users\bob\Downloads\invoice.pdf.exe"),
            ev("evtx:4688", "C:\\Users\\bob\\Downloads\\photo\u{202e}gnp.scr"),
            ev("evtx:4688", r"C:\Users\bob\Downloads\report.docx                 .exe"),
            ev("evtx:4688", r"C:\Users\bob\readme.txt:payload.exe"),
            ev("evtx:4688", r"C:\Users\bob\AppData\Local\Temp\svch0st.exe"),
            ev("evtx:4688", r"C:\ProgramData\scvhost.exe"),
            ev("evtx:4688", r"C:\Windows\System32\svchosts.exe"),
            ev("evtx:4688", r"C:\Windows\Temp\53c012f3-3f47-421a-9dad-b4a9eac43557\MPSigStub.exe"),
            ev("evtx:4688", r"C:\Windows\Temp\CR_CEA63.tmp\setup.exe"),
            ev("evtx:applocker:8005", r"%OSDRIVE%\USERS\BOB\APPDATA\LOCAL\TEMP\__PSSCRIPTPOLICYTEST_A42J1PKE.ZAB.PS1"),
            ev("evtx:4688", r"C:\Windows\SoftwareDistribution\Download\Install\ndp40-kb3032662-x86.exe"),
            ev("registry:bam", r"C:\Users\Public\a.exe"),
            ev("registry:bam", r"C:\Users\Public\3f2a9c1b7e4d.exe"),
            ev("registry:bam", r"C:\Users\bob\AppData\Roaming\{9f1c2b3a-4d5e-4f60-8a7b-1c2d3e4f5a6b}.exe"),
            ev("evtx:4688", r"C:\Users\bob\AppData\Local\Temp\Rar$EXa0.123\setup.exe"),
            ev("evtx:4688", r"\\10.0.0.5\share\tool.exe"),
            ev("evtx:4688", r"\\evil.example@SSL\DavWWWRoot\payload.exe"),
            ev("evtx:4688", r"C:\$Recycle.Bin\S-1-5-21-1\x.exe"),
        ];
        let h = hits(&events);
        for want in [
            ("NAM-DOUBLE-EXT", 85),
            ("NAM-RTLO", 95),
            ("NAM-PADDED", 80),
            ("PATH-ADS", 90),
            ("NAM-LOOKALIKE", 90),
            ("NAM-LOOKALIKE", 75),
            ("NAM-RANDOM", 55),
            ("NAM-RANDOM", 60),
            ("PATH-ARCHIVE-TEMP", 65),
            ("PATH-REMOTE", 70),
            ("PATH-REMOTE", 80),
            ("PATH-SCRATCH", 85),
            ("PATH-SCRATCH", 70),
            ("PATH-SCRATCH", 40),
        ] {
            assert!(h.contains(&want), "missing {:?} in {:?}", want, h);
        }
        // one edit away inside System32, the Defender stub, Chrome's updater, the AppLocker
        // probe and a KB package: nothing
        assert_eq!(h.iter().filter(|(r, _)| *r == "NAM-LOOKALIKE").count(), 2, "{:?}", h);
        assert_eq!(h.iter().filter(|(r, s)| *r == "PATH-SCRATCH" && *s == 80).count(), 0, "{:?}", h);
        assert_eq!(h.iter().filter(|(r, s)| *r == "NAM-RANDOM" && *s == 50).count(), 0, "{:?}", h);
        assert_eq!(h.iter().filter(|(r, s)| *r == "PATH-SCRATCH" && *s == 40).count(), 2, "{:?}", h);
    }

    #[test]
    fn test_linux_rules() {
        let events = vec![
            ev("linux:audit:execve", "/usr/bin/sudo"),
            ev("linux:audit:execve", "/usr/sbin/sshd"),
            ev("linux:audit:user_cmd", "systemctl"),
            ev("linux:systemd:service", "/usr/bin/snap"),
            ev("linux:audit:execve", "/tmp/[kworker/0:1]"),
            ev("linux:audit:execve", "kworker/u8:2"),
            ev("linux:process:pacct", "kworker/u8:2"),
            ev("linux:audit:execve", "/tmp/sshd"),
            ev("linux:audit:execve", "/usr/local/sbin/sshd"),
            ev("linux:audit:execve", "/dev/shm/x"),
            ev("linux:audit:execve", "/var/www/html/uploads/shell"),
            ev("linux:audit:execve", "/home/bob/.cache/.x/miner"),
            ev("linux:cron:scheduled_job", "/var/tmp/deadbeef00"),
            ev("linux:audit:execve", "/usr/bin/systemd-journa1d"),
            ev("linux:audit:execve", "/home/bob/build/myapp"),
            ev("linux:journal:process", "/usr/bin/gpasswd"),
            ev("linux:audit:execve", "/tmp/rsyslog"),
        ];
        let h = hits(&events);
        assert!(!h.iter().any(|(r, s)| *r == "NAM-FAKE-KERNEL" && *s != 95));
        assert_eq!(h.iter().filter(|(r, _)| *r == "NAM-FAKE-KERNEL").count(), 2, "{:?}", h);
        assert!(h.contains(&("NAM-SYSTEM-PATH", 90)), "{:?}", h);
        assert!(h.contains(&("NAM-SYSTEM-PATH", 60)), "{:?}", h);
        assert!(h.contains(&("PATH-SCRATCH", 85)), "{:?}", h);
        assert!(h.contains(&("PATH-SCRATCH", 75)), "{:?}", h);
        assert!(h.contains(&("PATH-SCRATCH", 70)), "{:?}", h);
        assert!(h.contains(&("PATH-SCRATCH", 40)), "{:?}", h);
        assert!(h.contains(&("NAM-RANDOM", 60)), "{:?}", h);
        assert!(h.contains(&("NAM-LOOKALIKE", 90)), "{:?}", h);
        // gpasswd in /usr/bin is a real neighbour of passwd; rsyslog in /tmp is not one of rsyslogd
        assert_eq!(h.iter().filter(|(r, s)| *r == "NAM-LOOKALIKE" && *s == 75).count(), 1, "{:?}", h);
        // /var/www shell: scratch 85, and the hidden miner: 75; sudo, sshd, snap, systemctl: nothing
        let tree = ProcessTree::build(&events);
        let f = run(&events, &tree);
        assert!(!f.iter().any(|f| f.processname == "/usr/bin/sudo" || f.processname == "/usr/sbin/sshd" || f.processname == "systemctl" || f.processname == "/usr/bin/snap"), "{:?}", f.iter().map(|f| (&f.processname, f.rule_id)).collect::<Vec<_>>());
    }
}
