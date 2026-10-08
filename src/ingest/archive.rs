use chrono::Local;
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tar::Archive as TarArchive;
use zip::read::ZipArchive;

use crate::ingest::triage::{detect_triage_type, extract_triage_hostname, TriageInfo, TriageType};

/// Known forensic passwords used across DFIR investigations, CTFs, and triage tools
const FORENSIC_PASSWORDS: &[&[u8]] = &[
    b"",
    b"infected",
    b"cyberdefenders.org",
    b"malware",
    b"password",
    b"velox",
    b"Velociraptor",
];

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Checks if a file path is a supported compressed archive
pub fn is_supported_archive(path: &Path) -> bool {
    let filename = match path.file_name() {
        Some(n) => n.to_string_lossy().to_lowercase(),
        None => return false,
    };

    filename.ends_with(".zip")
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tgz")
        || filename.ends_with(".tar")
}

/// Checks if an archive entry is a relevant forensic artifact for execution timelining
pub fn is_relevant_artifact(entry_name: &str) -> bool {
    let lower = entry_name.replace('\\', "/").to_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);

    // Ignore VMware tools driver source modules and installer bundles
    if lower.contains("vmware-tools") || lower.contains("modules/source") {
        return false;
    }

    // EVTX logs
    if file_name.ends_with(".evtx") {
        return true;
    }

    // Windows Registry hives
    let standard_hives = ["system", "software", "sam", "security", "ntuser.dat", "usrclass.dat", "amcache.hve"];
    if standard_hives.iter().any(|&h| file_name == h || file_name.ends_with(&format!("_{}", h)) || file_name.ends_with(&format!("-{}", h))) {
        return true;
    }
    if file_name.ends_with(".hve") {
        return true;
    }

    // Registry transaction logs
    if file_name.ends_with(".log1") || file_name.ends_with(".log2") {
        return true;
    }

    // Targeted Linux execution logs
    if file_name == "audit.log" || file_name.starts_with("audit.log.")
        || file_name == "cron" || file_name.starts_with("cron-") || file_name.starts_with("cron.")
        || file_name == "secure" || file_name.starts_with("secure-") || file_name.starts_with("secure.")
        || file_name == "auth.log" || file_name.starts_with("auth.log.")
        || file_name == "dpkg.log" || file_name.starts_with("dpkg.log.")
        || file_name == "yum.log" || file_name.starts_with("yum.log.")
        || file_name.ends_with("access_log") || file_name.ends_with("access.log")
        || file_name == "dmesg.txt" || file_name == "dmesg"
    {
        return true;
    }

    // Linux shell & editor histories (.bash_history, .zsh_history, .viminfo, .nano_history, etc.)
    if file_name.contains("history") || file_name == ".viminfo" || file_name == "main.shada" || file_name.contains("lesshst") {
        return true;
    }

    // Linux process execution triage (ps lstart, /proc/<pid>/*)
    if file_name.starts_with("ps_") || file_name.starts_with("proc_")
        || file_name.contains("cmdline") || file_name.contains("status") || file_name.contains("environ")
        || file_name.contains("running_processes") || file_name == "hostname.txt" || file_name == "hostname"
    {
        return true;
    }

    // Linux package management
    if file_name.contains("installtime") {
        return true;
    }

    // Linux scheduled jobs & persistence (cron.d, spool/cron, systemd units)
    if lower.contains("cron.d/") || lower.contains("spool/cron/") || lower.contains("systemd/system/")
        || lower.contains("init.d/") || file_name == "crontab" || file_name == "rc.local"
    {
        return true;
    }

    // Linux process accounting, GUI recently used, web access logs, and crash logs
    if file_name.contains("pacct") || file_name.contains("psacct")
        || file_name == "recently-used.xbel"
        || file_name.contains("segfault") || file_name.contains("coredump")
    {
        return true;
    }

    // Nested archives (excluding VMware drivers)
    if file_name.ends_with(".zip") || file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") || file_name.ends_with(".tar") {
        return true;
    }

    // Triage metadata markers (useful to preserve triage context)
    if file_name == "_kape.cli" || file_name == "client_info.json" || file_name == "manifest.json" {
        return true;
    }

    false
}

/// Reads the top-level entries of a ZIP without deep extraction
pub fn read_zip_top_entries(zip_path: &Path) -> Option<Vec<String>> {
    let file = File::open(zip_path).ok()?;
    let mut archive = ZipArchive::new(file).ok()?;
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            names.push(entry.name().to_string());
        }
    }
    Some(names)
}

/// Inspects an archive to detect triage package type and hostname
pub fn inspect_triage_archive(path: &Path) -> Option<TriageInfo> {
    let path_str = path.to_string_lossy().to_string();
    let entries = read_zip_top_entries(path).unwrap_or_default();
    let kind = detect_triage_type(&path_str, &entries).unwrap_or(TriageType::Generic);
    let hostname = extract_triage_hostname(&path_str, kind);

    Some(TriageInfo {
        kind,
        source_path: path_str,
        hostname,
    })
}

/// Recursively unpacks relevant artifacts from an archive (ZIP, TAR, GZ) into a staging directory
pub fn unpack_archive_recursive(
    archive_path: &Path,
    dest_base: &Path,
    silent: bool,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("extracted");

    let target_dir = dest_base.join(stem);
    fs::create_dir_all(&target_dir)?;

    let path_str = archive_path.to_string_lossy().to_lowercase();

    if path_str.ends_with(".zip") {
        unpack_zip(archive_path, &target_dir, silent)?;
    } else if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
        unpack_tar_gz(archive_path, &target_dir, silent)?;
    } else if path_str.ends_with(".tar") {
        unpack_tar(archive_path, &target_dir, silent)?;
    }

    let mut all_dirs = vec![target_dir.clone()];

    // Check for nested archives inside the newly extracted directory and unpack them
    let nested_dirs = scan_and_unpack_nested(&target_dir, dest_base, silent)?;
    all_dirs.extend(nested_dirs);

    Ok(all_dirs)
}

/// Unpacks relevant files from a ZIP archive, attempting known forensic passwords if encrypted
fn unpack_zip(zip_path: &Path, target_dir: &Path, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;

    // Probe passwords on the first file entry
    let mut working_pwd: Option<&[u8]> = None;
    let entry_count = archive.len();

    let test_idx = (0..entry_count)
        .find(|&i| archive.by_index_raw(i).map(|e| !e.is_dir()).unwrap_or(false))
        .unwrap_or(0);

    for &pwd in FORENSIC_PASSWORDS {
        let f = match File::open(zip_path) {
            Ok(file) => file,
            Err(_) => break,
        };
        let mut probe_archive = match ZipArchive::new(f) {
            Ok(a) => a,
            Err(_) => break,
        };

        let success = if pwd.is_empty() {
            if let Ok(mut e) = probe_archive.by_index(test_idx) {
                let mut buf = [0u8; 4];
                e.read(&mut buf).is_ok()
            } else {
                false
            }
        } else if let Ok(Ok(mut e)) = probe_archive.by_index_decrypt(test_idx, pwd) {
            let mut buf = [0u8; 4];
            e.read(&mut buf).is_ok()
        } else {
            false
        };

        if success {
            working_pwd = Some(pwd);
            if !pwd.is_empty() {
                log_message(
                    silent,
                    &format!(
                        "🔓 Archive is password-protected. Unlocked with known forensic password for: {}",
                        zip_path.display()
                    ),
                );
            }
            break;
        }
    }

    for i in 0..entry_count {
        let mut entry = match working_pwd {
            Some(pwd) if !pwd.is_empty() => match archive.by_index_decrypt(i, pwd) {
                Ok(Ok(e)) => e,
                _ => continue,
            },
            _ => match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            },
        };

        if entry.is_dir() {
            continue;
        }

        let entry_name = entry.name().to_string();
        if !is_relevant_artifact(&entry_name) {
            continue;
        }

        // Sanitize destination path against directory traversal
        let clean_relative = entry_name.replace("..", "").replace(':', "_");
        let out_path = target_dir.join(clean_relative);

        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(mut out_file) = File::create(&out_path) {
            let _ = io::copy(&mut entry, &mut out_file);
        }
    }

    Ok(())
}

/// Unpacks relevant files from a tar.gz / tgz archive
fn unpack_tar_gz(tar_path: &Path, target_dir: &Path, _silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(tar_path)?;
    let gz = GzDecoder::new(file);
    let mut archive = TarArchive::new(gz);

    for entry_res in archive.entries()? {
        let mut entry = entry_res?;
        let path = entry.path()?.to_string_lossy().to_string();

        if !is_relevant_artifact(&path) {
            continue;
        }

        let clean_relative = path.replace("..", "").replace(':', "_");
        let out_path = target_dir.join(clean_relative);

        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        entry.unpack(&out_path)?;
    }

    Ok(())
}

/// Unpacks relevant files from an uncompressed tar archive
fn unpack_tar(tar_path: &Path, target_dir: &Path, _silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(tar_path)?;
    let mut archive = TarArchive::new(file);

    for entry_res in archive.entries()? {
        let mut entry = entry_res?;
        let path = entry.path()?.to_string_lossy().to_string();

        if !is_relevant_artifact(&path) {
            continue;
        }

        let clean_relative = path.replace("..", "").replace(':', "_");
        let out_path = target_dir.join(clean_relative);

        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        entry.unpack(&out_path)?;
    }

    Ok(())
}

/// Scans for nested archives inside an extracted directory and unpacks them
fn scan_and_unpack_nested(extracted_dir: &Path, dest_base: &Path, silent: bool) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut nested_archives = Vec::new();

    for entry in walkdir::WalkDir::new(extracted_dir).into_iter().flatten() {
        let path = entry.path();
        if path.is_file() && is_supported_archive(path) {
            nested_archives.push(path.to_path_buf());
        }
    }

    let mut out_dirs = Vec::new();
    for nested in nested_archives {
        log_message(silent, &format!("📦 Unpacking nested archive: {}", nested.display()));
        if let Ok(dirs) = unpack_archive_recursive(&nested, dest_base, silent) {
            out_dirs.extend(dirs);
        }
    }

    Ok(out_dirs)
}
