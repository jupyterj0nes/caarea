use chrono::Local;
use flate2::read::GzDecoder;
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
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

/// Maximum nesting depth for archives inside archives (protects against zip quines / bombs)
const MAX_NESTING_DEPTH: usize = 5;

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

    // EVTX logs and Prefetch files
    if file_name.ends_with(".evtx") || file_name.ends_with(".pf") {
        return true;
    }

    // NTFS metadata copies as triage tools name them
    if file_name == "$mft"
        || file_name.ends_with("$mft")
        || file_name.ends_with("_mft")
        || file_name == "$j"
        || file_name == "$usnjrnl%3a$j"
        || file_name == "$usnjrnl_$j"
        || file_name == "$usnjrnl$j"
    {
        return true;
    }

    // Windows file artifacts: PowerShell history, WER reports, Defender logs, PCA logs,
    // scheduled task definitions (extension-less files under a Tasks folder)
    if file_name == "consolehost_history.txt"
        || file_name == "report.wer"
        || ((file_name.starts_with("mplog-") || file_name.starts_with("mpdetection-")) && file_name.ends_with(".log"))
        || file_name == "pcaapplaunchdic.txt"
        || file_name == "srudb.dat"
        || file_name.ends_with(".lnk")
        || file_name.ends_with(".automaticdestinations-ms")
        || file_name.ends_with(".customdestinations-ms")
        || file_name == "activitiescache.db"
        || file_name == "activitiescache.db-wal"
        || file_name == "recentfilecache.bcf"
        || file_name == "objects.data"
        || (file_name.starts_with("pcageneraldb") && file_name.ends_with(".txt"))
        || (lower.contains("/tasks/") && !file_name.contains('.'))
    {
        return true;
    }

    // Windows Registry hives and their transaction logs (.LOG, .LOG1, .LOG2)
    let standard_hives = ["system", "software", "sam", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve", "syscache.hve"];
    let hive_stem = file_name
        .trim_end_matches(".log1")
        .trim_end_matches(".log2")
        .trim_end_matches(".log");
    if standard_hives
        .iter()
        .any(|&h| hive_stem == h || hive_stem.ends_with(&format!("_{}", h)) || hive_stem.ends_with(&format!("-{}", h)))
    {
        return true;
    }
    if hive_stem.ends_with(".hve") {
        return true;
    }

    // Targeted Linux execution logs
    if file_name == "audit.log" || file_name.starts_with("audit.log.")
        || file_name == "cron" || file_name.starts_with("cron-") || file_name.starts_with("cron.log")
        || file_name == "secure" || file_name.starts_with("secure-") || file_name.starts_with("secure.")
        || file_name == "auth.log" || file_name.starts_with("auth.log.")
        || file_name == "syslog" || file_name.starts_with("syslog.")
        || file_name == "messages" || file_name.starts_with("messages-") || file_name.starts_with("messages.")
        || file_name == "kern.log" || file_name.starts_with("kern.log.")
        || file_name == "dpkg.log" || file_name.starts_with("dpkg.log.")
        || file_name == "yum.log" || file_name.starts_with("yum.log.")
        || file_name.ends_with("access_log") || file_name.ends_with("access.log") || file_name.contains("access.log.")
        || file_name == "dmesg.txt" || file_name == "dmesg" || file_name.starts_with("dmesg.")
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
    if lower.contains("cron.d/") || lower.contains("spool/cron/") || lower.contains("crontabs/") || lower.contains("systemd/system/")
        || lower.contains("init.d/") || file_name == "crontab" || file_name == "rc.local"
    {
        return true;
    }

    // Linux process accounting, GUI recently used, web access logs, and crash logs
    if file_name.contains("pacct") || file_name.contains("psacct") || lower.contains("/account/acct")
        || file_name == "recently-used.xbel"
        || file_name.contains("segfault") || file_name.contains("coredump")
    {
        return true;
    }

    // Host time zone evidence (etc/timezone, etc/localtime, UAC timedatectl / date output)
    if (lower.ends_with("/etc/timezone") || lower == "etc/timezone")
        || (lower.ends_with("/etc/localtime") || lower == "etc/localtime")
        || file_name == "timedatectl_status.txt" || file_name == "date.txt" || file_name == "hwclock.txt"
    {
        return true;
    }

    // Nested archives (excluding VMware drivers)
    if file_name.ends_with(".zip") || file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") || file_name.ends_with(".tar") {
        return true;
    }

    // Triage metadata markers (useful to preserve triage context)
    if file_name == "_kape.cli" || file_name == "client_info.json" || file_name == "manifest.json" || file_name == "uac.log" {
        return true;
    }

    false
}

/// Converts an archive entry name into a safe *relative* path that can only land inside the
/// extraction directory: root / drive prefixes are dropped, `..` components are rejected and
/// characters that are illegal on Windows (`: < > " | ? *`) are replaced by `_`.
pub fn safe_relative_path(entry_name: &str) -> Option<PathBuf> {
    let normalized = entry_name.replace('\\', "/");
    let mut out = PathBuf::new();
    for raw in normalized.split('/') {
        if raw.is_empty() || raw == "." {
            continue;
        }
        if raw == ".." {
            return None;
        }
        let cleaned: String = raw
            .chars()
            .map(|c| match c {
                ':' | '<' | '>' | '"' | '|' | '?' | '*' => '_',
                c if (c as u32) < 0x20 => '_',
                c => c,
            })
            .collect();
        let cleaned = cleaned.trim_end_matches([' ', '.']).to_string();
        if cleaned.is_empty() || cleaned == ".." {
            return None;
        }
        out.push(cleaned);
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    // Belt and braces: the result must be purely relative/normal components
    if out.components().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    Some(out)
}

/// Builds a unique extraction directory for an archive so that two archives with the same
/// file name (e.g. `data.zip` from several Velociraptor collections) never overwrite each other.
fn extraction_dir_for(archive_path: &Path, dest_base: &Path) -> PathBuf {
    let stem = archive_path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.trim_end_matches(".tar.gz").trim_end_matches(".tgz").trim_end_matches(".zip").trim_end_matches(".tar"))
        .filter(|s| !s.is_empty())
        .unwrap_or("extracted");
    let stem_clean: String = stem
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    let abs = fs::canonicalize(archive_path).unwrap_or_else(|_| archive_path.to_path_buf());
    let mut hasher = DefaultHasher::new();
    abs.to_string_lossy().hash(&mut hasher);
    dest_base.join(format!("{}__{:08x}", stem_clean, hasher.finish() as u32))
}

/// Reads the top-level entries of a ZIP without deep extraction
pub fn read_zip_top_entries(zip_path: &Path) -> Option<Vec<String>> {
    let file = File::open(zip_path).ok()?;
    let mut archive = ZipArchive::new(file).ok()?;
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index_raw(i) {
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
    unpack_archive_at_depth(archive_path, dest_base, silent, 0)
}

fn unpack_archive_at_depth(
    archive_path: &Path,
    dest_base: &Path,
    silent: bool,
    depth: usize,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    if depth > MAX_NESTING_DEPTH {
        log_message(
            silent,
            &format!("⚠️ Skipping {}: archive nesting deeper than {} levels", archive_path.display(), MAX_NESTING_DEPTH),
        );
        return Ok(vec![]);
    }

    let target_dir = extraction_dir_for(archive_path, dest_base);
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
    let nested_dirs = scan_and_unpack_nested(&target_dir, dest_base, silent, depth + 1)?;
    all_dirs.extend(nested_dirs);

    Ok(all_dirs)
}

/// Resolves the destination for an entry, or `None` when the entry must be skipped.
fn destination_for(entry_name: &str, target_dir: &Path, silent: bool) -> Option<PathBuf> {
    if !is_relevant_artifact(entry_name) {
        return None;
    }
    match safe_relative_path(entry_name) {
        Some(rel) => Some(target_dir.join(rel)),
        None => {
            log_message(silent, &format!("⚠️ Skipping unsafe archive entry name: {:?}", entry_name));
            None
        }
    }
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
        let out_path = match destination_for(&entry_name, target_dir, silent) {
            Some(p) => p,
            None => continue,
        };

        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(mut out_file) = File::create(&out_path) {
            let _ = io::copy(&mut entry, &mut out_file);
        }
    }

    Ok(())
}

/// Extracts the regular-file entries of a tar stream into `target_dir`, safely.
fn unpack_tar_entries<R: Read>(mut archive: TarArchive<R>, target_dir: &Path, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    for entry_res in archive.entries()? {
        let mut entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue,
        };

        let kind = entry.header().entry_type();
        let path = match entry.path() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        // Symlinks are never materialised, but the *target* of /etc/localtime tells us the host
        // time zone: keep it as a tiny text sidecar (`etc/localtime.symlink`).
        if kind.is_symlink() {
            let lower = path.replace('\\', "/").to_lowercase();
            if lower.ends_with("/etc/localtime") || lower == "etc/localtime" {
                if let (Ok(Some(target)), Some(out_path)) = (entry.link_name(), destination_for(&path, target_dir, silent)) {
                    let sidecar = out_path.with_file_name("localtime.symlink");
                    if let Some(parent) = sidecar.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::write(&sidecar, target.to_string_lossy().as_bytes());
                }
            }
            continue;
        }

        // Only regular files are evidence we can parse; devices / hardlinks are skipped too, so
        // no later entry can be redirected outside the staging directory.
        if !(kind.is_file() || kind.is_contiguous() || kind.is_gnu_sparse()) {
            continue;
        }

        let out_path = match destination_for(&path, target_dir, silent) {
            Some(p) => p,
            None => continue,
        };

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
fn unpack_tar_gz(tar_path: &Path, target_dir: &Path, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(tar_path)?;
    let gz = GzDecoder::new(file);
    unpack_tar_entries(TarArchive::new(gz), target_dir, silent)
}

/// Unpacks relevant files from an uncompressed tar archive
fn unpack_tar(tar_path: &Path, target_dir: &Path, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(tar_path)?;
    unpack_tar_entries(TarArchive::new(file), target_dir, silent)
}

/// Scans for nested archives inside an extracted directory and unpacks them
fn scan_and_unpack_nested(
    extracted_dir: &Path,
    dest_base: &Path,
    silent: bool,
    depth: usize,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
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
        if let Ok(dirs) = unpack_archive_at_depth(&nested, dest_base, silent, depth) {
            out_dirs.extend(dirs);
        }
    }

    Ok(out_dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_relative_path_blocks_traversal() {
        assert_eq!(safe_relative_path("C/Windows/System32/config/SYSTEM").unwrap(), PathBuf::from("C/Windows/System32/config/SYSTEM"));
        assert_eq!(safe_relative_path("/etc/cron.d/evil").unwrap(), PathBuf::from("etc/cron.d/evil"));
        assert_eq!(safe_relative_path("\\Windows\\System32\\evil.dll").unwrap(), PathBuf::from("Windows/System32/evil.dll"));
        assert_eq!(safe_relative_path("C:/Users/x/NTUSER.DAT").unwrap(), PathBuf::from("C_/Users/x/NTUSER.DAT"));
        assert_eq!(safe_relative_path("./a/./b").unwrap(), PathBuf::from("a/b"));
        assert!(safe_relative_path("../../evil").is_none());
        assert!(safe_relative_path("a/../../evil").is_none());
        assert!(safe_relative_path("....//....//evil.txt").is_none()); // dot-only components are rejected
        assert!(safe_relative_path("").is_none());
        assert!(safe_relative_path("/").is_none());
    }

    #[test]
    fn test_extraction_dirs_are_unique_per_source() {
        let base = Path::new("/staging");
        let a = extraction_dir_for(Path::new("/cases/hostA/data.zip"), base);
        let b = extraction_dir_for(Path::new("/cases/hostB/data.zip"), base);
        assert_ne!(a, b);
        assert!(a.file_name().unwrap().to_string_lossy().starts_with("data__"));
        let t = extraction_dir_for(Path::new("/cases/uac-host-linux-20260101.tar.gz"), base);
        assert!(t.file_name().unwrap().to_string_lossy().starts_with("uac-host-linux-20260101__"));
    }

    #[test]
    fn test_relevant_artifacts() {
        assert!(is_relevant_artifact("C/Windows/System32/config/SYSTEM"));
        assert!(is_relevant_artifact("C/Windows/System32/config/SYSTEM.LOG1"));
        assert!(is_relevant_artifact("C/Windows/System32/config/SOFTWARE.LOG"));
        assert!(is_relevant_artifact("C/Users/bob/NTUSER.DAT.LOG2"));
        assert!(is_relevant_artifact("[root]/var/log/syslog"));
        assert!(is_relevant_artifact("[root]/var/log/messages-20260101"));
        assert!(is_relevant_artifact("[root]/var/account/pacct"));
        assert!(is_relevant_artifact("[root]/var/spool/cron/crontabs/root"));
        assert!(is_relevant_artifact("[root]/etc/timezone"));
        assert!(is_relevant_artifact("[root]/etc/localtime"));
        assert!(is_relevant_artifact("live_response/system/timedatectl_status.txt"));
        assert!(!is_relevant_artifact("[root]/usr/share/doc/readme.txt"));
    }
}
