//! Safety properties of the archive ingestion: no path traversal, no cross-host collisions.

use caarea::ingest::archive::unpack_archive_recursive;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::ZipWriter;

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("caarea_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn make_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).unwrap();
    let mut zip = ZipWriter::new(file);
    for (name, data) in entries {
        zip.start_file(*name, FileOptions::default()).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

fn list_files(root: &Path) -> Vec<String> {
    WalkDir::new(root)
        .into_iter()
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"))
        .collect()
}

#[test]
fn malicious_entry_names_stay_inside_the_staging_directory() {
    let work = temp_dir("zipslip");
    let staging = work.join("staging");
    fs::create_dir_all(&staging).unwrap();
    let canary = work.join("canary.txt");
    fs::write(&canary, b"original").unwrap();

    let archive = work.join("evil.zip");
    make_zip(
        &archive,
        &[
            ("../canary.txt", b"OVERWRITTEN"),
            ("../../etc/cron.d/evil", b"* * * * * root /tmp/x"),
            ("/etc/cron.d/absolute", b"* * * * * root /tmp/y"),
            ("C:/Windows/System32/config/SYSTEM", b"regf-not-really"),
            ("C/Users/bob/NTUSER.DAT", b"regf-not-really"),
            ("[root]/var/log/auth.log", b"Sep 20 03:10:01 h CRON[1]: (root) CMD (ls)"),
        ],
    );

    let dirs = unpack_archive_recursive(&archive, &staging, true).expect("extraction must not fail");
    assert!(!dirs.is_empty());

    // The canary outside the staging dir is untouched
    assert_eq!(fs::read(&canary).unwrap(), b"original");
    assert!(!work.join("etc").exists());

    // Everything extracted lives under the staging directory, with sanitised names
    let files = list_files(&staging);
    assert!(files.iter().any(|f| f.ends_with("etc/cron.d/absolute")), "{:?}", files);
    assert!(files.iter().any(|f| f.ends_with("C_/Windows/System32/config/SYSTEM")), "{:?}", files);
    assert!(files.iter().any(|f| f.ends_with("C/Users/bob/NTUSER.DAT")), "{:?}", files);
    assert!(files.iter().any(|f| f.ends_with("[root]/var/log/auth.log")), "{:?}", files);
    assert!(!files.iter().any(|f| f.contains("canary")), "{:?}", files);
    for f in &files {
        assert!(staging.join(f).starts_with(&staging));
    }

    let _ = fs::remove_dir_all(&work);
}

#[test]
fn archives_with_the_same_name_do_not_overwrite_each_other() {
    let work = temp_dir("collision");
    let staging = work.join("staging");
    fs::create_dir_all(&staging).unwrap();

    let host_a = work.join("hostA");
    let host_b = work.join("hostB");
    fs::create_dir_all(&host_a).unwrap();
    fs::create_dir_all(&host_b).unwrap();

    // Two Velociraptor-style collections, both with a nested data.zip
    let inner_a = work.join("inner_a.zip");
    make_zip(&inner_a, &[("uploads/auto/C/Windows/System32/winevt/Logs/Security.evtx", b"AAAA")]);
    let inner_b = work.join("inner_b.zip");
    make_zip(&inner_b, &[("uploads/auto/C/Windows/System32/winevt/Logs/Security.evtx", b"BBBB")]);

    make_zip(&host_a.join("Collection.zip"), &[("data.zip", &fs::read(&inner_a).unwrap())]);
    make_zip(&host_b.join("Collection.zip"), &[("data.zip", &fs::read(&inner_b).unwrap())]);

    let dirs_a = unpack_archive_recursive(&host_a.join("Collection.zip"), &staging, true).unwrap();
    let dirs_b = unpack_archive_recursive(&host_b.join("Collection.zip"), &staging, true).unwrap();
    assert_ne!(dirs_a[0], dirs_b[0], "top-level extraction dirs must differ");

    let security_files: Vec<PathBuf> = WalkDir::new(&staging)
        .into_iter()
        .flatten()
        .filter(|e| e.path().is_file() && e.file_name() == "Security.evtx")
        .map(|e| e.path().to_path_buf())
        .collect();
    assert_eq!(security_files.len(), 2, "both nested data.zip must be extracted: {:?}", security_files);
    let mut contents: Vec<Vec<u8>> = security_files.iter().map(|p| fs::read(p).unwrap()).collect();
    contents.sort();
    assert_eq!(contents, vec![b"AAAA".to_vec(), b"BBBB".to_vec()]);

    let _ = fs::remove_dir_all(&work);
}
