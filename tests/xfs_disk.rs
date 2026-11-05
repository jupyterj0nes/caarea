//! XFS volumes inside disk images: faramir's lab images (`scripts/linux_disk_lab.sh` there), a
//! GPT partition and an LVM logical volume, both v5 with checksums, each with the hostname
//! `lab-<tag>`, a crontab, a cron.d job, a user crontab and a systemd unit.

use std::io::Read;
use std::path::{Path, PathBuf};

fn gunzip_fixture(name: &str, into: &Path) -> PathBuf {
    let gz = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/linux_disk").join(format!("{}.gz", name));
    let mut dec = flate2::read::GzDecoder::new(std::fs::File::open(&gz).expect("fixture"));
    let mut bytes = Vec::new();
    dec.read_to_end(&mut bytes).unwrap();
    let out = into.join(name);
    std::fs::write(&out, bytes).unwrap();
    out
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("caarea_xfs_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn staged_volume(live_dir: &Path) -> PathBuf {
    // one Linux volume per image: linux_partition_0 for a partition, lvm_0/lv_<name> for LVM
    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(live_dir).min_depth(1).max_depth(3).into_iter().flatten() {
        if entry.file_type().is_dir() && entry.path().join("etc").join("hostname").is_file() {
            found.push(entry.into_path());
        }
    }
    assert_eq!(found.len(), 1, "{:?}", found);
    found.remove(0)
}

fn check(name: &str, tag: &str) {
    let d = scratch(tag);
    let img = gunzip_fixture(name, &d);
    let staging = d.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    let out = caarea::ingest::image::unpack_disk_image(&img, &staging, true).expect("unpack");
    let vol = staged_volume(&out.live_dir);
    let host = std::fs::read_to_string(vol.join("etc/hostname")).unwrap().trim().to_string();
    assert_eq!(host, format!("lab-{}", tag));
    assert!(vol.join("etc/crontab").is_file(), "etc/crontab staged");
    assert!(vol.join("var/spool/cron/crontabs/bob").is_file(), "user crontab staged");
    assert!(vol.join("etc/systemd/system/multi-user.target.wants/lab.service").is_file(), "symlinked unit resolved to its target");
    assert!(!vol.join("etc/cron.d/gone").exists(), "a deleted file does not come back from XFS");
    let events = caarea::parsers::linux::process_linux_target(&vol, true).expect("linux parsers");
    assert!(!events.is_empty());
    assert!(events.iter().all(|e| e.computer == host), "every row carries the volume's hostname");
    assert!(events.iter().any(|e| e.artifact.starts_with("linux:cron") && e.commandline.as_deref().unwrap_or("").contains("/opt/lab/")), "the lab's cron canary is in the timeline");
    assert!(events.iter().any(|e| e.artifact.starts_with("linux:systemd")), "the lab's unit is in the timeline");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn gpt_xfs_partition_is_staged_and_parsed() {
    check("gpt_xfs.img", "xfs");
}

#[test]
fn lvm_xfs_logical_volume_is_staged_and_parsed() {
    check("mbr_lvm_xfs.img", "lvmxfs");
}
