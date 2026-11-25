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

/// A raw disk as a QCOW2 (version 3, 64 KiB clusters, clusters of zeros left out), under
/// another name: what `qemu-img convert -O qcow2` writes, in its plainest form.
fn as_qcow2(raw_path: &Path, name: &str) -> PathBuf {
    let raw = std::fs::read(raw_path).unwrap();
    let cs = 65536usize;
    let clusters = raw.len().div_ceil(cs);
    let tables = clusters.div_ceil(cs / 8);
    let mut img = vec![0u8; cs * (2 + tables)];
    img[..4].copy_from_slice(b"QFI\xfb");
    img[4..8].copy_from_slice(&3u32.to_be_bytes());
    img[20..24].copy_from_slice(&16u32.to_be_bytes());
    img[24..32].copy_from_slice(&(raw.len() as u64).to_be_bytes());
    img[36..40].copy_from_slice(&(tables as u32).to_be_bytes());
    img[40..48].copy_from_slice(&(cs as u64).to_be_bytes());
    img[96..100].copy_from_slice(&4u32.to_be_bytes());
    img[100..104].copy_from_slice(&104u32.to_be_bytes());
    for t in 0..tables {
        img[cs + t * 8..cs + t * 8 + 8].copy_from_slice(&((cs * (2 + t)) as u64).to_be_bytes());
    }
    for (i, chunk) in raw.chunks(cs).enumerate() {
        if chunk.iter().all(|&b| b == 0) {
            continue;
        }
        let at = img.len();
        img.extend_from_slice(chunk);
        img.resize(at + cs, 0);
        let entry = cs * 2 + i * 8;
        img[entry..entry + 8].copy_from_slice(&(at as u64).to_be_bytes());
    }
    let out = raw_path.with_file_name(name);
    std::fs::write(&out, img).unwrap();
    std::fs::remove_file(raw_path).unwrap();
    out
}

fn check(name: &str, tag: &str) {
    check_as(name, tag, None)
}

fn check_as(name: &str, tag: &str, qcow2_name: Option<&str>) {
    let d = scratch(&format!("{}{}", tag, qcow2_name.map(|_| "_q").unwrap_or("")));
    let img = gunzip_fixture(name, &d);
    let img = match qcow2_name {
        Some(n) => as_qcow2(&img, n),
        None => img,
    };
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

#[test]
fn gpt_xfs_partition_inside_a_qcow2() {
    check_as("gpt_xfs.img", "xfs", Some("vm-100-disk-0.qcow2"));
}

/// A QCOW2 with a name that says nothing, as a cloud image has: known by its content.
#[test]
fn lvm_xfs_inside_a_qcow2_with_no_extension() {
    check_as("mbr_lvm_xfs.img", "lvmxfs", Some("b3f1c2d4-image"));
}
