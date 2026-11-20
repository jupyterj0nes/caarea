//! Disk images recognised by their content: a cloud snapshot with no
//! extension (an Azure OS disk export starts with GRUB's boot code, `EB 63 90`),
//! a fixed VHD with no extension, a raw disk named `.vhd`, and the files that
//! must not be taken for an image (hives, later EWF segments, small files).

use caarea::ingest::image::{image_kind, image_kind_from_bytes, is_supported_image, unpack_disk_image, ImageKind, SNIFF_MIN_SIZE};
use std::io::Read;
use std::path::{Path, PathBuf};

fn fixture_bytes(name: &str) -> Vec<u8> {
    let gz = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/linux_disk").join(format!("{}.gz", name));
    let mut dec = flate2::read::GzDecoder::new(std::fs::File::open(&gz).expect("fixture"));
    let mut bytes = Vec::new();
    dec.read_to_end(&mut bytes).unwrap();
    bytes
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("caarea_sniff_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// A fixed VHD footer, as Azure and Hyper-V write it after the disk's bytes.
fn fixed_vhd_footer(size: u64) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[..8].copy_from_slice(b"conectix");
    f[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    f[40..48].copy_from_slice(&size.to_be_bytes());
    f[48..56].copy_from_slice(&size.to_be_bytes());
    f[60..64].copy_from_slice(&2u32.to_be_bytes());
    f
}

/// The hostname of the one Linux volume an image stages.
fn staged_host(dir: &Path, img: &Path) -> String {
    let staging = dir.join(format!("staging_{}", img.file_name().unwrap().to_string_lossy()));
    std::fs::create_dir_all(&staging).unwrap();
    let out = unpack_disk_image(img, &staging, true).expect("unpack");
    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(&out.live_dir).min_depth(1).max_depth(3).into_iter().flatten() {
        if entry.file_type().is_dir() && entry.path().join("etc").join("hostname").is_file() {
            found.push(entry.into_path());
        }
    }
    assert_eq!(found.len(), 1, "{:?}", found);
    std::fs::read_to_string(found[0].join("etc/hostname")).unwrap().trim().to_string()
}

fn head_with(at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 4096];
    h[at..at + bytes.len()].copy_from_slice(bytes);
    h
}

#[test]
fn container_formats_by_their_magic() {
    let tail = [0u8; 512];
    assert_eq!(image_kind_from_bytes(&head_with(0, b"EVF\x09\x0d\x0a\xff\x00"), &tail), Some(ImageKind::Ewf));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"EVF2\x0d\x0a\x81\x00"), &tail), Some(ImageKind::Ewf));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"vhdxfile"), &tail), Some(ImageKind::Vhd));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"conectix"), &tail), Some(ImageKind::Vhd));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"KDMV"), &tail), Some(ImageKind::Vmdk));
    let mut fixed_tail = [0u8; 512];
    fixed_tail[..8].copy_from_slice(b"conectix");
    assert_eq!(image_kind_from_bytes(&vec![0u8; 4096], &fixed_tail), Some(ImageKind::Vhd));
}

#[test]
fn raw_disks_and_volumes_by_what_they_start_with() {
    let tail = [0u8; 512];
    let mut grub = head_with(0, &[0xEB, 0x63, 0x90, 0x00]);
    grub[446] = 0x80;
    grub[450] = 0x83;
    grub[454..458].copy_from_slice(&2048u32.to_le_bytes());
    grub[458..462].copy_from_slice(&1_000_000u32.to_le_bytes());
    grub[510] = 0x55;
    grub[511] = 0xAA;
    assert_eq!(image_kind_from_bytes(&grub, &tail), Some(ImageKind::Raw), "GRUB MBR of an Azure Linux OS disk");
    let mut gpt = head_with(512, b"EFI PART");
    gpt[510] = 0x55;
    gpt[511] = 0xAA;
    assert_eq!(image_kind_from_bytes(&gpt, &tail), Some(ImageKind::Raw));
    assert_eq!(image_kind_from_bytes(&head_with(3, b"NTFS    "), &tail), Some(ImageKind::Raw));
    assert_eq!(image_kind_from_bytes(&head_with(1080, &[0x53, 0xEF]), &tail), Some(ImageKind::Raw));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"XFSB"), &tail), Some(ImageKind::Raw));
    assert_eq!(image_kind_from_bytes(&head_with(512, b"LABELONE"), &tail), Some(ImageKind::Raw));
}

#[test]
fn other_content_is_not_an_image() {
    let tail = [0u8; 512];
    assert_eq!(image_kind_from_bytes(&head_with(0, b"regf"), &tail), None);
    assert_eq!(image_kind_from_bytes(&head_with(0, b"ElfFile\0"), &tail), None);
    assert_eq!(image_kind_from_bytes(&head_with(0, b"MAM\x04"), &tail), None, "a compressed prefetch file");
    assert_eq!(image_kind_from_bytes(&vec![0u8; 4096], &tail), None);
    let mut empty_mbr = vec![0u8; 4096];
    empty_mbr[510] = 0x55;
    empty_mbr[511] = 0xAA;
    assert_eq!(image_kind_from_bytes(&empty_mbr, &tail), None);
}

#[test]
fn extensionless_snapshot_is_an_image_and_is_staged() {
    let d = scratch("snapshot");
    let img = write(&d, "snap-lab_os_disk-20261116", &fixture_bytes("gpt_xfs.img"));
    assert!(is_supported_image(&img));
    assert_eq!(image_kind(&img), ImageKind::Raw);
    assert_eq!(staged_host(&d, &img), "lab-xfs");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn extensionless_fixed_vhd_opens_as_vhd() {
    let d = scratch("fixed_vhd");
    let mut bytes = fixture_bytes("mbr_lvm_xfs.img");
    let size = bytes.len() as u64;
    bytes.extend_from_slice(&fixed_vhd_footer(size));
    let img = write(&d, "snap-lab_os_disk", &bytes);
    assert!(is_supported_image(&img));
    assert_eq!(image_kind(&img), ImageKind::Vhd);
    assert_eq!(staged_host(&d, &img), "lab-lvmxfs");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn raw_disk_named_vhd_opens_as_raw() {
    let d = scratch("raw_named_vhd");
    let img = write(&d, "exported.vhd", &fixture_bytes("gpt_xfs.img"));
    assert_eq!(image_kind(&img), ImageKind::Raw);
    assert_eq!(staged_host(&d, &img), "lab-xfs");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn hives_segments_and_small_files_are_not_sniffed_as_images() {
    let d = scratch("negatives");
    let mut hive = vec![0u8; 256 * 1024];
    hive[..4].copy_from_slice(b"regf");
    assert!(!is_supported_image(&write(&d, "SYSTEM", &hive)));
    let mut seg = vec![0u8; 256 * 1024];
    seg[..8].copy_from_slice(b"EVF\x09\x0d\x0a\xff\x00");
    assert!(!is_supported_image(&write(&d, "case.E02", &seg)), "a later EWF segment carries the same magic");
    assert!(is_supported_image(&write(&d, "case.E01", &seg)), "the first one is an image by its name");
    let small = fixture_bytes("gpt_xfs.img")[..(SNIFF_MIN_SIZE as usize - 1)].to_vec();
    assert!(!is_supported_image(&write(&d, "tiny", &small)));
    assert!(!is_supported_image(&d.join("missing")));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn cli_on_an_extensionless_snapshot_gives_rows() {
    let d = scratch("cli");
    let img = write(&d, "snap-lab_os_disk-20261116", &fixture_bytes("gpt_xfs.img"));
    let out = d.join("out.csv");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_caarea"))
        .args(["-f", &img.to_string_lossy(), "-o", &out.to_string_lossy()])
        .output()
        .expect("run caarea");
    let stdout = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(o.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&o.stderr));
    assert!(!stdout.contains("No parser recognised file"), "{stdout}");
    let csv = std::fs::read_to_string(&out).unwrap();
    assert!(csv.lines().count() > 1, "rows from the image: {csv}");
    assert!(csv.contains("lab-xfs"), "rows carry the image's hostname");
    let _ = std::fs::remove_dir_all(&d);
}
