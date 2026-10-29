//! Linux file systems inside disk images: ext2/3/4 partitions (MBR, GPT or a bare
//! partition image) and ext4 logical volumes inside LVM2 physical volumes. The files the
//! Linux parsers know are copied out with their original paths (`etc/hostname`,
//! `var/log/auth.log`, `home/<user>/.bash_history`, ...), so the extracted tree is handled
//! exactly like a UAC collection, time-zone detection included.
//!
//! Partition discovery and the reader bridge are the ones masstin uses; the file list is
//! caarea's.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ext4_view::{Ext4, Ext4Read, FileType};

const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const GPT_LINUX_FS_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];
const GPT_LINUX_LVM_GUID: [u8; 16] = [
    0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44, 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28,
];
/// Files larger than this are not copied (journals and logs stay well below).
const MAX_FILE_BYTES: u64 = 1 << 30;
/// Directory walk depth under the roots listed below.
const MAX_DEPTH: usize = 6;

/// Does an ext2/3/4 superblock sit at `offset`?
pub fn verify_ext4_superblock<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset + 1024 + 56)).is_err() {
        return false;
    }
    let mut magic = [0u8; 2];
    reader.read_exact(&mut magic).is_ok() && u16::from_le_bytes(magic) == EXT4_SUPER_MAGIC
}

/// Byte offsets of ext partitions (`ext4`) and of LVM physical volumes (`lvm`).
pub struct LinuxPartitions {
    pub ext4: Vec<u64>,
    pub lvm: Vec<u64>,
}

pub fn find_linux_partitions<R: Read + Seek>(reader: &mut R) -> LinuxPartitions {
    let mut out = LinuxPartitions { ext4: Vec::new(), lvm: Vec::new() };
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return out;
    }
    let mut mbr = [0u8; 512];
    if reader.read_exact(&mut mbr).is_ok() && mbr[510] == 0x55 && mbr[511] == 0xAA {
        if mbr[446 + 4] == 0xEE {
            // GPT
            let mut hdr = [0u8; 92];
            if reader.seek(SeekFrom::Start(512)).is_ok() && reader.read_exact(&mut hdr).is_ok() && &hdr[0..8] == b"EFI PART" {
                let entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
                let count = u32::from_le_bytes(hdr[80..84].try_into().unwrap()).min(128);
                let size = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
                if (128..=4096).contains(&size) {
                    for i in 0..count as u64 {
                        let mut entry = vec![0u8; size];
                        if reader.seek(SeekFrom::Start(entry_lba * 512 + i * size as u64)).is_err() || reader.read_exact(&mut entry).is_err() {
                            continue;
                        }
                        let guid: [u8; 16] = entry[0..16].try_into().unwrap();
                        if guid == [0u8; 16] {
                            continue;
                        }
                        let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
                        let offset = first_lba * 512;
                        if guid == GPT_LINUX_LVM_GUID {
                            out.lvm.push(offset);
                        } else if verify_ext4_superblock(reader, offset) {
                            out.ext4.push(offset);
                        } else if guid == GPT_LINUX_FS_GUID {
                            // Linux data partition that is not ext: could still be an LVM PV
                            out.lvm.push(offset);
                        }
                    }
                }
            }
        } else {
            for i in 0..4 {
                let e = 446 + i * 16;
                let ptype = mbr[e + 4];
                let lba = u32::from_le_bytes([mbr[e + 8], mbr[e + 9], mbr[e + 10], mbr[e + 11]]) as u64;
                if lba == 0 {
                    continue;
                }
                let offset = lba * 512;
                match ptype {
                    0x8E => out.lvm.push(offset),
                    0x83 | 0x93 | 0xFD => {
                        if verify_ext4_superblock(reader, offset) {
                            out.ext4.push(offset);
                        } else {
                            out.lvm.push(offset);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if out.ext4.is_empty() && out.lvm.is_empty() && verify_ext4_superblock(reader, 0) {
        out.ext4.push(0);
    }
    out
}

/// Reader bridge: ext4-view owns a `Box<dyn Ext4Read>`, our reader is borrowed. The `Ext4`
/// instance never outlives the borrow (it is dropped inside `extract_partition`), and
/// nothing else touches the reader meanwhile.
struct BorrowedReader<R: Read + Seek> {
    reader: *mut R,
    offset: u64,
}

unsafe impl<R: Read + Seek> Send for BorrowedReader<R> {}
unsafe impl<R: Read + Seek> Sync for BorrowedReader<R> {}

impl<R: Read + Seek> Ext4Read for BorrowedReader<R> {
    fn read(&mut self, start_byte: u64, dst: &mut [u8]) -> Result<(), Box<dyn core::error::Error + Send + Sync + 'static>> {
        let reader = unsafe { &mut *self.reader };
        reader.seek(SeekFrom::Start(self.offset + start_byte))?;
        reader.read_exact(dst)?;
        Ok(())
    }
}

/// Exact paths copied when present.
const EXACT_FILES: &[&str] = &[
    "/etc/hostname",
    "/etc/timezone",
    "/etc/localtime",
    "/etc/os-release",
    "/etc/passwd",
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/ld.so.preload",
    "/var/run/utmp",
    "/run/utmp",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/dpkg.log",
    "/var/log/yum.log",
    "/var/log/dnf.log",
    "/var/log/dnf.rpm.log",
    "/var/log/pacman.log",
    "/var/log/zypp/history",
    "/var/log/cloud-init.log",
    "/var/log/cloud-init-output.log",
    "/var/log/apt/history.log",
    "/var/log/apt/term.log",
    "/var/log/sudo.log",
];

/// Directories walked (depth-limited) with a name filter.
const WALK_DIRS: &[&str] = &[
    "/var/log",
    "/var/account",
    "/var/log/account",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/at",
    "/etc/systemd/system",
    "/var/lib/systemd/timers",
    "/var/mail",
    "/var/spool/mail",
    "/var/lib/docker/containers",
    "/var/lib/containerd/io.containerd.runtime.v2.task",
    "/var/log/pods",
    "/home",
    "/root",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/var/www",
];

/// Should a file under one of `WALK_DIRS` be copied? Decided on the volume-relative path.
fn wanted(path: &str, name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let p = path.to_ascii_lowercase();
    // histories and editor state in any home
    if n.ends_with("_history") || n == ".history" || n == ".viminfo" || n == ".lesshst" || n == "fish_history" || n == "recently-used.xbel" {
        return true;
    }
    if p.starts_with("/var/log/") {
        // rotated and compressed variants included; journals; audit; web logs
        let stem = n.split('.').next().unwrap_or("");
        return matches!(
            stem,
            "auth" | "secure" | "syslog" | "messages" | "cron" | "kern" | "dpkg" | "yum" | "dnf" | "pacman" | "audit" | "history" | "term"
                | "wtmp" | "btmp" | "lastlog" | "sudo" | "pacct" | "acct" | "dmesg" | "boot" | "cloud-init" | "cloud-init-output"
        ) || n.ends_with(".journal")
            || n.ends_with(".journal~")
            || n.contains("access.log")
            || n.contains("access_log")
            || p.contains("/var/log/pods/");
    }
    if p.starts_with("/var/account") || p.starts_with("/var/log/account") {
        return n.starts_with("pacct") || n.starts_with("acct");
    }
    if p.starts_with("/etc/cron") || p.starts_with("/var/spool/cron") || p.starts_with("/var/spool/at") {
        return true;
    }
    if p.starts_with("/etc/systemd/system") {
        return n.ends_with(".service") || n.ends_with(".timer");
    }
    if p.starts_with("/var/lib/systemd/timers") {
        return n.starts_with("stamp-");
    }
    if p.starts_with("/var/mail") || p.starts_with("/var/spool/mail") {
        return true;
    }
    if p.starts_with("/var/lib/docker/containers") {
        return n == "config.v2.json" || n == "hostconfig.json" || n.ends_with("-json.log");
    }
    if p.starts_with("/var/lib/containerd") {
        return n == "config.json";
    }
    if p.starts_with("/var/www") {
        return n.contains("access") && n.contains("log");
    }
    // /tmp, /var/tmp, /dev/shm: scripts and binaries dropped there (small files only)
    if p.starts_with("/tmp") || p.starts_with("/var/tmp") || p.starts_with("/dev/shm") {
        return n.ends_with(".sh") || n.ends_with(".py") || n.ends_with(".pl") || n.ends_with(".elf") || !n.contains('.');
    }
    false
}

fn dest_for(output_dir: &Path, linux_path: &str) -> PathBuf {
    output_dir.join(linux_path.trim_start_matches('/'))
}

fn write_file(dest: &Path, data: &[u8]) -> bool {
    if let Some(parent) = dest.parent() {
        let _ = fs::create_dir_all(parent);
    }
    File::create(dest).and_then(|mut f| f.write_all(data)).is_ok()
}

fn copy_path(fs: &Ext4, linux_path: &str, output_dir: &Path, max_bytes: u64) -> bool {
    match fs.metadata(linux_path) {
        Ok(meta) if meta.file_type() == FileType::Regular && meta.len() <= max_bytes => match fs.read(linux_path) {
            Ok(data) => write_file(&dest_for(output_dir, linux_path), &data),
            Err(_) => false,
        },
        _ => false,
    }
}

fn walk(fs: &Ext4, dir: &str, output_dir: &Path, depth: usize, count: &mut usize) {
    let Ok(entries) = fs.read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().as_str().map(|s| s.to_string()) else { continue };
        if name == "." || name == ".." {
            continue;
        }
        let path = if dir == "/" { format!("/{}", name) } else { format!("{}/{}", dir, name) };
        match entry.file_type() {
            Ok(FileType::Directory) if depth < MAX_DEPTH => {
                walk(fs, &path, output_dir, depth + 1, count);
            }
            Ok(FileType::Regular) if wanted(&path, &name) => {
                let limit = if path.starts_with("/tmp") || path.starts_with("/var/tmp") || path.starts_with("/dev/shm") {
                    4 << 20
                } else {
                    MAX_FILE_BYTES
                };
                if copy_path(fs, &path, output_dir, limit) {
                    *count += 1;
                }
            }
            _ => {}
        }
    }
}

/// Copies the Linux artifacts of the ext file system at `offset` into `output_dir`.
pub fn extract_partition<R: Read + Seek + 'static>(reader: &mut R, offset: u64, output_dir: &Path) -> Result<usize, String> {
    let fs = {
        let bridge = BorrowedReader { reader: reader as *mut R, offset };
        Ext4::load(Box::new(bridge)).map_err(|e| format!("cannot load ext file system at {:#x}: {}", offset, e))?
    };
    let _ = fs::create_dir_all(output_dir);
    let mut count = 0usize;
    for path in EXACT_FILES {
        if copy_path(&fs, path, output_dir, MAX_FILE_BYTES) {
            count += 1;
        }
    }
    // /etc/localtime is usually a symlink to the zoneinfo file: keep its target as a sidecar
    if let Ok(target) = fs.read_link("/etc/localtime") {
        let t = target.display().to_string();
        if write_file(&dest_for(output_dir, "/etc/localtime.symlink"), t.as_bytes()) {
            count += 1;
        }
    }
    for dir in WALK_DIRS {
        walk(&fs, dir, output_dir, 0, &mut count);
    }
    drop(fs);
    Ok(count)
}

/// ext4 logical volumes inside an LVM2 physical volume at `offset`: each one is dumped to a
/// temporary raw file and extracted like a partition. Returns `(volumes found, files)`.
pub fn extract_lvm<R: Read + Seek>(reader: &mut R, offset: u64, output_dir: &Path, staging: &Path) -> (usize, usize) {
    struct Off<'a, R: Read + Seek> {
        inner: &'a mut R,
        base: u64,
        pos: u64,
    }
    impl<R: Read + Seek> Read for Off<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.seek(SeekFrom::Start(self.base + self.pos))?;
            let n = self.inner.read(buf)?;
            self.pos += n as u64;
            Ok(n)
        }
    }
    impl<R: Read + Seek> Seek for Off<'_, R> {
        fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
            self.pos = match p {
                SeekFrom::Start(s) => s,
                SeekFrom::Current(d) => (self.pos as i64 + d).max(0) as u64,
                SeekFrom::End(_) => return Err(std::io::Error::other("unknown end")),
            };
            Ok(self.pos)
        }
    }
    let mut pv = Off { inner: reader, base: offset, pos: 0 };
    let Ok(lvm) = lvm2::Lvm2::open(&mut pv) else { return (0, 0) };
    let names: Vec<String> = lvm.lvs().map(|lv| lv.name().to_string()).collect();
    let mut files = 0usize;
    let mut volumes = 0usize;
    for name in &names {
        let Some(lv) = lvm.lvs().find(|l| l.name() == name.as_str()) else { continue };
        let mut olv = lvm.open_lv(lv, &mut pv);
        let mut magic = [0u8; 2];
        if olv.seek(SeekFrom::Start(0x438)).is_err() || olv.read_exact(&mut magic).is_err() || u16::from_le_bytes(magic) != EXT4_SUPER_MAGIC {
            continue;
        }
        volumes += 1;
        let tmp = staging.join(format!("lvm_{:x}_{}.raw", offset, name.replace(['/', '\\'], "_")));
        let dumped = (|| -> std::io::Result<()> {
            olv.seek(SeekFrom::Start(0))?;
            let mut out = File::create(&tmp)?;
            let mut buf = vec![0u8; 1 << 20];
            loop {
                match olv.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => out.write_all(&buf[..n])?,
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })();
        if dumped.is_ok() {
            if let Ok(mut f) = File::open(&tmp) {
                if let Ok(n) = extract_partition(&mut f, 0, &output_dir.join(format!("lv_{}", name.replace(['/', '\\'], "_")))) {
                    files += n;
                }
            }
        }
        let _ = fs::remove_file(&tmp);
    }
    (volumes, files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wanted_paths() {
        assert!(wanted("/var/log/auth.log.2.gz", "auth.log.2.gz"));
        assert!(wanted("/var/log/journal/abc/system.journal", "system.journal"));
        assert!(wanted("/home/bob/.bash_history", ".bash_history"));
        assert!(wanted("/var/lib/docker/containers/x/config.v2.json", "config.v2.json"));
        assert!(wanted("/etc/systemd/system/x.timer", "x.timer"));
        assert!(!wanted("/etc/systemd/system/x.conf", "x.conf"));
        assert!(!wanted("/var/log/Xorg.0.log", "Xorg.0.log"));
        assert!(wanted("/tmp/x.sh", "x.sh"));
        assert!(!wanted("/tmp/notes.txt", "notes.txt"));
    }

    #[test]
    fn bare_partition_detection() {
        let mut img = vec![0u8; 4096];
        img[1024 + 56] = 0x53;
        img[1024 + 57] = 0xEF;
        let mut c = std::io::Cursor::new(img);
        let p = find_linux_partitions(&mut c);
        assert_eq!(p.ext4, vec![0]);
        assert!(p.lvm.is_empty());
    }
}
