//! XFS volumes inside disk images: the file system RHEL, Rocky, Alma and Oracle Linux install
//! by default, as a partition or as an LVM logical volume. Read through the `rust-fs-xfs`
//! driver (short-form, block, leaf and node directories, extent and B+tree forks, v4 and v5
//! with checksums) over the same borrowed reader the ext path uses; the files the Linux
//! parsers know come out as the same root tree the ext4 path produces, so the extracted
//! directory is handled exactly like a UAC collection. The driver and the walk are the ones
//! faramir uses.
//!
//! XFS has no equivalent of the ext4 journal recovery: its log holds operations, not block
//! copies, so nothing deleted comes back from here (`--carve` still reads the raw bytes).

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use fs_core::BlockRead;
use fs_xfs::inode::Inode;
use fs_xfs::Filesystem;

use super::linux_image::{dest_for, wanted, write_file, EXACT_FILES, MAX_DEPTH, MAX_FILE_BYTES, WALK_DIRS};

/// Magic of an XFS superblock, at byte 0 of the volume.
pub const XFS_MAGIC: &[u8; 4] = b"XFSB";

/// Does an XFS superblock sit at `offset`?
pub fn verify_xfs_superblock<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset)).is_err() {
        return false;
    }
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).is_ok() && &magic == XFS_MAGIC
}

/// Reader bridge: the driver owns an `Arc<dyn BlockRead>`, our reader is borrowed. The
/// `Filesystem` never outlives the borrow (it is dropped inside `extract_partition`), and
/// nothing else touches the reader meanwhile; the mutex serialises the driver's reads.
struct BorrowedBlock<R: Read + Seek> {
    reader: Mutex<*mut R>,
    offset: u64,
    size: u64,
}

unsafe impl<R: Read + Seek> Send for BorrowedBlock<R> {}
unsafe impl<R: Read + Seek> Sync for BorrowedBlock<R> {}

impl<R: Read + Seek> BlockRead for BorrowedBlock<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        let mut guard = self.reader.lock().map_err(|_| fs_core::Error::Io(std::io::Error::other("reader poisoned")))?;
        let reader = unsafe { &mut **guard };
        reader.seek(SeekFrom::Start(self.offset + offset)).map_err(fs_core::Error::Io)?;
        reader.read_exact(buf).map_err(fs_core::Error::Io)
    }

    fn size_bytes(&self) -> u64 {
        self.size
    }
}

struct Copier<'a> {
    fs: &'a Filesystem,
    out: &'a Path,
    count: usize,
    seen: HashSet<String>,
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", dir.trim_end_matches('/'), name)
    }
}

/// Resolve a symlink target relative to the directory holding the link.
fn resolve_link(dir: &str, target: &str) -> String {
    let joined = if target.starts_with('/') { target.to_string() } else { join(dir, target) };
    let mut parts: Vec<&str> = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    format!("/{}", parts.join("/"))
}

impl Copier<'_> {
    /// Inode of a path, with a symlink in the final component followed (bounded chain).
    fn open(&self, path: &str, hops: usize) -> Option<(Inode, Vec<u8>)> {
        if hops > 8 {
            return None;
        }
        let inode = self.fs.lookup_path(path).ok()?;
        let (inode, raw) = self.fs.read_inode_raw(inode.ino).ok()?;
        if inode.is_symlink() {
            let target = self.fs.read_link(&inode, &raw).ok()?;
            let target = String::from_utf8_lossy(&target).to_string();
            let dir = path.rsplit_once('/').map(|(d, _)| if d.is_empty() { "/" } else { d }).unwrap_or("/");
            return self.open(&resolve_link(dir, &target), hops + 1);
        }
        Some((inode, raw))
    }

    fn copy_file(&mut self, linux_path: &str, max_bytes: u64) -> bool {
        if !self.seen.insert(linux_path.to_string()) {
            return false;
        }
        let Some((inode, raw)) = self.open(linux_path, 0) else { return false };
        if !inode.is_regular_file() || inode.size > max_bytes {
            return false;
        }
        let Ok(data) = self.fs.read_file(&inode, &raw) else { return false };
        let dest = dest_for(self.out, linux_path);
        if !write_file(&dest, &data) {
            return false;
        }
        if let Some(t) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(inode.mtime.sec.max(0) as u64)) {
            let _ = std::fs::File::options().write(true).open(&dest).and_then(|f| f.set_modified(t));
        }
        self.count += 1;
        true
    }

    fn walk(&mut self, dir: &str, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let Some((inode, raw)) = self.open(dir, 0) else { return };
        if !inode.is_dir() {
            return;
        }
        let Ok(entries) = self.fs.read_dir(&inode, &raw) else { return };
        for e in entries {
            let name = String::from_utf8_lossy(&e.name).to_string();
            if name == "." || name == ".." {
                continue;
            }
            let path = join(dir, &name);
            // a symlinked directory is not followed (loops, usr-merge)
            let is_link = self.fs.lookup_path(&path).map(|i| i.is_symlink()).unwrap_or(false);
            let Some((child, _)) = self.open(&path, 0) else { continue };
            if child.is_dir() {
                if !is_link {
                    self.walk(&path, depth + 1);
                }
            } else if child.is_regular_file() && wanted(&path, &name) {
                let limit = if path.starts_with("/tmp") || path.starts_with("/var/tmp") || path.starts_with("/dev/shm") { 4 << 20 } else { MAX_FILE_BYTES };
                self.copy_file(&path, limit);
            }
        }
    }
}

/// Copies the Linux artifacts of the XFS file system at `offset` into `output_dir`: the same
/// files, the same tree and the same `etc/localtime.symlink` sidecar as the ext path.
pub fn extract_partition<R: Read + Seek + 'static>(reader: &mut R, offset: u64, output_dir: &Path) -> Result<usize, String> {
    let size = reader.seek(SeekFrom::End(0)).map(|end| end.saturating_sub(offset)).unwrap_or(u64::MAX);
    let device: Arc<dyn BlockRead> = Arc::new(BorrowedBlock { reader: Mutex::new(reader as *mut R), offset, size });
    let fs = Filesystem::mount(device).map_err(|e| format!("cannot mount XFS file system at {:#x}: {}", offset, e))?;
    let _ = std::fs::create_dir_all(output_dir);
    let mut c = Copier { fs: &fs, out: output_dir, count: 0, seen: HashSet::new() };
    for path in EXACT_FILES {
        c.copy_file(path, MAX_FILE_BYTES);
    }
    if let Ok(inode) = fs.lookup_path("/etc/localtime") {
        if inode.is_symlink() {
            if let Ok((inode, raw)) = fs.read_inode_raw(inode.ino) {
                if let Ok(target) = fs.read_link(&inode, &raw) {
                    if write_file(&dest_for(output_dir, "/etc/localtime.symlink"), &target) {
                        c.count += 1;
                    }
                }
            }
        }
    }
    for dir in WALK_DIRS {
        c.walk(dir, 0);
    }
    let count = c.count;
    drop(c);
    drop(fs);
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xfs_magic_at_partition_start() {
        let mut img = vec![0u8; 4096];
        img[..4].copy_from_slice(b"XFSB");
        let mut c = std::io::Cursor::new(img);
        assert!(verify_xfs_superblock(&mut c, 0));
        assert!(!verify_xfs_superblock(&mut c, 512));
        assert_eq!(resolve_link("/etc/systemd/system", "../../../usr/lib/systemd/system/x.service"), "/usr/lib/systemd/system/x.service");
        assert_eq!(resolve_link("/etc", "/usr/share/zoneinfo/Europe/Madrid"), "/usr/share/zoneinfo/Europe/Madrid");
    }
}
