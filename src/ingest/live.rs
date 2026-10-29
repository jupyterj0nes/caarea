//! Live NTFS volumes (`\\.\C:` on Windows): the same extraction as a disk image, run on the
//! system itself. Locked files (hives, `$MFT`, in-use event logs) and every Volume Shadow
//! Copy are read straight from the raw volume, which is what a triage of a running host
//! needs. Direct volume reads must be sector aligned, so the device is wrapped in a reader
//! that serves any offset and length from aligned 64 KB blocks.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

const BLOCK: u64 = 1 << 16;

/// Is this a raw volume path (`\\.\C:`, `\\.\PhysicalDrive0` on Windows; `/dev/sda1`,
/// `/dev/mapper/vg-root` on Linux)?
pub fn is_live_volume(path: &str) -> bool {
    let p = path.trim();
    ((p.starts_with("\\\\.\\") || p.starts_with("//./")) && p.len() > 4) || p.starts_with("/dev/")
}

/// Short, file-system safe label for a device path: `\\.\C:` -> `live_C`, `/dev/sda1` -> `live_sda1`.
pub fn live_label(path: &str) -> String {
    let tail = path.trim().trim_start_matches("\\\\.\\").trim_start_matches("//./").trim_start_matches("/dev/");
    let clean: String = tail.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    format!("live_{}", if clean.is_empty() { "volume".to_string() } else { clean })
}

/// Sector-aligned read cache over a raw device.
pub struct AlignedReader<R: Read + Seek> {
    inner: R,
    pos: u64,
    size: u64,
    block: Vec<u8>,
    block_start: u64,
    block_len: usize,
}

impl<R: Read + Seek> AlignedReader<R> {
    pub fn new(inner: R, size: u64) -> Self {
        AlignedReader { inner, pos: 0, size, block: vec![0u8; BLOCK as usize], block_start: u64::MAX, block_len: 0 }
    }

    fn load(&mut self, start: u64) -> io::Result<()> {
        let want = BLOCK.min(self.size.saturating_sub(start)) as usize;
        self.inner.seek(SeekFrom::Start(start))?;
        let mut got = 0usize;
        while got < want {
            match self.inner.read(&mut self.block[got..want]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        self.block_start = start;
        self.block_len = got;
        Ok(())
    }
}

impl<R: Read + Seek> Read for AlignedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let start = self.pos - self.pos % BLOCK;
        if start != self.block_start {
            self.load(start)?;
        }
        let off = (self.pos - start) as usize;
        if off >= self.block_len {
            return Ok(0);
        }
        let n = buf.len().min(self.block_len - off);
        buf[..n].copy_from_slice(&self.block[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for AlignedReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Opens a raw volume or disk device. The size comes from the NTFS boot sector when there is
/// one (Windows volume handles cannot be measured with a seek), otherwise from seeking to the
/// end, which Linux block devices support.
pub fn open_live_volume(path: &str) -> Result<(AlignedReader<File>, u64), String> {
    let mut file = File::open(path).map_err(|e| format!("cannot open {} (administrator or root rights are required): {}", path, e))?;
    let seek_size = file.seek(SeekFrom::End(0)).ok().filter(|&s| s > 0);
    let mut probe = AlignedReader::new(file, BLOCK);
    let mut boot = [0u8; 512];
    probe.read_exact(&mut boot).map_err(|e| format!("cannot read the first sector of {}: {}", path, e))?;
    let size = if &boot[3..11] == b"NTFS    " {
        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]) as u64;
        let total_sectors = u64::from_le_bytes(boot[40..48].try_into().unwrap());
        if bytes_per_sector == 0 || total_sectors == 0 {
            return Err(format!("{}: implausible NTFS geometry", path));
        }
        // the boot sector copy is the sector after the last one counted
        (total_sectors + 1) * bytes_per_sector
    } else {
        seek_size.ok_or_else(|| format!("{}: not an NTFS volume and the device size cannot be determined", path))?
    };
    let inner = probe.inner;
    Ok((AlignedReader::new(inner, size), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_reader_serves_unaligned_requests() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut r = AlignedReader::new(std::io::Cursor::new(data.clone()), data.len() as u64);
        r.seek(SeekFrom::Start(65_530)).unwrap();
        let mut buf = [0u8; 20];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[65_530..65_550]);
        r.seek(SeekFrom::End(-5)).unwrap();
        let mut tail = Vec::new();
        r.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, data[data.len() - 5..].to_vec());
        assert!(is_live_volume("\\\\.\\C:"));
        assert!(!is_live_volume("C:\\image.dd"));
        assert_eq!(live_label("\\\\.\\C:"), "live_C");
    }
}
