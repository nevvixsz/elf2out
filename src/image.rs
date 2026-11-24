//! A flat in-memory image of the ELF's loadable segments.
//!
//! Relocations are applied in the *original* ELF address space and only then
//! the whole image is copied into the Plan 9 text/data layout with a single
//! uniform load bias.  Keeping everything in one flat `Vec<u8>` makes that
//! simple and makes the optional absolute-address patcher possible.

use crate::elf::{ElfFile, Phdr};
use crate::error::{Error, ErrorKind, Result};

/// Refuse absurdly sparse ELFs.  A static Zig freestanding binary is a few
/// megabytes; anything spanning gigabytes is not something this converter
/// should silently turn into a multi-gigabyte a.out file.
pub const MAX_IMAGE_SPAN: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Memory {
    pub base: u64,
    pub end: u64,
    pub buf: Vec<u8>,
}

impl Memory {
    pub fn from_load_segments(elf: &ElfFile) -> Result<Self> {
        let (min, max) = elf.load_bounds()?;
        let span = max.saturating_sub(min);
        ensure!(
            span <= MAX_IMAGE_SPAN,
            ErrorKind::Layout,
            "ELF load segments span {:#x} bytes (limit {:#x}); a sparse ELF like this \
             cannot be represented as a flat a.out image",
            span,
            MAX_IMAGE_SPAN
        );
        Ok(Self {
            base: min,
            end: max,
            buf: vec![0u8; span as usize],
        })
    }

    pub fn contains(&self, addr: u64, len: u64) -> bool {
        addr >= self.base && addr.saturating_add(len) <= self.end
    }

    fn index(&self, addr: u64, len: u64) -> Result<usize> {
        ensure!(
            self.contains(addr, len),
            ErrorKind::Format,
            "address range {:#x}..{:#x} is not part of any loadable ELF segment",
            addr,
            addr.saturating_add(len)
        );
        Ok((addr - self.base) as usize)
    }

    pub fn load_segment(&mut self, elf: &ElfFile, ph: &Phdr) -> Result<()> {
        if ph.filesz == 0 {
            return Ok(());
        }
        let idx = self.index(ph.vaddr, ph.filesz)?;
        let src_start = ph.offset as usize;
        let src_end = src_start.checked_add(ph.filesz as usize).ok_or_else(|| {
            Error::format("PT_LOAD file range overflow")
        })?;
        ensure!(
            src_end <= elf.data.len(),
            ErrorKind::Format,
            "PT_LOAD at {:#x} points past end of input file",
            ph.vaddr
        );
        let dst_end = idx.checked_add(ph.filesz as usize).ok_or_else(|| {
            Error::format("PT_LOAD memory range overflow")
        })?;
        self.buf[idx..dst_end].copy_from_slice(&elf.data[src_start..src_end]);
        Ok(())
    }

    pub fn read_u8(&self, addr: u64) -> Result<u8> {
        let i = self.index(addr, 1)?;
        Ok(self.buf[i])
    }

    pub fn read_u32(&self, addr: u64) -> Result<u32> {
        let i = self.index(addr, 4)?;
        Ok(u32::from_le_bytes([
            self.buf[i],
            self.buf[i + 1],
            self.buf[i + 2],
            self.buf[i + 3],
        ]))
    }

    pub fn read_u64(&self, addr: u64) -> Result<u64> {
        let i = self.index(addr, 8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[i..i + 8]);
        Ok(u64::from_le_bytes(b))
    }

    pub fn write_u8(&mut self, addr: u64, value: u8) -> Result<()> {
        let i = self.index(addr, 1)?;
        self.buf[i] = value;
        Ok(())
    }

    pub fn write_u32(&mut self, addr: u64, value: u32) -> Result<()> {
        let i = self.index(addr, 4)?;
        self.buf[i..i + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub fn write_u64(&mut self, addr: u64, value: u64) -> Result<()> {
        let i = self.index(addr, 8)?;
        self.buf[i..i + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let i = self.index(addr, len as u64)?;
        Ok(self.buf[i..i + len].to_vec())
    }

    pub fn write_bytes(&mut self, addr: u64, bytes: &[u8]) -> Result<()> {
        let i = self.index(addr, bytes.len() as u64)?;
        self.buf[i..i + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Extract a range into an owned vector, zero-filling anything that was
    /// not part of a loadable section (the padding in front of the program,
    /// for example).
    pub fn extract(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        ensure!(
            len <= MAX_IMAGE_SPAN,
            ErrorKind::Layout,
            "requested image slice of {:#x} bytes is unreasonably large",
            len
        );
        let mut out = vec![0u8; len as usize];
        let start = addr.max(self.base);
        let stop = (addr.saturating_add(len)).min(self.end);
        if stop > start {
            let dst = (start - addr) as usize;
            let src = (start - self.base) as usize;
            let n = (stop - start) as usize;
            out[dst..dst + n].copy_from_slice(&self.buf[src..src + n]);
        }
        Ok(out)
    }

    /// Like `extract`, but the start address may be negative.  This happens
    /// when the padding in front of the ELF image is larger than the ELF's
    /// lowest virtual address (the normal case for a PIE linked at zero).
    pub fn extract_from_i128(&self, addr: i128, len: u64) -> Result<Vec<u8>> {
        if addr >= 0 {
            return self.extract(addr as u64, len);
        }
        let missing = (-addr) as u64;
        if missing >= len {
            return Ok(vec![0u8; len as usize]);
        }
        let mut out = vec![0u8; missing as usize];
        out.extend_from_slice(&self.extract(0, len - missing)?);
        Ok(out)
    }

    /// Does this address belong to a file-backed part of the image?
    pub fn contains_original_address(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Memory {
        Memory {
            base: 0x1000,
            end: 0x1010,
            buf: (0u8..16).collect(),
        }
    }

    #[test]
    fn read_write_le() {
        let mut m = image();
        m.write_u32(0x1004, 0xdead_beef).unwrap();
        assert_eq!(m.read_u32(0x1004).unwrap(), 0xdead_beef);
        assert_eq!(m.read_u8(0x1004).unwrap(), 0xef);
    }

    #[test]
    fn extract_zero_fills_gaps() {
        let m = image();
        let v = m.extract(0x0ff8, 32).unwrap();
        assert_eq!(v.len(), 32);
        assert_eq!(&v[0..8], &[0; 8]);
        assert_eq!(v[8], 0);
        assert_eq!(v[16], 8);
    }

    #[test]
    fn extract_from_negative_start() {
        let m = Memory {
            base: 0,
            end: 16,
            buf: (0u8..16).collect(),
        };
        let v = m.extract_from_i128(-4, 12).unwrap();
        assert_eq!(v.len(), 12);
        assert_eq!(&v[0..4], &[0; 4]);
        assert_eq!(v[4], 0);
        assert_eq!(v[11], 7);
    }

    #[test]
    fn out_of_range_access_fails() {
        let m = image();
        assert!(m.read_u64(0x100c).is_err());
    }
}
