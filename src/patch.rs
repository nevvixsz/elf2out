//! Optional heuristic fixup for non-PIE (`ET_EXEC`) binaries.
//!
//! When an ELF was linked at a fixed address and the 9front layout requires a
//! different address, RIP-relative code keeps working but *absolute*
//! immediates and pointers do not.  This module rewrites the common x86
//! encodings of absolute addresses and all naturally aligned pointer words in
//! data.  It is deliberately opt-in (`--patch-abs`) because no pattern scan
//! can ever be as reliable as real relocations: use `-fPIE` if you can.

use crate::arch::{EM_386, EM_X86_64};
use crate::elf::{ElfFile, PF_W, PF_X};
use crate::error::{Error, Result};
use crate::image::Memory;

#[derive(Debug, Default, Clone)]
pub struct PatchStats {
    pub patched: usize,
    pub notes: Vec<String>,
}

pub fn patch_absolute_addresses(
    elf: &ElfFile,
    mem: &mut Memory,
    bias: i64,
) -> Result<PatchStats> {
    let (min, max) = elf.load_bounds()?;
    let mut stats = PatchStats::default();

    if elf.is_64 {
        if elf.machine != EM_X86_64 {
            return Err(Error::unsupported(
                "--patch-abs currently supports x86-64 ELF64 only; rebuild with -fPIE \
                 for other architectures",
            ));
        }
        for ph in elf.load_segments() {
            if ph.filesz == 0 {
                continue;
            }
            if ph.flags & PF_X != 0 {
                patch_x86_64_code(mem, ph.vaddr, ph.filesz, min, max, bias, &mut stats)?;
            } else {
                patch_pointer_words(mem, ph.vaddr, ph.filesz, min, max, bias, &mut stats)?;
            }
        }
    } else {
        if elf.machine != EM_386 {
            return Err(Error::unsupported(
                "--patch-abs currently supports i386 and x86-64 only; rebuild with -fPIE",
            ));
        }
        for ph in elf.load_segments() {
            if ph.filesz == 0 {
                continue;
            }
            if ph.flags & PF_X != 0 {
                patch_i386_code(mem, ph.vaddr, ph.filesz, min, max, bias, &mut stats)?;
            } else {
                patch_i386_data(mem, ph.vaddr, ph.filesz, min, max, bias, &mut stats)?;
            }
        }
    }

    stats.notes.push(format!(
        "heuristically patched {} absolute address(es); verify the result on 9front",
        stats.patched
    ));
    Ok(stats)
}

fn rebased(value: u64, bias: i64) -> u64 {
    (value as i128 + bias as i128) as u64
}

fn in_range(value: u64, min: u64, max: u64) -> bool {
    value >= min && value < max
}

fn patch_x86_64_code(
    mem: &mut Memory,
    start: u64,
    len: u64,
    min: u64,
    max: u64,
    bias: i64,
    stats: &mut PatchStats,
) -> Result<()> {
    let end = start + len;
    let mut addr = start;
    while addr + 1 < end {
        let b0 = mem.read_u8(addr)?;
        let mut rex = 0u8;
        let mut op = b0;
        let mut i = addr;
        if (0x48..=0x4f).contains(&b0) && addr + 1 < end {
            rex = b0;
            op = mem.read_u8(addr + 1)?;
            i = addr + 1;
        }

        // movabs $imm64, %reg   (REX.W + B8+r + imm64)
        if rex & 0x08 != 0 && (0xb8..=0xbf).contains(&op) && i + 9 <= end {
            let value = mem.read_u64(i + 1)?;
            if in_range(value, min, max) {
                mem.write_u64(i + 1, rebased(value, bias))?;
                stats.patched += 1;
                addr = i + 9;
                continue;
            }
        }

        // mov $imm32, %reg      (B8+r + imm32)
        if rex & 0x08 == 0 && (0xb8..=0xbf).contains(&op) && i + 5 <= end {
            let value = mem.read_u32(i + 1)? as u64;
            if in_range(value, min, max) {
                let new = rebased(value, bias);
                if new <= u32::MAX as u64 {
                    mem.write_u32(i + 1, new as u32)?;
                    stats.patched += 1;
                }
                addr = i + 5;
                continue;
            }
        }

        // push $imm32
        if op == 0x68 && i + 5 <= end {
            let value = mem.read_u32(i + 1)? as u64;
            if in_range(value, min, max) {
                let new = rebased(value, bias);
                if new <= u32::MAX as u64 {
                    mem.write_u32(i + 1, new as u32)?;
                    stats.patched += 1;
                }
            }
            addr = i + 5;
            continue;
        }

        // mov $imm32, m64       ([REX.W] C7 /0 imm32)
        if op == 0xc7 {
            if let Some(imm_at) = modrm_imm32_offset(mem, i, end, rex != 0)? {
                let value = mem.read_u32(imm_at)? as u64;
                if in_range(value, min, max) {
                    let new = rebased(value, bias);
                    if new <= u32::MAX as u64 {
                        mem.write_u32(imm_at, new as u32)?;
                        stats.patched += 1;
                    }
                }
                addr = imm_at + 4;
                continue;
            }
        }

        // movabs moffs64, %rax / %rax, moffs64
        if op == 0xa1 || op == 0xa3 {
            if rex & 0x08 != 0 && i + 9 <= end {
                let value = mem.read_u64(i + 1)?;
                if in_range(value, min, max) {
                    mem.write_u64(i + 1, rebased(value, bias))?;
                    stats.patched += 1;
                }
                addr = i + 9;
                continue;
            }
        }

        addr += 1;
    }
    Ok(())
}

/// Return the address of the imm32 that follows a C7 /0 or 81 /0 instruction
/// starting at `opcode` (pointing at the opcode byte).
fn modrm_imm32_offset(
    mem: &Memory,
    opcode: u64,
    end: u64,
    has_rex: bool,
) -> Result<Option<u64>> {
    if opcode + 1 >= end {
        return Ok(None);
    }
    let modrm = mem.read_u8(opcode + 1)?;
    if ((modrm >> 3) & 7) != 0 {
        // Not a /0 instruction; C7 /7 is XBEGIN, not mov.
        return Ok(None);
    }
    let mod_bits = modrm >> 6;
    let rm = modrm & 7;
    let mut at = opcode + 2;
    if rm == 4 && mod_bits != 3 {
        if at >= end {
            return Ok(None);
        }
        let _sib = mem.read_u8(at)?;
        at += 1;
    }
    match mod_bits {
        0 => {
            if rm == 5 {
                at += 4; // RIP-relative disp32 / absolute in 32-bit mode
            }
        }
        1 => at += 1,
        2 => at += 4,
        3 => {}
        _ => unreachable!(),
    }
    let _ = has_rex;
    if at + 4 > end {
        return Ok(None);
    }
    Ok(Some(at))
}

fn patch_pointer_words(
    mem: &mut Memory,
    start: u64,
    len: u64,
    min: u64,
    max: u64,
    bias: i64,
    stats: &mut PatchStats,
) -> Result<()> {
    // Only naturally aligned qwords are treated as pointers; random unaligned
    // byte sequences in strings or float constants must not be touched.
    let aligned = (start + 7) & !7u64;
    let mut addr = aligned;
    let end = start + len;
    while addr + 8 <= end {
        let value = mem.read_u64(addr)?;
        if in_range(value, min, max) {
            mem.write_u64(addr, rebased(value, bias))?;
            stats.patched += 1;
        }
        addr += 8;
    }
    Ok(())
}

fn patch_i386_code(
    mem: &mut Memory,
    start: u64,
    len: u64,
    min: u64,
    max: u64,
    bias: i64,
    stats: &mut PatchStats,
) -> Result<()> {
    let end = start + len;
    let mut addr = start;
    while addr + 5 <= end {
        let op = mem.read_u8(addr)?;
        if (0xb8..=0xbf).contains(&op) {
            let value = mem.read_u32(addr + 1)? as u64;
            if in_range(value, min, max) {
                let new = rebased(value, bias);
                if new <= u32::MAX as u64 {
                    mem.write_u32(addr + 1, new as u32)?;
                    stats.patched += 1;
                }
            }
            addr += 5;
            continue;
        }
        if op == 0x68 {
            let value = mem.read_u32(addr + 1)? as u64;
            if in_range(value, min, max) {
                let new = rebased(value, bias);
                if new <= u32::MAX as u64 {
                    mem.write_u32(addr + 1, new as u32)?;
                    stats.patched += 1;
                }
            }
            addr += 5;
            continue;
        }
        if op == 0xc7 {
            if let Some(imm_at) = modrm_imm32_offset(mem, addr, end, false)? {
                let value = mem.read_u32(imm_at)? as u64;
                if in_range(value, min, max) {
                    let new = rebased(value, bias);
                    if new <= u32::MAX as u64 {
                        mem.write_u32(imm_at, new as u32)?;
                        stats.patched += 1;
                    }
                }
                addr = imm_at + 4;
                continue;
            }
        }
        addr += 1;
    }
    Ok(())
}

fn patch_i386_data(
    mem: &mut Memory,
    start: u64,
    len: u64,
    min: u64,
    max: u64,
    bias: i64,
    stats: &mut PatchStats,
) -> Result<()> {
    let aligned = (start + 3) & !3u64;
    let mut addr = aligned;
    let end = start + len;
    let _ = PF_W;
    while addr + 4 <= end {
        let value = mem.read_u32(addr)? as u64;
        if in_range(value, min, max) {
            let new = rebased(value, bias);
            if new <= u32::MAX as u64 {
                mem.write_u32(addr, new as u32)?;
                stats.patched += 1;
            }
        }
        addr += 4;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebasing_wraps_like_a_loader() {
        assert_eq!(rebased(0x100_1000, -0x10_0000), 0xf0_1000);
    }

    #[test]
    fn range_check() {
        assert!(in_range(0x1000, 0x1000, 0x2000));
        assert!(!in_range(0x2000, 0x1000, 0x2000));
    }
}
