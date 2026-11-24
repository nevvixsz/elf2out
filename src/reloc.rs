//! Static relocation application.
//!
//! A freestanding PIE emitted by Zig has no dynamic loader on 9front, so all
//! `R_*_RELATIVE` (and the occasional absolute/GOT) relocations have to be
//! resolved here and written back into the image before it is split into the
//! a.out text and data segments.

use crate::arch::{Arch, EM_386, EM_AARCH64, EM_X86_64};
use crate::elf::{ElfFile, Reloc, STB_WEAK};
use crate::error::{Error, ErrorKind, Result};
use crate::image::Memory;

#[derive(Debug, Default, Clone)]
pub struct RelocStats {
    pub applied: usize,
    pub relative: usize,
    pub ignored: usize,
    pub notes: Vec<String>,
}

/// Relocation numbers we can resolve without a loader.
pub mod x86_64 {
    pub const NONE: u32 = 0;
    pub const R64: u32 = 1;
    pub const PC32: u32 = 2;
    pub const GOT32: u32 = 3;
    pub const PLT32: u32 = 4;
    pub const COPY: u32 = 5;
    pub const GLOB_DAT: u32 = 6;
    pub const JUMP_SLOT: u32 = 7;
    pub const RELATIVE: u32 = 8;
    pub const GOTPCREL: u32 = 9;
    pub const R32: u32 = 10;
    pub const R32S: u32 = 11;
    pub const R16: u32 = 12;
    pub const PC16: u32 = 13;
    pub const R8: u32 = 14;
    pub const PC8: u32 = 15;
    pub const DTPMOD64: u32 = 16;
    pub const DTPOFF64: u32 = 17;
    pub const TPOFF64: u32 = 18;
    pub const TLSGD: u32 = 19;
    pub const TLSLD: u32 = 20;
    pub const DTPOFF32: u32 = 21;
    pub const GOTTPOFF: u32 = 22;
    pub const TPOFF32: u32 = 23;
    pub const PC64: u32 = 24;
    pub const GOTOFF64: u32 = 25;
    pub const GOTPC32: u32 = 26;
    pub const SIZE32: u32 = 32;
    pub const SIZE64: u32 = 33;
    pub const IRELATIVE: u32 = 37;
    pub const RELATIVE64: u32 = 38;
}

pub mod aarch64 {
    pub const NONE: u32 = 0;
    pub const ABS64: u32 = 257;
    pub const ABS32: u32 = 258;
    pub const ABS16: u32 = 259;
    pub const PREL64: u32 = 260;
    pub const PREL32: u32 = 261;
    pub const PREL16: u32 = 262;
    pub const ADR_PREL_PG_HI21: u32 = 275;
    pub const ADD_ABS_LO12_NC: u32 = 276;
    pub const JMP26: u32 = 282;
    pub const CALL26: u32 = 283;
    pub const GLOB_DAT: u32 = 1025;
    pub const JUMP_SLOT: u32 = 1026;
    pub const RELATIVE: u32 = 1027;
    pub const COPY: u32 = 1028;
    pub const IRELATIVE: u32 = 1041;
    pub const TLS_DTPMOD64: u32 = 1022;
    pub const TLS_DTPREL64: u32 = 1023;
    pub const TLS_TPREL64: u32 = 1024;
}

pub mod i386 {
    pub const NONE: u32 = 0;
    pub const R32: u32 = 1;
    pub const PC32: u32 = 2;
    pub const GOT32: u32 = 3;
    pub const PLT32: u32 = 4;
    pub const COPY: u32 = 5;
    pub const GLOB_DAT: u32 = 6;
    pub const JMP_SLOT: u32 = 7;
    pub const RELATIVE: u32 = 8;
    pub const GOTOFF: u32 = 9;
    pub const GOTPC: u32 = 10;
    pub const IRELATIVE: u32 = 38;
}

/// Used by the section parser to decide whether a relocation section without
/// a symbol table can still be read safely.
pub fn is_relative_type(machine: u16, typ: u32) -> bool {
    match machine {
        EM_X86_64 => typ == x86_64::RELATIVE,
        EM_AARCH64 => typ == aarch64::RELATIVE,
        EM_386 => typ == i386::RELATIVE,
        _ => false,
    }
}

pub fn apply_relocations(
    elf: &ElfFile,
    mem: &mut Memory,
    arch: Arch,
    bias: i64,
) -> Result<RelocStats> {
    let mut stats = RelocStats::default();
    for r in &elf.relocs {
        apply_one(elf, mem, arch, bias, r, &mut stats)?;
    }
    Ok(stats)
}

fn addend_for(elf: &ElfFile, mem: &Memory, r: &Reloc) -> Result<i64> {
    if r.is_rela {
        return Ok(r.addend);
    }
    // REL has no explicit addend: it is stored in the location itself.
    match arch_pointer_size(elf) {
        8 => Ok(mem.read_u64(r.offset)? as i64),
        4 => Ok(mem.read_u32(r.offset)? as i32 as i64),
        n => bail!(ErrorKind::Format, "unsupported pointer size {}", n),
    }
}

fn arch_pointer_size(elf: &ElfFile) -> usize {
    if elf.is_64 { 8 } else { 4 }
}

fn symbol_value(elf: &ElfFile, symbol_table: usize, index: u32, bias: i64) -> Result<u64> {
    if index == 0 {
        // STN_UNDEF: zero for RELATIVE-style relocations.
        return Ok(0);
    }
    let sym = elf.symbol(symbol_table, index)?;
    if sym.is_undefined() {
        if sym.bind() == STB_WEAK {
            return Ok(0);
        }
        return Err(Error::relocation(format!(
            "undefined symbol `{}` is referenced by a relocation; 9front has no \
             dynamic linker, so external symbols cannot be resolved",
            if sym.name.is_empty() { "<unnamed>" } else { &sym.name }
        )));
    }
    if sym.is_tls() {
        return Err(Error::relocation(format!(
            "TLS symbol `{}` cannot be represented in a 9front a.out executable",
            sym.name
        )));
    }
    if sym.is_absolute() {
        return Ok(sym.value);
    }
    Ok(sym.value.wrapping_add(bias as u64))
}

fn write_word(mem: &mut Memory, addr: u64, value: u64, bytes: usize) -> Result<()> {
    match bytes {
        8 => mem.write_u64(addr, value),
        4 => mem.write_u32(addr, value as u32),
        2 => mem.write_u8(addr, value as u8).and_then(|_| {
            mem.write_u8(addr + 1, (value >> 8) as u8)
        }),
        1 => mem.write_u8(addr, value as u8),
        _ => Err(Error::relocation(format!("unsupported relocation width {}", bytes))),
    }
}

fn check_signed(value: i128, bits: u32, what: &str) -> Result<()> {
    let min = -(1i128 << (bits - 1));
    let max = (1i128 << (bits - 1)) - 1;
    ensure!(
        value >= min && value <= max,
        ErrorKind::Relocation,
        "{} relocation out of range: {} does not fit in {} bits",
        what,
        value,
        bits
    );
    Ok(())
}

fn apply_one(
    elf: &ElfFile,
    mem: &mut Memory,
    arch: Arch,
    bias: i64,
    r: &Reloc,
    stats: &mut RelocStats,
) -> Result<()> {
    if r.offset == 0 && r.typ == 0 {
        return Ok(());
    }
    let addend = addend_for(elf, mem, r)?;
    let p = r.offset;
    let sym = symbol_value(elf, r.symtab, r.sym, bias)?;

    match elf.machine {
        EM_X86_64 => apply_x86_64(mem, r, addend, p, sym, bias, stats),
        EM_AARCH64 => apply_aarch64(mem, r, addend, p, sym, bias, stats),
        EM_386 => apply_i386(mem, r, addend, p, sym, bias, stats),
        _ => match arch {
            // For an explicitly forced architecture, fall back to the
            // pointer size of that architecture using generic ABS/RELATIVE.
            _ => Err(Error::unsupported(format!(
                "relocations for e_machine={} are not implemented",
                elf.machine
            ))),
        },
    }
}

fn apply_x86_64(
    mem: &mut Memory,
    r: &Reloc,
    a: i64,
    p: u64,
    s: u64,
    bias: i64,
    stats: &mut RelocStats,
) -> Result<()> {
    use x86_64::*;
    match r.typ {
        NONE => {
            stats.ignored += 1;
        }
        RELATIVE => {
            let value = (bias as u64).wrapping_add(a as u64);
            write_word(mem, p, value, 8)?;
            stats.relative += 1;
            stats.applied += 1;
        }
        RELATIVE64 => {
            let value = (bias as u64).wrapping_add(a as u64);
            write_word(mem, p, value, 8)?;
            stats.relative += 1;
            stats.applied += 1;
        }
        R64 | GLOB_DAT | JUMP_SLOT => {
            let value = s.wrapping_add(a as u64);
            write_word(mem, p, value, 8)?;
            stats.applied += 1;
        }
        PC64 | PLT32 | PC32 | GOTPCREL | GOTPC32 => {
            let delta = s as i128 - p as i128 + a as i128;
            let width: usize = if r.typ == PC64 { 8 } else { 4 };
            check_signed(delta, (width * 8) as u32, "PC-relative")?;
            write_word(mem, p, delta as u64, width)?;
            stats.applied += 1;
        }
        R32 => {
            let value = s.wrapping_add(a as u64);
            ensure!(
                value <= u32::MAX as u64,
                ErrorKind::Relocation,
                "R_X86_64_32 overflow at {:#x}",
                p
            );
            write_word(mem, p, value, 4)?;
            stats.applied += 1;
        }
        R32S => {
            let value = s as i128 + a as i128;
            check_signed(value, 32, "R_X86_64_32S")?;
            write_word(mem, p, value as u64, 4)?;
            stats.applied += 1;
        }
        R16 | PC16 => {
            let value = if r.typ == PC16 {
                s as i128 - p as i128 + a as i128
            } else {
                s as i128 + a as i128
            };
            check_signed(value, 16, "16-bit")?;
            write_word(mem, p, value as u64, 2)?;
            stats.applied += 1;
        }
        R8 | PC8 => {
            let value = if r.typ == PC8 {
                s as i128 - p as i128 + a as i128
            } else {
                s as i128 + a as i128
            };
            check_signed(value, 8, "8-bit")?;
            write_word(mem, p, value as u64, 1)?;
            stats.applied += 1;
        }
        SIZE32 | SIZE64 => {
            // Symbol sizes are unaffected by the load bias and no 9front
            // loader will ever look at them.
            stats.ignored += 1;
        }
        COPY => {
            return Err(Error::relocation(
                "R_X86_64_COPY requires a dynamic loader; copy relocations cannot be \
                 resolved when converting to a.out"
            ));
        }
        IRELATIVE => {
            return Err(Error::relocation(
                "R_X86_64_IRELATIVE (IFUNC) cannot be resolved without running a resolver"
            ));
        }
        DTPMOD64 | DTPOFF64 | TPOFF64 | TLSGD | TLSLD | DTPOFF32 | GOTTPOFF | TPOFF32 => {
            return Err(Error::relocation(format!(
                "TLS relocation type {} at {:#x} cannot be represented in a 9front binary",
                r.typ, p
            )));
        }
        GOT32 | GOTOFF64 => {
            return Err(Error::relocation(format!(
                "GOT-specific relocation type {} at {:#x} is not supported (build with \
                 -fPIE and no external symbols)",
                r.typ, p
            )));
        }
        other => {
            return Err(Error::relocation(format!(
                "unsupported x86-64 relocation type {} at {:#x}",
                other, p
            )));
        }
    }
    let _ = bias;
    Ok(())
}

fn apply_i386(
    mem: &mut Memory,
    r: &Reloc,
    a: i64,
    p: u64,
    s: u64,
    bias: i64,
    stats: &mut RelocStats,
) -> Result<()> {
    use i386::*;
    match r.typ {
        NONE => stats.ignored += 1,
        RELATIVE => {
            // For REL, `a` was read from the location and already contains
            // the original link-time address; the bias still has to be added.
            let value = (a as u64).wrapping_add(bias as u64);
            write_word(mem, p, value, 4)?;
            stats.relative += 1;
            stats.applied += 1;
        }
        R32 | GLOB_DAT | JMP_SLOT | GOT32 | PLT32 => {
            write_word(mem, p, s.wrapping_add(a as u64), 4)?;
            stats.applied += 1;
        }
        PC32 => {
            let delta = s as i128 - p as i128 + a as i128;
            check_signed(delta, 32, "PC-relative")?;
            write_word(mem, p, delta as u64, 4)?;
            stats.applied += 1;
        }
        COPY => {
            return Err(Error::relocation(
                "R_386_COPY requires a dynamic loader and cannot be converted"
            ));
        }
        IRELATIVE => {
            return Err(Error::relocation("R_386_IRELATIVE cannot be resolved statically"));
        }
        other => {
            return Err(Error::relocation(format!(
                "unsupported i386 relocation type {} at {:#x}",
                other, p
            )));
        }
    }
    Ok(())
}

fn apply_aarch64(
    mem: &mut Memory,
    r: &Reloc,
    a: i64,
    p: u64,
    s: u64,
    bias: i64,
    stats: &mut RelocStats,
) -> Result<()> {
    use aarch64::*;
    match r.typ {
        NONE => stats.ignored += 1,
        RELATIVE => {
            // `s` is already rebased by symbol_value() when a symbol is
            // present; RELATIVE normally has symbol 0, in which case the
            // addend (the link-time pointer) plus bias is the value.
            let value = if r.sym == 0 {
                (a as u64).wrapping_add(bias as u64)
            } else {
                s.wrapping_add(a as u64)
            };
            write_word(mem, p, value, 8)?;
            stats.relative += 1;
            stats.applied += 1;
        }
        ABS64 | GLOB_DAT | JUMP_SLOT => {
            write_word(mem, p, s.wrapping_add(a as u64), 8)?;
            stats.applied += 1;
        }
        ABS32 | PREL32 => {
            let value = if r.typ == PREL32 {
                s as i128 - p as i128 + a as i128
            } else {
                s as i128 + a as i128
            };
            check_signed(value, 32, "AArch64 32-bit")?;
            write_word(mem, p, value as u64, 4)?;
            stats.applied += 1;
        }
        ABS16 | PREL16 => {
            let width: usize = 2;
            let value = if r.typ == PREL16 {
                s as i128 - p as i128 + a as i128
            } else {
                s as i128 + a as i128
            };
            check_signed(value, (width * 8) as u32, "AArch64")?;
            write_word(mem, p, value as u64, width)?;
            stats.applied += 1;
        }
        PREL64 => {
            write_word(mem, p, (s as i128 - p as i128 + a as i128) as u64, 8)?;
            stats.applied += 1;
        }
        ADR_PREL_PG_HI21 | ADD_ABS_LO12_NC | JMP26 | CALL26 => {
            // For RELATIVE-style PIEs these are already resolved by ld.lld;
            // if they do show up, patch the instruction in place.
            let insn = mem.read_u32(p)?;
            let target = s.wrapping_add(a as u64);
            let encoded = if r.typ == ADR_PREL_PG_HI21 {
                let page_delta = ((target & !0xfffu64) as i64 - (p & !0xfffu64) as i64) >> 12;
                check_signed(page_delta as i128, 21, "ADRP page")?;
                let v = (page_delta as u32) & 0x1f_ffff;
                (insn & 0x9f00_001f) | ((v & 3) << 29) | (((v >> 2) & 0x7_ffff) << 5)
            } else if r.typ == ADD_ABS_LO12_NC {
                (insn & 0xffc0_03ff) | (((target & 0xfff) as u32) << 10)
            } else {
                let branch = ((target as i128 - p as i128) >> 2) as i64;
                check_signed(branch as i128, 26, "AArch64 branch")?;
                (insn & 0xfc00_0000) | ((branch as u32) & 0x03ff_ffff)
            };
            mem.write_u32(p, encoded)?;
            stats.applied += 1;
        }
        COPY => {
            return Err(Error::relocation(
                "R_AARCH64_COPY requires a dynamic loader and cannot be converted"
            ));
        }
        IRELATIVE => {
            return Err(Error::relocation("R_AARCH64_IRELATIVE cannot be resolved statically"));
        }
        TLS_DTPMOD64 | TLS_DTPREL64 => {
            return Err(Error::relocation(format!(
                "TLS relocation type {} at {:#x} cannot be represented in a 9front binary",
                r.typ, p
            )));
        }
        other => {
            return Err(Error::relocation(format!(
                "unsupported AArch64 relocation type {} at {:#x}",
                other, p
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::EM_AARCH64;

    fn memory() -> Memory {
        Memory {
            base: 0x1000,
            end: 0x2000,
            buf: vec![0u8; 0x1000],
        }
    }

    #[test]
    fn relative_types() {
        assert!(is_relative_type(EM_X86_64, x86_64::RELATIVE));
        assert!(is_relative_type(EM_AARCH64, aarch64::RELATIVE));
        assert!(!is_relative_type(EM_X86_64, x86_64::R64));
    }

    #[test]
    fn signed_range_check() {
        assert!(check_signed(100, 16, "test").is_ok());
        assert!(check_signed(-32768, 16, "test").is_ok());
        assert!(check_signed(32768, 16, "test").is_err());
    }

    #[test]
    fn writes_words() {
        let mut m = memory();
        write_word(&mut m, 0x1010, 0x1122_3344_5566_7788, 8).unwrap();
        assert_eq!(m.read_u64(0x1010).unwrap(), 0x1122_3344_5566_7788);
        write_word(&mut m, 0x1020, 0xdead_beef, 4).unwrap();
        assert_eq!(m.read_u32(0x1020).unwrap(), 0xdead_beef);
    }
}
