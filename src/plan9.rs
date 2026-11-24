//! Conversion from a loaded ELF image to the 9front `a.out(6)` format.

use crate::arch::Arch;
use crate::elf::{ElfFile, ET_EXEC, PF_W, SHN_ABS, STT_FILE, STT_FUNC, STT_NOTYPE, STT_OBJECT, STT_SECTION};
use crate::error::{Error, ErrorKind, Result};
use crate::image::{Memory, MAX_IMAGE_SPAN};
use crate::patch::PatchStats;
use crate::reloc::{apply_relocations, RelocStats};
use crate::patch::patch_absolute_addresses;

#[derive(Debug, Clone, Default)]
pub struct ConvertOptions {
    pub arch: Option<Arch>,
    pub symbols: bool,
    pub patch_abs: bool,
    pub ignore_tls: bool,
    pub entry_override: Option<u64>,
    /// Force the virtual address at which the first ELF byte is placed.
    pub base_override: Option<u64>,
    pub verbose: bool,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub arch: Arch,
    pub bias: i64,
    pub first_elf_vaddr: u64,
    pub elf_start_vaddr: u64,
    pub split_vaddr: u64,
    pub pad: u64,
    pub text_field: u64,
    pub data_field: u64,
    pub bss_field: u64,
    pub entry: u64,
    pub text_vaddr: u64,
    pub data_vaddr: u64,
    pub relocs: RelocStats,
    pub patches: Option<PatchStats>,
    pub warnings: Vec<String>,
    pub output_size: usize,
}

fn put_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64_be(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn round_up(value: u64, align: u64) -> Result<u64> {
    let mask = align - 1;
    ensure!(
        value <= u64::MAX - mask,
        ErrorKind::Layout,
        "rounding {:#x} up to {:#x} overflows",
        value,
        align
    );
    Ok((value + mask) & !mask)
}

pub fn convert(elf: &ElfFile, opts: &ConvertOptions) -> Result<(Vec<u8>, Report)> {
    let arch = match opts.arch {
        Some(a) => a,
        None => Arch::from_machine(elf.machine).ok_or_else(|| {
            Error::unsupported(format!(
                "cannot guess target architecture from e_machine={}; pass --arch",
                elf.machine
            ))
        })?,
    };
    arch.check_input_machine(elf.machine)?;

    let mut warnings: Vec<String> = Vec::new();

    if elf.has_interpreter() {
        return Err(Error::unsupported(
            "input has a PT_INTERP segment (dynamically linked ELF). 9front cannot load \
             ELF shared objects; build a static ELF with Zig instead",
        ));
    }
    if elf.has_needed_libraries() {
        return Err(Error::unsupported(
            "input has DT_NEEDED/DT_RUNPATH entries. A 9front a.out binary is completely \
             static; link with -lc-less / freestanding code only",
        ));
    }
    if elf.has_tls() && !opts.ignore_tls {
        warnings.push(
            "input uses ELF TLS; 9front has a different TLS ABI, so TLS variables will \
             not work (use --ignore-tls to silence this warning)"
                .to_string(),
        );
    }
    for ph in elf.phdrs.iter().filter(|p| p.p_type == 0x6474_e551) {
        if ph.flags & 1 != 0 {
            warnings.push(
                "PT_GNU_STACK requests an executable stack; 9front stacks are not executable"
                    .to_string(),
            );
        }
    }

    let (first, image_end) = elf.load_bounds()?;
    let split = elf
        .writable_segments()
        .map(|p| p.vaddr)
        .min()
        .unwrap_or(image_end);
    ensure!(
        split >= first,
        ErrorKind::Layout,
        "writable segment starts below the first load segment; image cannot be split"
    );
    let l = split - first;

    let header = arch.header_size();
    let text_start = arch.utzero() + header;
    let align = arch.data_align();

    let pad = match opts.base_override {
        Some(wanted) => {
            ensure!(
                wanted >= text_start,
                ErrorKind::Layout,
                "--base {:#x} is below the a.out text start {:#x}",
                wanted,
                text_start
            );
            let p = wanted - text_start;
            ensure!(
                p < align,
                ErrorKind::Layout,
                "--base {:#x} would need {:#x} bytes of padding, more than the {:#x} \
                 data alignment; choose a base congruent with the ELF data segment",
                wanted,
                p,
                align
            );
            p
        }
        None => {
            let residue = (l + arch.utzero() + header) % align;
            (align - residue) % align
        }
    };

    let x = text_start + pad;
    let bias_value = x as i128 - first as i128;
    ensure!(
        bias_value >= -(1i128 << 60) && bias_value <= (1i128 << 60),
        ErrorKind::Layout,
        "load bias {:#x} is too large to represent",
        bias_value
    );
    let bias = bias_value as i64;

    let data_vaddr = (split as i128 + bias_value) as u64;
    ensure!(
        data_vaddr % align == 0,
        ErrorKind::Layout,
        "internal error: computed data address {:#x} is not {:#x}-aligned",
        data_vaddr,
        align
    );

    let text_field = pad.saturating_add(l);
    ensure!(
        text_field <= u32::MAX as u64,
        ErrorKind::Layout,
        "text segment is too large for a 32-bit a.out header field"
    );
    ensure!(
        text_start + text_field <= arch.max_user_address(),
        ErrorKind::Layout,
        "text segment would end at {:#x}, above the kernel's user limit {:#x}",
        text_start + text_field,
        arch.max_user_address()
    );

    // Build the memory image in the original address space and apply all
    // static relocations there.
    let mut mem = Memory::from_load_segments(elf)?;
    for ph in elf.load_segments() {
        mem.load_segment(elf, ph)?;
    }
    let relocs = apply_relocations(elf, &mut mem, arch, bias)?;

    let patches = if opts.patch_abs && bias != 0 {
        Some(patch_absolute_addresses(elf, &mut mem, bias)?)
    } else {
        None
    };

    if elf.etype == ET_EXEC && bias != 0 && elf.relocs.is_empty() && !opts.patch_abs {
        return Err(Error::unsupported(format!(
            "this is a non-PIE ELF linked at {:#x} and the 9front layout requires it at \
             {:#x} (bias {:#x}); absolute addresses would be wrong. Rebuild Zig with \
             `-fPIE` (recommended), or use --patch-abs for a heuristic fixup, or link the \
             ELF so its first writable PT_LOAD lands at a {:#x}-aligned address",
            first, x, bias, align
        )));
    }

    let entry = match opts.entry_override {
        Some(e) => (e as i128 + bias_value) as u64,
        None => (elf.entry as i128 + bias_value) as u64,
    };
    ensure!(
        entry >= text_start,
        ErrorKind::Layout,
        "entry point {:#x} is below the start of text {:#x}",
        entry,
        text_start
    );
    ensure!(
        entry < text_start + text_field,
        ErrorKind::Layout,
        "entry point {:#x} is outside the text segment {:#x}..{:#x}; the 9front exec() \
         check would reject this binary",
        entry,
        text_start,
        text_start + text_field
    );

    // File-backed data begins at the first writable PT_LOAD.  Anything after
    // the file part of that segment is zero filled (both our padding and the
    // ELF's own .bss), so a single `data` + `bss` pair is enough.
    let mut data_end_file = split;
    let mut data_end_mem = split;
    for ph in elf.load_segments() {
        if ph.end_file() > split {
            data_end_file = data_end_file.max(ph.end_file());
        }
        if ph.end_vaddr() > split {
            data_end_mem = data_end_mem.max(ph.end_vaddr());
        }
    }
    let data_field = round_up(data_end_file - split, 4096)?;
    let bss_field = data_end_mem.saturating_sub(split.saturating_add(data_field));
    ensure!(
        data_field <= u32::MAX as u64 && bss_field <= u32::MAX as u64,
        ErrorKind::Layout,
        "data/bss are too large for 32-bit a.out header fields"
    );
    ensure!(
        data_field <= MAX_IMAGE_SPAN,
        ErrorKind::Layout,
        "data segment of {:#x} bytes is unreasonably large",
        data_field
    );

    // The a.out header occupies the first `header` bytes of the text
    // segment; the ELF image itself starts `pad` bytes later.  Translate that
    // back into the original ELF address space (it may become negative for a
    // PIE linked at vaddr 0, in which case the prefix is zero filled).
    let text_bytes = mem.extract_from_i128(first as i128 - pad as i128, text_field)?;
    let data_bytes = mem.extract(split, data_field)?;

    let symbols = if opts.symbols {
        emit_symbols(elf, bias, text_start, text_start + text_field, &mut warnings)?
    } else {
        Vec::new()
    };
    ensure!(
        symbols.len() <= u32::MAX as usize,
        ErrorKind::Layout,
        "symbol table is too large for a 32-bit a.out header field"
    );

    let mut out = Vec::with_capacity(
        (header as usize)
            .saturating_add(text_bytes.len())
            .saturating_add(data_bytes.len())
            .saturating_add(symbols.len()),
    );

    put_u32_be(&mut out, arch.magic());
    put_u32_be(&mut out, text_field as u32);
    put_u32_be(&mut out, data_field as u32);
    put_u32_be(&mut out, bss_field as u32);
    put_u32_be(&mut out, symbols.len() as u32);
    // For HDR_MAGIC binaries this 32-bit field is the *physical* entry;
    // 9front's own 6l writes PADDR(virtual entry) here.  The kernel ignores it
    // and uses the 64-bit value below.
    put_u32_be(&mut out, (entry & 0xffff_ffff) as u32);
    put_u32_be(&mut out, 0); // spsz: PC/SP table (68020 only)
    put_u32_be(&mut out, 0); // pcsz: PC/line table
    if arch.extended_header() {
        put_u64_be(&mut out, entry);
    }

    out.extend_from_slice(&text_bytes);
    out.extend_from_slice(&data_bytes);
    out.extend_from_slice(&symbols);

    if let Some(p) = &patches {
        warnings.extend(p.notes.iter().cloned());
    }
    warnings.extend(relocs.notes.iter().cloned());

    let report = Report {
        arch,
        bias,
        first_elf_vaddr: first,
        elf_start_vaddr: x,
        split_vaddr: split,
        pad,
        text_field,
        data_field,
        bss_field,
        entry,
        text_vaddr: text_start,
        data_vaddr,
        relocs,
        patches,
        warnings,
        output_size: out.len(),
    };
    Ok((out, report))
}

fn emit_symbols(
    elf: &ElfFile,
    bias: i64,
    text_start: u64,
    text_end: u64,
    warnings: &mut Vec<String>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for table in &elf.symbol_tables {
        for sym in table {
            if sym.name.is_empty() || sym.is_undefined() || sym.is_tls() {
                continue;
            }
            if matches!(sym.typ(), STT_SECTION | STT_FILE) {
                continue;
            }
            let value = if sym.is_absolute() {
                sym.value
            } else {
                (sym.value as i128 + bias as i128) as u64
            };
            let in_text = value >= text_start && value < text_end;
            let typ: u8 = match sym.typ() {
                STT_FUNC => if in_text { b'T' } else { b'D' },
                STT_OBJECT => {
                    if in_text {
                        b'D'
                    } else {
                        b'B'
                    }
                }
                STT_NOTYPE => if in_text { b'T' } else { b'D' },
                _ => continue,
            };
            put_u64_be(&mut out, value);
            out.push(typ | 0x80);
            out.extend_from_slice(sym.name.as_bytes());
            out.push(0);
            if out.len() > 8 * 1024 * 1024 {
                warnings.push("symbol table truncated at 8 MiB".to_string());
                break;
            }
        }
    }
    if out.is_empty() {
        warnings.push("--symbols was requested but the ELF has no usable symbol table".to_string());
    }
    let _ = PF_W;
    let _ = SHN_ABS;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_up_works() {
        assert_eq!(round_up(0x1234, 0x1000).unwrap(), 0x2000);
        assert_eq!(round_up(0x1000, 0x1000).unwrap(), 0x1000);
    }

    #[test]
    fn big_endian_header_fields() {
        let mut v = Vec::new();
        put_u32_be(&mut v, 0x8a97);
        put_u64_be(&mut v, 0x200028);
        assert_eq!(v, vec![0, 0, 0x8a, 0x97, 0, 0, 0, 0, 0, 0x20, 0, 0x28]);
    }
}
