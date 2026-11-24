//! elf2out: ELF -> 9front a.out converter for freestanding Zig binaries.

// Constants and helper methods that document the formats are intentionally
// kept even when a given conversion path does not need them.
#![allow(dead_code)]

mod arch;
mod cli;
mod elf;
#[macro_use]
mod error;
mod image;
mod patch;
mod plan9;
mod reloc;

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use error::{Error, Result};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("elf2out: {}", err);
            std::process::exit(1);
        }
    }
}

fn run(args: Vec<String>) -> Result<i32> {
    let parsed = cli::parse(args)?;
    if parsed.help {
        println!("{}", cli::help_text());
        return Ok(0);
    }
    if parsed.version {
        println!("elf2out {}", cli::VERSION);
        return Ok(0);
    }

    let input = parsed
        .input
        .clone()
        .ok_or_else(|| Error::usage(format!("missing input file\n\n{}", cli::help_text())))?;
    let output = parsed
        .output
        .clone()
        .unwrap_or_else(|| format!("{}.out", input));

    if parsed.dry_run && parsed.options.verbose {
        return Err(Error::usage("--dry-run and --verbose are mutually exclusive"));
    }

    if parsed.options.verbose {
        eprintln!("elf2out: reading {}", input);
    }
    let bytes = fs::read(&input).map_err(|e| {
        Error::io(format!("cannot read `{}`: {}", input, e))
    })?;
    let elf = elf::ElfFile::parse(bytes)?;
    let (out, report) = plan9::convert(&elf, &parsed.options)?;

    for warning in &report.warnings {
        eprintln!("elf2out: warning: {}", warning);
    }

    if parsed.options.verbose || parsed.dry_run {
        print_report(&report, &output, elf.etype);
    }

    if parsed.dry_run {
        return Ok(0);
    }

    write_output(Path::new(&output), &out)?;
    if parsed.options.verbose {
        eprintln!("elf2out: wrote {} bytes to {}", out.len(), output);
    }
    Ok(0)
}

fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    // Write atomically enough that a failed conversion never leaves a
    // half-baked executable behind.
    let tmp = path.with_extension(format!(
        "{}.elf2out.tmp",
        path.extension().and_then(|s| s.to_str()).unwrap_or("out")
    ));
    {
        let mut f = fs::File::create(&tmp).map_err(|e| {
            Error::io(format!("cannot create `{}`: {}", tmp.display(), e))
        })?;
        f.write_all(bytes)
            .and_then(|_| f.flush())
            .map_err(|e| Error::io(format!("cannot write `{}`: {}", tmp.display(), e)))?;
    }
    make_executable(&tmp);
    fs::rename(&tmp, path).map_err(|e| {
        Error::io(format!(
            "cannot rename `{}` to `{}`: {}",
            tmp.display(),
            path.display(),
            e
        ))
    })?;
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

fn print_report(report: &plan9::Report, output: &str, etype: u16) {
    let stdout = io::stdout();
    let mut w = stdout.lock();
    let _ = writeln!(w, "elf2out: conversion summary");
    let _ = writeln!(w, "  output          : {}", output);
    let _ = writeln!(
        w,
        "  target          : {} ({}, magic 0x{:08x})",
        report.arch.name(),
        report.arch.magic_name(),
        report.arch.magic()
    );
    let _ = writeln!(
        w,
        "  ELF type        : {}",
        if etype == elf::ET_DYN { "ET_DYN (PIE)" } else { "ET_EXEC" }
    );
    let _ = writeln!(w, "  ELF first vaddr : {:#x}", report.first_elf_vaddr);
    let _ = writeln!(w, "  ELF placed at   : {:#x}", report.elf_start_vaddr);
    let _ = writeln!(w, "  data split      : {:#x}", report.split_vaddr);
    let _ = writeln!(w, "  load bias       : {:#x}", report.bias);
    let _ = writeln!(w, "  prefix padding  : {:#x} bytes", report.pad);
    let _ = writeln!(
        w,
        "  text            : vaddr {:#x}, size {:#x}",
        report.text_vaddr, report.text_field
    );
    let _ = writeln!(
        w,
        "  data            : vaddr {:#x}, size {:#x}",
        report.data_vaddr, report.data_field
    );
    let _ = writeln!(w, "  bss             : size {:#x}", report.bss_field);
    let _ = writeln!(w, "  entry           : {:#x}", report.entry);
    let _ = writeln!(
        w,
        "  relocations     : {} applied ({} relative), {} ignored",
        report.relocs.applied, report.relocs.relative, report.relocs.ignored
    );
    if let Some(patch) = &report.patches {
        let _ = writeln!(w, "  absolute fixups : {}", patch.patched);
    }
    let _ = writeln!(w, "  output size     : {} bytes", report.output_size);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_and_version_do_not_need_a_file() {
        assert_eq!(run(vec!["--help".into()]).unwrap(), 0);
        assert_eq!(run(vec!["--version".into()]).unwrap(), 0);
    }

    #[test]
    fn missing_input_is_an_error() {
        assert!(run(vec![]).is_err());
    }

    /// Assemble a tiny ET_DYN ELF64 with one R/X and one RW PT_LOAD.
    fn minimal_pie_elf() -> Vec<u8> {
        fn put16(b: &mut [u8], off: usize, v: u16) {
            b[off..off + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn put32(b: &mut [u8], off: usize, v: u32) {
            b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn put64(b: &mut [u8], off: usize, v: u64) {
            b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        let mut b = vec![0u8; 0x300];
        b[0..4].copy_from_slice(&elf::ELFMAG);
        b[4] = elf::ELFCLASS64;
        b[5] = elf::ELFDATA2LSB;
        b[6] = 1;
        put16(&mut b, 16, elf::ET_DYN);
        put16(&mut b, 18, crate::arch::EM_X86_64);
        put32(&mut b, 20, 1);
        put64(&mut b, 24, 0x80); // entry
        put64(&mut b, 32, 64); // phoff
        put16(&mut b, 52, 64);
        put16(&mut b, 54, 56);
        put16(&mut b, 56, 2);
        // PT_LOAD #0: file 0x100, vaddr 0, R+X, 0x100 bytes.
        put32(&mut b, 64, elf::PT_LOAD);
        put32(&mut b, 68, elf::PF_R | elf::PF_X);
        put64(&mut b, 72, 0x100);
        put64(&mut b, 80, 0);
        put64(&mut b, 96, 0x100);
        put64(&mut b, 104, 0x100);
        put64(&mut b, 112, 0x1000);
        // PT_LOAD #1: file 0x200, vaddr 0x2000, RW, 0x10 file / 0x20 mem.
        put32(&mut b, 64 + 56, elf::PT_LOAD);
        put32(&mut b, 68 + 56, elf::PF_R | elf::PF_W);
        put64(&mut b, 72 + 56, 0x200);
        put64(&mut b, 80 + 56, 0x2000);
        put64(&mut b, 96 + 56, 0x10);
        put64(&mut b, 104 + 56, 0x20);
        put64(&mut b, 112 + 56, 0x200);
        // Synthetic program and data.
        for i in 0..0x100 {
            b[0x100 + i] = i as u8;
        }
        for i in 0..0x10 {
            b[0x200 + i] = 0xa0 + i as u8;
        }
        b
    }

    #[test]
    fn end_to_end_pie_conversion() {
        let bytes = minimal_pie_elf();
        let elf = elf::ElfFile::parse(bytes).unwrap();
        let opts = plan9::ConvertOptions {
            arch: Some(arch::Arch::Amd64),
            ignore_tls: true,
            ..Default::default()
        };
        let (out, report) = plan9::convert(&elf, &opts).unwrap();

        assert_eq!(report.arch, arch::Arch::Amd64);
        assert_eq!(report.first_elf_vaddr, 0);
        assert_eq!(report.split_vaddr, 0x2000);
        assert_eq!(report.elf_start_vaddr, 0x3fe000);
        assert_eq!(report.data_vaddr, 0x400000);
        assert_eq!(report.entry, 0x80 + 0x3fe000);
        assert_eq!(report.text_field, 0x1fffd8);
        assert_eq!(report.data_field, 0x1000);
        assert_eq!(report.bss_field, 0);

        let header: Vec<u32> = out[0..32]
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert_eq!(header[0], arch::Arch::Amd64.magic());
        assert_eq!(header[1] as u64, report.text_field);
        assert_eq!(header[2] as u64, report.data_field);
        assert_eq!(header[3] as u64, report.bss_field);
        assert_eq!(header[5] as u64, report.entry & 0xffff_ffff);
        let entry64 = u64::from_be_bytes(out[32..40].try_into().unwrap());
        assert_eq!(entry64, report.entry);
        assert_eq!(out.len(), 40 + report.text_field as usize + 0x1000);

        // First ELF byte must be exactly at 40 + pad.
        let elf_offset = 40 + report.pad as usize;
        assert_eq!(&out[elf_offset..elf_offset + 8], &[0, 1, 2, 3, 4, 5, 6, 7]);
        // Data starts immediately after the header + text.
        assert_eq!(&out[40 + report.text_field as usize..][..16], &[
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
            0xad, 0xae, 0xaf,
        ]);
    }

    #[test]
    fn write_output_creates_executable_file() {
        let dir = std::env::temp_dir().join(format!("elf2out-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("a.out");
        write_output(&path, b"hello").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }
}
