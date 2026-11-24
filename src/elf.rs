//! Minimal, dependency-free ELF32/ELF64 reader.
//!
//! Only the pieces needed for a static ELF -> Plan 9 a.out conversion are
//! implemented: the ELF header, program headers, section headers, symbol
//! tables and dynamic relocations.  There is deliberately no support for
//! dynamic linking: 9front does not have an ELF loader, and it certainly does
//! not have an ld.so that could satisfy `DT_NEEDED`.

use crate::bail;
use crate::ensure;
use crate::error::{Error, ErrorKind, Result};

pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_TLS: u8 = 6;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_XINDEX: u16 = 0xffff;
pub const PN_XNUM: u16 = 0xffff;

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_JMPREL: i64 = 23;
pub const DT_TEXTREL: i64 = 22;
pub const DT_RUNPATH: i64 = 29;
pub const DT_GNU_HASH: i64 = 0x6fff_ffef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phdr {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl Phdr {
    pub fn is_load(&self) -> bool {
        self.p_type == PT_LOAD && self.memsz != 0
    }

    pub fn end_vaddr(&self) -> u64 {
        self.vaddr.saturating_add(self.memsz)
    }

    pub fn end_file(&self) -> u64 {
        self.vaddr.saturating_add(self.filesz)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shdr {
    pub name: u32,
    pub typ: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
    pub name_string: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

impl Symbol {
    pub fn bind(&self) -> u8 {
        self.info >> 4
    }

    pub fn typ(&self) -> u8 {
        self.info & 0xf
    }

    pub fn is_undefined(&self) -> bool {
        self.shndx == SHN_UNDEF
    }

    pub fn is_absolute(&self) -> bool {
        self.shndx == SHN_ABS
    }

    pub fn is_tls(&self) -> bool {
        self.typ() == STT_TLS
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    pub offset: u64,
    pub typ: u32,
    pub sym: u32,
    pub addend: i64,
    pub symtab: usize,
    pub is_rela: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynEntry {
    pub tag: i64,
    pub val: u64,
}

#[derive(Debug, Clone)]
pub struct ElfFile {
    pub data: Vec<u8>,
    pub is_64: bool,
    pub little: bool,
    pub etype: u16,
    pub machine: u16,
    pub version: u32,
    pub flags: u32,
    pub entry: u64,
    pub phdrs: Vec<Phdr>,
    pub shdrs: Vec<Shdr>,
    pub symbol_tables: Vec<Vec<Symbol>>,
    /// Maps section index -> index inside `symbol_tables`, for symbol tables.
    pub section_symtab: Vec<Option<usize>>,
    pub relocs: Vec<Reloc>,
    pub dynamic: Vec<DynEntry>,
}

impl ElfFile {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        ensure!(data.len() >= 52, ErrorKind::Format, "file is too small to be ELF");
        ensure!(data[0..4] == ELFMAG, ErrorKind::Format, "not an ELF file (bad magic)");

        let class = data[4];
        let encoding = data[5];
        let is_64 = match class {
            ELFCLASS64 => true,
            ELFCLASS32 => false,
            other => bail!(ErrorKind::Format, "unsupported ELF class {}", other),
        };
        let little = match encoding {
            ELFDATA2LSB => true,
            ELFDATA2MSB => false,
            other => bail!(ErrorKind::Format, "unsupported ELF data encoding {}", other),
        };
        ensure!(data[6] == 1, ErrorKind::Format, "unsupported ELF ident version {}", data[6]);
        ensure!(data.len() >= if is_64 { 64 } else { 52 }, ErrorKind::Format, "truncated ELF header");

        let (etype, machine, version, entry, phoff, shoff, flags, phentsize, phnum, shentsize, shnum, shstrndx) =
            if is_64 {
                (
                    get_u16(&data, 16, little)?,
                    get_u16(&data, 18, little)?,
                    get_u32(&data, 20, little)?,
                    get_u64(&data, 24, little)?,
                    get_u64(&data, 32, little)?,
                    get_u64(&data, 40, little)?,
                    get_u32(&data, 48, little)?,
                    get_u16(&data, 54, little)? as usize,
                    get_u16(&data, 56, little)?,
                    get_u16(&data, 58, little)? as usize,
                    get_u16(&data, 60, little)?,
                    get_u16(&data, 62, little)?,
                )
            } else {
                (
                    get_u16(&data, 16, little)?,
                    get_u16(&data, 18, little)?,
                    get_u32(&data, 20, little)?,
                    get_u32(&data, 24, little)? as u64,
                    get_u32(&data, 28, little)? as u64,
                    get_u32(&data, 32, little)? as u64,
                    get_u32(&data, 36, little)?,
                    get_u16(&data, 42, little)? as usize,
                    get_u16(&data, 44, little)?,
                    get_u16(&data, 46, little)? as usize,
                    get_u16(&data, 48, little)?,
                    get_u16(&data, 50, little)?,
                )
            };

        ensure!(version >= 1, ErrorKind::Format, "bad ELF version {}", version);
        ensure!(
            etype == ET_EXEC || etype == ET_DYN,
            ErrorKind::Unsupported,
            "expected an ELF executable (ET_EXEC or ET_DYN), got e_type={}; \
             compile Zig with `zig build-exe`, not `zig build-obj`",
            etype
        );

        let mut elf = Self {
            data,
            is_64,
            little,
            etype,
            machine,
            version,
            flags,
            entry,
            phdrs: Vec::new(),
            shdrs: Vec::new(),
            symbol_tables: Vec::new(),
            section_symtab: Vec::new(),
            relocs: Vec::new(),
            dynamic: Vec::new(),
        };

        // Extended section/program-header counts live in section 0.
        let mut shnum = shnum as usize;
        let mut shstrndx = shstrndx as usize;
        let mut phnum = phnum as usize;

        // Parse the raw section headers first (names are filled in later).
        if shoff != 0 && shnum != 0 {
            let min_shentsize = if is_64 { 64 } else { 40 };
            ensure!(
                shentsize >= min_shentsize,
                ErrorKind::Format,
                "bad e_shentsize={} (expected at least {})",
                shentsize,
                min_shentsize
            );
            ensure!(
                shoff.saturating_add((shnum as u64).saturating_mul(shentsize as u64)) <= elf.data.len() as u64,
                ErrorKind::Format,
                "section header table extends past end of file"
            );
        }

        if shoff != 0 {
            // Read section zero to resolve SHN_XINDEX / PN_XNUM if needed.
            let zero = elf.parse_shdr_at(shoff)?;
            if phnum == PN_XNUM as usize {
                phnum = zero.info as usize;
            }
            if shnum == 0 {
                shnum = zero.size as usize;
            }
            if shstrndx == SHN_XINDEX as usize {
                shstrndx = zero.link as usize;
            }
        }

        let min_phentsize = if is_64 { 56 } else { 32 };
        if phnum != 0 {
            ensure!(phoff != 0, ErrorKind::Format, "e_phnum != 0 but e_phoff == 0");
            ensure!(
                phentsize >= min_phentsize,
                ErrorKind::Format,
                "bad e_phentsize={} (expected at least {})",
                phentsize,
                min_phentsize
            );
            ensure!(
                phoff.saturating_add((phnum as u64).saturating_mul(phentsize as u64)) <= elf.data.len() as u64,
                ErrorKind::Format,
                "program header table extends past end of file"
            );
            for i in 0..phnum {
                let off = phoff + (i as u64) * (phentsize as u64);
                elf.phdrs.push(elf.parse_phdr_at(off)?);
            }
        }

        if shoff != 0 && shnum != 0 {
            for i in 0..shnum {
                let off = shoff + (i as u64) * (shentsize as u64);
                elf.shdrs.push(elf.parse_shdr_at(off)?);
            }
            if shstrndx != 0 && shstrndx < elf.shdrs.len() {
                let strtab = elf.shdrs[shstrndx].clone();
                let names: Vec<String> = elf
                    .shdrs
                    .iter()
                    .map(|s| elf.string_at(&strtab, s.name).unwrap_or_default())
                    .collect();
                for (i, name) in names.into_iter().enumerate() {
                    elf.shdrs[i].name_string = name;
                }
            }
        }

        elf.validate_phdrs()?;
        elf.parse_symbol_tables()?;
        elf.parse_dynamic()?;
        elf.parse_section_relocs()?;
        elf.parse_dynamic_relocs()?;
        elf.dedupe_relocs();

        Ok(elf)
    }

    fn parse_phdr_at(&self, off: u64) -> Result<Phdr> {
        let off = off as usize;
        if self.is_64 {
            Ok(Phdr {
                p_type: get_u32(&self.data, off, self.little)?,
                flags: get_u32(&self.data, off + 4, self.little)?,
                offset: get_u64(&self.data, off + 8, self.little)?,
                vaddr: get_u64(&self.data, off + 16, self.little)?,
                paddr: get_u64(&self.data, off + 24, self.little)?,
                filesz: get_u64(&self.data, off + 32, self.little)?,
                memsz: get_u64(&self.data, off + 40, self.little)?,
                align: get_u64(&self.data, off + 48, self.little)?,
            })
        } else {
            Ok(Phdr {
                p_type: get_u32(&self.data, off, self.little)?,
                offset: get_u32(&self.data, off + 4, self.little)? as u64,
                vaddr: get_u32(&self.data, off + 8, self.little)? as u64,
                paddr: get_u32(&self.data, off + 12, self.little)? as u64,
                filesz: get_u32(&self.data, off + 16, self.little)? as u64,
                memsz: get_u32(&self.data, off + 20, self.little)? as u64,
                flags: get_u32(&self.data, off + 24, self.little)?,
                align: get_u32(&self.data, off + 28, self.little)? as u64,
            })
        }
    }

    fn parse_shdr_at(&self, off: u64) -> Result<Shdr> {
        let off = off as usize;
        if self.is_64 {
            Ok(Shdr {
                name: get_u32(&self.data, off, self.little)?,
                typ: get_u32(&self.data, off + 4, self.little)?,
                flags: get_u64(&self.data, off + 8, self.little)?,
                addr: get_u64(&self.data, off + 16, self.little)?,
                offset: get_u64(&self.data, off + 24, self.little)?,
                size: get_u64(&self.data, off + 32, self.little)?,
                link: get_u32(&self.data, off + 40, self.little)?,
                info: get_u32(&self.data, off + 44, self.little)?,
                addralign: get_u64(&self.data, off + 48, self.little)?,
                entsize: get_u64(&self.data, off + 56, self.little)?,
                name_string: String::new(),
            })
        } else {
            Ok(Shdr {
                name: get_u32(&self.data, off, self.little)?,
                typ: get_u32(&self.data, off + 4, self.little)?,
                flags: get_u32(&self.data, off + 8, self.little)? as u64,
                addr: get_u32(&self.data, off + 12, self.little)? as u64,
                offset: get_u32(&self.data, off + 16, self.little)? as u64,
                size: get_u32(&self.data, off + 20, self.little)? as u64,
                link: get_u32(&self.data, off + 24, self.little)?,
                info: get_u32(&self.data, off + 28, self.little)?,
                addralign: get_u32(&self.data, off + 32, self.little)? as u64,
                entsize: get_u32(&self.data, off + 36, self.little)? as u64,
                name_string: String::new(),
            })
        }
    }

    fn validate_phdrs(&self) -> Result<()> {
        for ph in &self.phdrs {
            if ph.p_type != PT_LOAD {
                continue;
            }
            ensure!(
                ph.filesz <= ph.memsz,
                ErrorKind::Format,
                "PT_LOAD at {:#x} has p_filesz > p_memsz",
                ph.vaddr
            );
            ensure!(
                ph.offset.saturating_add(ph.filesz) <= self.data.len() as u64,
                ErrorKind::Format,
                "PT_LOAD at {:#x} extends past end of file",
                ph.vaddr
            );
            ensure!(
                ph.vaddr.saturating_add(ph.memsz) < (1u64 << 63),
                ErrorKind::Format,
                "PT_LOAD at {:#x} has unreasonable size",
                ph.vaddr
            );
            if ph.align > 1 {
                ensure!(
                    (ph.vaddr.saturating_sub(ph.offset)) % ph.align == 0,
                    ErrorKind::Format,
                    "PT_LOAD at {:#x} is not congruent with its file offset modulo p_align",
                    ph.vaddr
                );
            }
        }
        Ok(())
    }

    pub fn load_segments(&self) -> impl Iterator<Item = &Phdr> {
        self.phdrs.iter().filter(|p| p.is_load())
    }

    pub fn writable_segments(&self) -> impl Iterator<Item = &Phdr> {
        self.phdrs.iter().filter(|p| p.is_load() && (p.flags & PF_W) != 0)
    }

    pub fn segment_for_vaddr(&self, vaddr: u64, size: u64) -> Option<&Phdr> {
        self.load_segments()
            .find(|p| vaddr >= p.vaddr && vaddr.saturating_add(size) <= p.end_vaddr())
    }

    pub fn vaddr_to_file_offset(&self, vaddr: u64, size: u64) -> Result<u64> {
        match self.segment_for_vaddr(vaddr, size) {
            Some(ph) => Ok(ph.offset + (vaddr - ph.vaddr)),
            None => bail!(
                ErrorKind::Format,
                "virtual address {:#x} (+{:#x}) is not inside a PT_LOAD segment",
                vaddr,
                size
            ),
        }
    }

    pub fn section_data(&self, shdr: &Shdr) -> Result<&[u8]> {
        if shdr.typ == SHT_NOBITS || shdr.typ == SHT_NULL {
            return Ok(&[]);
        }
        let start = shdr.offset as usize;
        let end = start.checked_add(shdr.size as usize).ok_or_else(|| {
            Error::format("section size overflow")
        })?;
        ensure!(
            end <= self.data.len(),
            ErrorKind::Format,
            "section `{}` extends past end of file",
            shdr.name_string
        );
        Ok(&self.data[start..end])
    }

    pub fn string_at(&self, strtab: &Shdr, index: u32) -> Result<String> {
        let bytes = self.section_data(strtab)?;
        let start = index as usize;
        ensure!(
            start < bytes.len(),
            ErrorKind::Format,
            "string table index {} out of range",
            index
        );
        let tail = &bytes[start..];
        let nul = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
        Ok(String::from_utf8_lossy(&tail[..nul]).into_owned())
    }

    fn parse_symbol_tables(&mut self) -> Result<()> {
        let shdrs = self.shdrs.clone();
        self.section_symtab = vec![None; shdrs.len()];
        for (i, shdr) in shdrs.iter().enumerate() {
            if shdr.typ != SHT_SYMTAB && shdr.typ != SHT_DYNSYM {
                continue;
            }
            let entsize = if shdr.entsize != 0 {
                shdr.entsize as usize
            } else if self.is_64 {
                24
            } else {
                16
            };
            let min = if self.is_64 { 24 } else { 16 };
            ensure!(
                entsize >= min,
                ErrorKind::Format,
                "symbol table `{}` has bad sh_entsize={}",
                shdr.name_string,
                entsize
            );
            ensure!(
                (shdr.link as usize) < shdrs.len(),
                ErrorKind::Format,
                "symbol table `{}` has invalid sh_link",
                shdr.name_string
            );
            let strtab = shdrs[shdr.link as usize].clone();
            let bytes = self.section_data(shdr).unwrap_or(&[][..]).to_vec();
            let mut table = Vec::new();
            let mut off = 0usize;
            while off + min <= bytes.len() {
                let (name_idx, value, size, info, other, shndx) = if self.is_64 {
                    (
                        get_u32(&bytes, off, self.little)?,
                        get_u64(&bytes, off + 8, self.little)?,
                        get_u64(&bytes, off + 16, self.little)?,
                        bytes[off + 4],
                        bytes[off + 5],
                        get_u16(&bytes, off + 6, self.little)?,
                    )
                } else {
                    (
                        get_u32(&bytes, off, self.little)?,
                        get_u32(&bytes, off + 4, self.little)? as u64,
                        get_u32(&bytes, off + 8, self.little)? as u64,
                        bytes[off + 12],
                        bytes[off + 13],
                        get_u16(&bytes, off + 14, self.little)?,
                    )
                };
                let name = self.string_at(&strtab, name_idx).unwrap_or_default();
                table.push(Symbol {
                    name,
                    value,
                    size,
                    info,
                    other,
                    shndx,
                });
                off += entsize;
            }
            self.section_symtab[i] = Some(self.symbol_tables.len());
            self.symbol_tables.push(table);
        }
        Ok(())
    }

    fn parse_dynamic(&mut self) -> Result<()> {
        let phdrs = self.phdrs.clone();
        for ph in phdrs.iter().filter(|p| p.p_type == PT_DYNAMIC) {
            let entsize: usize = if self.is_64 { 16 } else { 8 };
            ensure!(
                ph.offset.saturating_add(ph.filesz) <= self.data.len() as u64,
                ErrorKind::Format,
                "PT_DYNAMIC extends past end of file"
            );
            let mut off = ph.offset as usize;
            let end = (ph.offset + ph.filesz) as usize;
            while off + entsize <= end {
                if self.is_64 {
                    let tag = get_u64(&self.data, off, self.little)? as i64;
                    let val = get_u64(&self.data, off + 8, self.little)?;
                    if tag == DT_NULL {
                        break;
                    }
                    self.dynamic.push(DynEntry { tag, val });
                } else {
                    let tag = get_u32(&self.data, off, self.little)? as i32 as i64;
                    let val = get_u32(&self.data, off + 4, self.little)? as u64;
                    if tag == DT_NULL {
                        break;
                    }
                    self.dynamic.push(DynEntry { tag, val });
                }
                off += entsize;
            }
        }
        Ok(())
    }

    pub fn dyn_value(&self, tag: i64) -> Option<u64> {
        self.dynamic.iter().find(|d| d.tag == tag).map(|d| d.val)
    }

    pub fn has_needed_libraries(&self) -> bool {
        self.dynamic.iter().any(|d| d.tag == DT_NEEDED || d.tag == DT_RUNPATH)
    }

    fn parse_section_relocs(&mut self) -> Result<()> {
        let shdrs = self.shdrs.clone();
        for (idx, shdr) in shdrs.iter().enumerate() {
            if shdr.typ != SHT_RELA && shdr.typ != SHT_REL {
                continue;
            }
            // Debug/.eh_frame relocations are normally already applied by the
            // linker and re-applying them would corrupt the image.  They are
            // useless for a 9front executable anyway.
            let name = shdr.name_string.as_str();
            if name.starts_with(".rela.debug")
                || name.starts_with(".rel.debug")
                || name.starts_with(".rela.eh_frame")
                || name.starts_with(".rel.eh_frame")
                || name.starts_with(".rela.note")
            {
                continue;
            }
            // Only relocations that target loaded sections matter.
            if !self.section_is_loaded(shdr.info as usize) {
                continue;
            }
            let symtab = self.section_symtab.get(shdr.link as usize).copied().flatten();
            let symtab = match symtab {
                Some(s) => s,
                None => {
                    // Dynamic relocation sections occasionally point at a
                    // stripped symtab; fall back to .dynsym.
                    match self
                        .shdrs
                        .iter()
                        .position(|s| s.typ == SHT_DYNSYM)
                        .and_then(|i| self.section_symtab[i])
                    {
                        Some(s) => s,
                        None => {
                            // Relative relocations need no symbols at all.
                            let only_relative = self.relocs_are_all_relative(shdr, idx)?;
                            if !only_relative {
                                continue;
                            }
                            self.symbol_tables.push(Vec::new());
                            self.symbol_tables.len() - 1
                        }
                    }
                }
            };
            self.parse_reloc_table(shdr, symtab)?;
        }
        Ok(())
    }

    fn section_is_loaded(&self, section_index: usize) -> bool {
        if section_index == 0 || section_index >= self.shdrs.len() {
            return false;
        }
        let target = &self.shdrs[section_index];
        self.phdrs.iter().any(|p| {
            p.is_load()
                && target.addr >= p.vaddr
                && target.addr.saturating_add(target.size) <= p.end_vaddr()
        })
    }

    fn relocs_are_all_relative(&self, shdr: &Shdr, _section_index: usize) -> Result<bool> {
        let bytes = self.section_data(shdr)?;
        let entsize = if shdr.entsize != 0 {
            shdr.entsize as usize
        } else if shdr.typ == SHT_RELA {
            if self.is_64 { 24 } else { 12 }
        } else if self.is_64 {
            16
        } else {
            8
        };
        if entsize == 0 {
            return Ok(false);
        }
        let mut off = 0usize;
        while off + 8 <= bytes.len() {
            let typ = if self.is_64 {
                (get_u64(bytes, off + 8, self.little)? & 0xffff_ffff) as u32
            } else {
                get_u32(bytes, off + 4, self.little)? & 0xff
            };
            if !crate::reloc::is_relative_type(self.machine, typ) {
                return Ok(false);
            }
            off += entsize;
        }
        Ok(true)
    }

    fn parse_dynamic_relocs(&mut self) -> Result<()> {
        if self.dynamic.is_empty() {
            return Ok(());
        }
        let dynsym_index = self
            .shdrs
            .iter()
            .position(|s| s.typ == SHT_DYNSYM)
            .and_then(|i| self.section_symtab[i]);
        let dynsym = match dynsym_index {
            Some(i) => i,
            None => {
                // Synthesise an empty table: RELATIVE relocations do not need
                // one, and any symbol-based relocation will report a clear
                // error later.
                self.symbol_tables.push(Vec::new());
                self.symbol_tables.len() - 1
            }
        };

        let (rela_addr, rela_size, rela_ent) = (
            self.dyn_value(DT_RELA),
            self.dyn_value(DT_RELASZ).unwrap_or(0),
            self.dyn_value(DT_RELAENT).unwrap_or(if self.is_64 { 24 } else { 12 }),
        );
        if let Some(addr) = rela_addr {
            if rela_size != 0 {
                let offset = self.vaddr_to_file_offset(addr, rela_size)?;
                let shdr = Shdr {
                    name: 0,
                    typ: SHT_RELA,
                    flags: 0,
                    addr,
                    offset,
                    size: rela_size,
                    link: 0,
                    info: 0,
                    addralign: 1,
                    entsize: rela_ent,
                    name_string: ".rela.dyn".to_string(),
                };
                self.parse_reloc_table(&shdr, dynsym)?;
            }
        }

        let (rel_addr, rel_size, rel_ent) = (
            self.dyn_value(DT_REL),
            self.dyn_value(DT_RELSZ).unwrap_or(0),
            self.dyn_value(DT_RELENT).unwrap_or(if self.is_64 { 16 } else { 8 }),
        );
        if let Some(addr) = rel_addr {
            if rel_size != 0 {
                let offset = self.vaddr_to_file_offset(addr, rel_size)?;
                let shdr = Shdr {
                    name: 0,
                    typ: SHT_REL,
                    flags: 0,
                    addr,
                    offset,
                    size: rel_size,
                    link: 0,
                    info: 0,
                    addralign: 1,
                    entsize: rel_ent,
                    name_string: ".rel.dyn".to_string(),
                };
                self.parse_reloc_table(&shdr, dynsym)?;
            }
        }

        let pltrel_size = self.dyn_value(DT_PLTRELSZ).unwrap_or(0);
        if let Some(addr) = self.dyn_value(DT_JMPREL) {
            if pltrel_size != 0 {
                let is_rela = self.dyn_value(DT_PLTREL) == Some(DT_RELA as u64);
                let offset = self.vaddr_to_file_offset(addr, pltrel_size)?;
                let shdr = Shdr {
                    name: 0,
                    typ: if is_rela { SHT_RELA } else { SHT_REL },
                    flags: 0,
                    addr,
                    offset,
                    size: pltrel_size,
                    link: 0,
                    info: 0,
                    addralign: 1,
                    entsize: if is_rela {
                        if self.is_64 { 24 } else { 12 }
                    } else if self.is_64 {
                        16
                    } else {
                        8
                    },
                    name_string: ".rela.plt".to_string(),
                };
                self.parse_reloc_table(&shdr, dynsym)?;
            }
        }
        Ok(())
    }

    fn parse_reloc_table(&mut self, shdr: &Shdr, symtab: usize) -> Result<()> {
        let bytes = self.section_data(shdr)?.to_vec();
        let default_ent = if shdr.typ == SHT_RELA {
            if self.is_64 { 24 } else { 12 }
        } else if self.is_64 {
            16
        } else {
            8
        };
        let entsize = if shdr.entsize != 0 {
            shdr.entsize as usize
        } else {
            default_ent
        };
        ensure!(
            entsize >= default_ent,
            ErrorKind::Format,
            "relocation section `{}` has bad sh_entsize={}",
            shdr.name_string,
            entsize
        );
        let is_rela = shdr.typ == SHT_RELA;
        let mut off = 0usize;
        while off + default_ent <= bytes.len() {
            let (offset, info, addend) = if self.is_64 {
                (
                    get_u64(&bytes, off, self.little)?,
                    get_u64(&bytes, off + 8, self.little)?,
                    if is_rela {
                        get_u64(&bytes, off + 16, self.little)? as i64
                    } else {
                        0
                    },
                )
            } else {
                (
                    get_u32(&bytes, off, self.little)? as u64,
                    get_u32(&bytes, off + 4, self.little)? as u64,
                    if is_rela {
                        get_u32(&bytes, off + 8, self.little)? as i32 as i64
                    } else {
                        0
                    },
                )
            };
            let (sym, typ) = if self.is_64 {
                ((info >> 32) as u32, (info & 0xffff_ffff) as u32)
            } else {
                ((info >> 8) as u32, (info & 0xff) as u32)
            };
            self.relocs.push(Reloc {
                offset,
                typ,
                sym,
                addend,
                symtab,
                is_rela,
            });
            off += entsize;
        }
        Ok(())
    }

    fn dedupe_relocs(&mut self) {
        // Section headers and PT_DYNAMIC describe the same relocation table
        // twice in a normal PIE.  Applying it twice would add the load bias
        // twice, which is a particularly nasty class of bug.
        let mut seen = std::collections::HashSet::new();
        self.relocs.retain(|r| {
            let key = (r.offset, r.typ, r.sym, r.addend, r.is_rela);
            seen.insert(key)
        });
    }

    pub fn symbol(&self, table: usize, index: u32) -> Result<&Symbol> {
        let table = self
            .symbol_tables
            .get(table)
            .ok_or_else(|| Error::format("relocation refers to a missing symbol table"))?;
        table
            .get(index as usize)
            .ok_or_else(|| Error::format(format!("symbol index {} out of range", index)))
    }

    pub fn has_tls(&self) -> bool {
        self.phdrs
            .iter()
            .any(|p| p.p_type == PT_TLS && p.memsz != 0)
            || self.symbol_tables.iter().flatten().any(|s| s.is_tls())
    }

    pub fn has_interpreter(&self) -> bool {
        self.phdrs.iter().any(|p| p.p_type == PT_INTERP)
    }

    pub fn load_bounds(&self) -> Result<(u64, u64)> {
        let mut loads = self.load_segments();
        let first = loads
            .next()
            .ok_or_else(|| Error::format("ELF has no PT_LOAD segments"))?;
        let mut min = first.vaddr;
        let mut max = first.end_vaddr();
        for ph in loads {
            min = min.min(ph.vaddr);
            max = max.max(ph.end_vaddr());
        }
        Ok((min, max))
    }
}

fn slice_at(data: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    data.get(off..off.saturating_add(len))
        .ok_or_else(|| Error::format(format!("unexpected end of file at offset {:#x}", off)))
}

pub fn get_u16(data: &[u8], off: usize, little: bool) -> Result<u16> {
    let b = slice_at(data, off, 2)?;
    Ok(if little {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}

pub fn get_u32(data: &[u8], off: usize, little: bool) -> Result<u32> {
    let b = slice_at(data, off, 4)?;
    Ok(if little {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}

pub fn get_u64(data: &[u8], off: usize, little: bool) -> Result<u64> {
    let b = slice_at(data, off, 8)?;
    Ok(if little {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny ET_EXEC ELF64 with a single R/X PT_LOAD and no sections.
    fn tiny_elf() -> Vec<u8> {
        let mut b = vec![0u8; 0x2000];
        b[0..4].copy_from_slice(&ELFMAG);
        b[4] = ELFCLASS64;
        b[5] = ELFDATA2LSB;
        b[6] = 1;
        b[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        b[18..20].copy_from_slice(&crate::arch::EM_X86_64.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // e_entry
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        // PT_LOAD covering the whole file at vaddr 0x400000.
        let p = 64;
        b[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
        b[p + 16..p + 24].copy_from_slice(&0x400000u64.to_le_bytes());
        b[p + 32..p + 40].copy_from_slice(&0x1000u64.to_le_bytes());
        b[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        b[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    #[test]
    fn parses_minimal_elf() {
        let elf = ElfFile::parse(tiny_elf()).unwrap();
        assert!(elf.is_64);
        assert!(elf.little);
        assert_eq!(elf.entry, 0x401000);
        assert_eq!(elf.phdrs.len(), 1);
        assert_eq!(elf.load_bounds().unwrap(), (0x400000, 0x401000));
        assert_eq!(elf.vaddr_to_file_offset(0x400100, 4).unwrap(), 0x100);
    }

    #[test]
    fn rejects_non_elf() {
        let mut b = vec![0u8; 128];
        b[0] = 0;
        assert!(ElfFile::parse(b).is_err());
    }

    #[test]
    fn getters_honor_endianness() {
        let b = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        assert_eq!(get_u16(&b, 0, true).unwrap(), 0x3412);
        assert_eq!(get_u16(&b, 0, false).unwrap(), 0x1234);
        assert_eq!(get_u32(&b, 0, true).unwrap(), 0x7856_3412);
        assert_eq!(get_u64(&b, 0, false).unwrap(), 0x1234_5678_9abc_def0);
    }
}
