//! Architecture descriptions for the 9front a.out format.
//!
//! The numbers in this file are taken from 9front's
//! `sys/include/a.out.h`, `sys/src/9/pc64/mem.h`,
//! `sys/src/9/arm64/mem.h`, `sys/src/9/pc/mem.h` and
//! `sys/src/cmd/6l/obj.c`:

use crate::error::{Error, Result};

/// ELF e_machine values we understand.
pub const EM_386: u16 = 3;
pub const EM_ARM: u16 = 40;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

/// `HDR_MAGIC` from a.out.h: the header has an additional 64-bit entry.
pub const HDR_MAGIC: u32 = 0x0000_8000;

/// Compute one of the classic Plan 9 magic numbers.
///
/// `_MAGIC(f, b) = f | (((4 * b) + 0) * b + 7)`.
pub const fn magic(flags: u32, b: u32) -> u32 {
    flags | ((4 * b) * b + 7)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// amd64 (`S_MAGIC`, fat header, 2 MiB data alignment).
    Amd64,
    /// arm64 (`R_MAGIC`, fat header, 64 KiB data alignment).
    Arm64,
    /// i386 (`I_MAGIC`, short header, 4 KiB data alignment).
    I386,
    /// 32-bit ARM (`E_MAGIC`, short header, 4 KiB data alignment).
    Arm,
}

impl Arch {
    pub fn from_machine(machine: u16) -> Option<Self> {
        match machine {
            EM_X86_64 => Some(Self::Amd64),
            EM_AARCH64 => Some(Self::Arm64),
            EM_386 => Some(Self::I386),
            EM_ARM => Some(Self::Arm),
            _ => None,
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "amd64" | "x86_64" | "x86-64" | "x64" => Ok(Self::Amd64),
            "arm64" | "aarch64" | "armv8" | "armv8-a" => Ok(Self::Arm64),
            "386" | "i386" | "x86" => Ok(Self::I386),
            "arm" | "armv7" => Ok(Self::Arm),
            _ => Err(Error::usage(format!(
                "unknown architecture `{}` (expected amd64, arm64, 386 or arm)",
                name
            ))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
            Arch::I386 => "386",
            Arch::Arm => "arm",
        }
    }

    pub fn machine(self) -> u16 {
        match self {
            Arch::Amd64 => EM_X86_64,
            Arch::Arm64 => EM_AARCH64,
            Arch::I386 => EM_386,
            Arch::Arm => EM_ARM,
        }
    }

    pub fn magic(self) -> u32 {
        match self {
            Arch::Amd64 => magic(HDR_MAGIC, 26), // S_MAGIC
            Arch::Arm64 => magic(HDR_MAGIC, 28), // R_MAGIC
            Arch::I386 => magic(0, 11),          // I_MAGIC
            Arch::Arm => magic(0, 20),           // E_MAGIC
        }
    }

    pub fn magic_name(self) -> &'static str {
        match self {
            Arch::Amd64 => "S_MAGIC",
            Arch::Arm64 => "R_MAGIC",
            Arch::I386 => "I_MAGIC",
            Arch::Arm => "E_MAGIC",
        }
    }

    /// Size of the a.out header on disk, including the optional 64-bit entry.
    pub fn header_size(self) -> u64 {
        if self.extended_header() {
            32 + 8
        } else {
            32
        }
    }

    /// Whether magic has `HDR_MAGIC` and therefore an 8-byte virtual entry.
    pub fn extended_header(self) -> bool {
        matches!(self, Arch::Amd64 | Arch::Arm64)
    }

    /// `UTZERO`: the first virtual address of the text segment.
    pub fn utzero(self) -> u64 {
        match self {
            Arch::Amd64 => 0x0000_0000_0020_0000,
            Arch::Arm64 => 0x0000_0000_0001_0000,
            Arch::I386 | Arch::Arm => 0x1000,
        }
    }

    /// Text-to-data alignment (`INITRND` in the 9front linker).
    ///
    /// 9front's amd64 kernel rounds the data segment start up to 2 MiB;
    /// arm64 uses 64 KiB and the 32-bit ports use one page.
    pub fn data_align(self) -> u64 {
        match self {
            Arch::Amd64 => 0x20_0000,
            Arch::Arm64 => 0x1_0000,
            Arch::I386 | Arch::Arm => 0x1000,
        }
    }

    /// Pointer width of the target.
    pub fn pointer_size(self) -> usize {
        match self {
            Arch::Amd64 | Arch::Arm64 => 8,
            Arch::I386 | Arch::Arm => 4,
        }
    }

    /// Is this a little-endian target? All four supported ones are.
    pub fn little_endian(self) -> bool {
        true
    }

    /// Largest address the kernel will accept for the end of the image.
    /// This is a conservative approximation of `USTKTOP - USTKSIZE`.
    pub fn max_user_address(self) -> u64 {
        match self {
            Arch::Amd64 => 0x0000_7fff_ffff_f000u64 - 0x100_0000,
            Arch::Arm64 => (1u64 << 47) - 0x1_0000,
            Arch::I386 => 0xff00_0000,
            Arch::Arm => 0xbf00_0000,
        }
    }

    /// Sanity check that an ELF machine matches the requested output arch.
    pub fn check_input_machine(self, machine: u16) -> Result<()> {
        if machine == self.machine() {
            return Ok(());
        }
        if let Some(other) = Arch::from_machine(machine) {
            return Err(Error::unsupported(format!(
                "input ELF is for {} (e_machine={}), but output was requested for {}; \
                 use --arch {} only for an ELF that really is for that ISA (an ISA \
                 mismatch cannot be fixed by this tool)",
                other.name(), machine, self.name(), other.name()
            )));
        }
        Err(Error::format(format!(
            "input ELF has unsupported e_machine={}",
            machine
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_values_match_9front() {
        assert_eq!(Arch::Amd64.magic(), 0x8a97);
        assert_eq!(Arch::Arm64.magic(), 0x8c47);
        assert_eq!(Arch::I386.magic(), 0x1eb);
        assert_eq!(Arch::Arm.magic(), 0x647);
    }

    #[test]
    fn header_sizes() {
        assert_eq!(Arch::Amd64.header_size(), 40);
        assert_eq!(Arch::Arm64.header_size(), 40);
        assert_eq!(Arch::I386.header_size(), 32);
    }

    #[test]
    fn align_is_power_of_two() {
        for a in [Arch::Amd64, Arch::Arm64, Arch::I386, Arch::Arm] {
            assert!(a.data_align().is_power_of_two());
            assert_eq!(a.utzero() % a.data_align(), 0);
        }
    }
}
