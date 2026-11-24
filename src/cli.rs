//! Hand-rolled command line parser (no external crates).

use crate::ensure;
use crate::arch::Arch;
use crate::error::{Error, ErrorKind, Result};
use crate::plan9::ConvertOptions;

pub const VERSION: &str = "0.1.0";

pub struct Args {
    pub input: Option<String>,
    pub output: Option<String>,
    pub options: ConvertOptions,
    pub dry_run: bool,
    pub help: bool,
    pub version: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            input: None,
            output: None,
            options: ConvertOptions::default(),
            dry_run: false,
            help: false,
            version: false,
        }
    }
}

pub fn help_text() -> &'static str {
    "\
elf2out - convert a static ELF executable into a 9front (Plan 9) a.out binary

USAGE:
    elf2out [OPTIONS] <input.elf> [output.out]
    elf2out [OPTIONS] -o <output.out> <input.elf>

OPTIONS:
    -o, --output <FILE>   Write the a.out binary to FILE (default: <input>.out)
    -a, --arch <ARCH>     Target architecture: amd64, arm64, 386, arm
                          (default: taken from the ELF e_machine)
        --entry <ADDR>    Override the virtual entry address from the ELF
        --base <ADDR>     Force the virtual address of the first ELF byte
        --symbols         Convert ELF symbols into a Plan 9 symbol table
        --patch-abs       Heuristically fix absolute addresses in a non-PIE ELF
        --ignore-tls      Do not warn about ELF TLS usage
        --dry-run         Do not write the output, only print the layout
    -v, --verbose         Print the computed a.out layout
    -h, --help            Show this help
    -V, --version         Show the version

ADDR accepts decimal or 0x-prefixed hexadecimal.

EXAMPLE:
    zig build-exe main.zig -target x86_64-linux-musl -fPIE -OReleaseSmall
    elf2out -v -o main.out main.elf
    chmod +x main.out   # then copy main.out to a 9front machine

NOTE:
    This tool only converts the container. A Linux-targeted program that
    issues Linux syscalls will not run on 9front: use freestanding Zig code
    with 9front syscall wrappers (see examples/hello9.zig and README.md)."
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut out = Args::default();
    let mut iter = args.into_iter().peekable();
    let mut positional = Vec::new();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => out.help = true,
            "-V" | "--version" => out.version = true,
            "-v" | "--verbose" => out.options.verbose = true,
            "--dry-run" => out.dry_run = true,
            "--symbols" => out.options.symbols = true,
            "--patch-abs" => out.options.patch_abs = true,
            "--ignore-tls" => out.options.ignore_tls = true,
            "-o" | "--output" => {
                out.output = Some(
                    iter.next()
                        .ok_or_else(|| Error::usage("--output needs a file name"))?,
                );
            }
            "-a" | "--arch" => {
                let name = iter.next().ok_or_else(|| Error::usage("--arch needs a value"))?;
                out.options.arch = Some(Arch::parse(&name)?);
            }
            "--entry" => {
                let value = iter.next().ok_or_else(|| Error::usage("--entry needs an address"))?;
                out.options.entry_override = Some(parse_addr(&value)?);
            }
            "--base" => {
                let value = iter.next().ok_or_else(|| Error::usage("--base needs an address"))?;
                out.options.base_override = Some(parse_addr(&value)?);
            }
            "--" => {
                positional.extend(iter);
                break;
            }
            other if other.starts_with("--") => {
                return Err(Error::usage(format!(
                    "unknown option `{}` (try --help)",
                    other
                )));
            }
            other if other.starts_with('-') && other.len() > 1 => {
                // Allow short option clusters such as -vv.
                for c in other[1..].chars() {
                    match c {
                        'v' => out.options.verbose = true,
                        'h' => out.help = true,
                        'V' => out.version = true,
                        _ => {
                            return Err(Error::usage(format!(
                                "unknown short option `-{}` (try --help)",
                                c
                            )))
                        }
                    }
                }
            }
            _ => positional.push(arg),
        }
    }

    if positional.len() > 2 {
        return Err(Error::usage(
            "too many positional arguments (expected <input.elf> [output.out])",
        ));
    }
    out.input = positional.get(0).cloned();
    if out.output.is_none() {
        out.output = positional.get(1).cloned();
    }
    Ok(out)
}

pub fn parse_addr(text: &str) -> Result<u64> {
    let cleaned = text.replace('_', "");
    let (radix, digits) = if let Some(rest) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        (16, rest)
    } else if let Some(rest) = cleaned.strip_prefix("0b").or_else(|| cleaned.strip_prefix("0B")) {
        (2, rest)
    } else if let Some(rest) = cleaned.strip_prefix("0o").or_else(|| cleaned.strip_prefix("0O")) {
        (8, rest)
    } else {
        (10, cleaned.as_str())
    };
    ensure!(
        !digits.is_empty(),
        ErrorKind::Usage,
        "invalid address `{}`",
        text
    );
    u64::from_str_radix(digits, radix)
        .map_err(|_| Error::usage(format!("invalid address `{}`", text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(parse_addr("4096").unwrap(), 4096);
        assert_eq!(parse_addr("0x1000").unwrap(), 4096);
        assert_eq!(parse_addr("0b1000_0000").unwrap(), 128);
        assert_eq!(parse_addr("0o10").unwrap(), 8);
        assert!(parse_addr("0x").is_err());
        assert!(parse_addr("abc").is_err());
    }

    #[test]
    fn option_parsing() {
        let a = parse(
            ["-vv", "--symbols", "--arch", "arm64", "in.elf", "-o", "out"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(a.input.as_deref(), Some("in.elf"));
        assert_eq!(a.output.as_deref(), Some("out"));
        assert!(a.options.verbose);
        assert!(a.options.symbols);
        assert_eq!(a.options.arch, Some(Arch::Arm64));
    }
}
