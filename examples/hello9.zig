// Minimal freestanding 9front (amd64) program.
//
// Build (Zig 0.13):
//   zig build-exe examples/hello9.zig \
//       -target x86_64-linux-musl -OReleaseSmall -fPIE \
//       -fno-entry -fentry=_start -femit-bin=hello9.elf
//   ./target/debug/elf2out -v -o hello9.out hello9.elf
//
// This does NOT use Linux syscalls. 9front amd64 takes the syscall number in
// RBP and the arguments on the user stack at RSP+8, RSP+16, ...; the result
// comes back in RAX. See 9front's sys/src/libc/9syscall/mkfile.

const SYS_EXITS: usize = 8;
const SYS_WRITE: usize = 20;

/// Raw 9front syscall with six arguments.  The seven qwords pushed here are
/// [dummy, arg0, arg1, arg2, arg3, arg4, arg5] so that the kernel's
/// `Sargs*` (= user RSP + 8) points at arg0.
fn syscall6(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) usize {
    return asm volatile (
        \\pushq %%rbp
        \\pushq %[a5]
        \\pushq %[a4]
        \\pushq %[a3]
        \\pushq %[a2]
        \\pushq %[a1]
        \\pushq %[a0]
        \\pushq $0
        \\movq %[number], %%rbp
        \\syscall
        \\addq $56, %%rsp
        \\popq %%rbp
        : [ret] "=rax" (-> usize)
        : [number] "r" (number),
          [a0] "r" (a0),
          [a1] "r" (a1),
          [a2] "r" (a2),
          [a3] "r" (a3),
          [a4] "r" (a4),
          [a5] "r" (a5)
        : "rcx", "r11", "memory"
    );
}

fn write(fd: usize, buf: []const u8) usize {
    return syscall6(SYS_WRITE, fd, @intFromPtr(buf.ptr), buf.len, 0, 0, 0);
}

fn exits(status: usize) noreturn {
    _ = syscall6(SYS_EXITS, status, 0, 0, 0, 0, 0);
    unreachable;
}

const greeting = "hello from zig on 9front\n";

pub export fn _start() noreturn {
    _ = write(1, greeting);
    exits(0);
}
