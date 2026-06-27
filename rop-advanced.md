# CTF Pwn - Advanced ROP Techniques

## Double Stack Pivot to BSS via leave;ret

Small overflow (RBP + RIP only). Overwrite RBP → BSS address, RIP → `leave;ret` gadget. `leave` sets RSP = RBP (BSS). Second stage at BSS calls `fgets(BSS+offset, large_size, stdin)` to load full ROP chain. See advanced.md.

## SROP with UTF-8 Constraints

When payload must be valid UTF-8, use SROP — only 3 gadgets needed. Multi-byte UTF-8 sequences spanning register boundaries encode arbitrary values.

## RETF Architecture Switch

Seccomp blocks 64-bit syscalls. Use `retf` gadget to load CS=0x23 (IA-32e compatibility mode). In 32-bit mode, `int 0x80` uses different syscall numbers (open=5, read=3, write=4) not covered by the filter. Requires `mprotect` to make BSS executable for 32-bit shellcode.

## ret2vdso

Statically-linked binary with zero useful ROP gadgets. Leak vDSO base via AT_SYSINFO_EHDR (type 0x21) from stack. Use vDSO gadgets for `pop rdx; ret`, `pop rbx; ret`, `mov rdi, rbx; syscall`. See advanced.md for full chain.

## Vsyscall ROP (Fixed Addresses)

- `0xffffffffff600000` — gettimeofday (ret at +0x9)
- `0xffffffffff600400` — time (ret at +0x9)
- `0xffffffffff600800` — getcpu (ret at +0x9)

Modern kernels may disable vsyscall entirely (`vsyscall=none`).

## x32 ABI Syscall Number Aliasing

Standard execve blocked: syscall 59. x32 variant: `0x40000000 | 59 = 0x4000003B`. Seccomp BPF often misses this.

## pwntools Template

```python
#!/usr/bin/env python3
from pwn import *
context.binary = './binary'
elef = ELF(BINARY)
libc = ELF(LIBC) if LIBC else None

def get_conn():
    return remote(HOST, PORT) if args.REMOTE else process(BINARY)
```

## Shellcode with Input Reversal

Limited charset (no `\x90` NOP sled). Read input, reverse it in a register, then execute.

## .fini_array Hijack

No libc leak, no PLT calls after vuln. Overwrite `.fini_array[0]` with `main()` for re-execution loop, enabling multi-stage exploits.

## Useful Commands

```bash
ROPgadget --binary binary > gadgets.txt
ropper -f binary --search "pop rdi"
ropr --no-uniq -R "jnp|jo|jl" binary
seccomp-tools dump ./binary
one_gadget libc.so.6
```
