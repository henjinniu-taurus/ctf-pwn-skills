# CTF Pwn - ROP Chains and Shellcode

## Two-Stage ret2libc

Stage 1: Leak libc via `puts@PLT(puts@GOT)`, return to vuln. Stage 2: `system("/bin/sh")`.

**Key:** Use `call vuln` address in main (not main itself) as return target — it preserves the stack frame.

## DynELF (Remote Libc Discovery)

```python
d = DynELF(leak_func, elf=elf)
system_addr = d.lookup('system', 'libc')
```

## Raw Syscall ROP

When `system()`/`execve()` crash (CET/IBT), use `pop rax; ret` + `syscall; ret` from libc.

## ret2csu

`__libc_csu_init` gadgets control `rdx`, `rsi`, `edi` without libc gadgets. See advanced.md for full gadget chain.

## Bad Char XOR Bypass

XOR payload data with key before writing to `.data`, then XOR back with ROP gadgets.

## Stack Pivot via xchg rax,esp

Swap stack pointer to attacker-controlled heap/buffer. Requires `pop rax; ret` to load pivot address first.

## rdx Control

After `puts()`, rdx is clobbered to 1. Options:
1. `pop rdx; pop rbx; ret` from libc
2. Re-enter binary's read setup + stack pivot
3. **Canary XOR epilogue as rdx zeroing gadget:** Jump into `xor rdx, fs:28h` — it zeros RDX when canary is intact.

## stub_execveat (Syscall 322)

When no `pop rax; ret` exists, use `stub_execveat` instead of `execve` — send exactly 0x142 bytes so `read()` return value sets rax.

## Exotic Gadgets (BEXTR/XLAT/STOSB/PEXT)

When standard `mov` write gadgets are unavailable, chain obscure x86 instructions for byte-by-byte writes.

## Shellcode in Small Buffers

Buffer too small for full shellcode (<20 bytes). Use `read()` stub to pull stage-2:
```asm
xor rsi, rsi; mov rdi, rsp; xor edx, edx; mov eax, 0; syscall; jmp rsp
```

## Shell Interaction

After `execve`: `sleep(1)` then `sendline(b'cat /flag*')`. Commands sent too early may be consumed by prior `read()` calls.
