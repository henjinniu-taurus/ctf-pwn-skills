---
name: ctf-pwn
description: CTF binary exploitation skill — buffer overflow, ROP, format strings, heap, kernel, sandbox escape.
metadata:
  user-invocable: "false"
---

# CTF Binary Exploitation (Pwn)

Quick reference for binary exploitation (pwn) CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Quick Start Commands

```bash
checksec --file=binary
ROPgadget --binary binary | grep "pop rdi"
one_gadget /lib/x86_64-linux-gnu/libc.so.6
python3 -c "from pwn import *; print(cyclic(200))"
python3 -c "from pwn import *; print(cyclic_find(0x61616168))"
```

## Protection Decision Tree

| Protection | Status | Approach |
|------------|--------|----------|
| PIE | Disabled | Direct address overwrite (GOT, PLT, functions) |
| RELRO | Partial | GOT writable → GOT overwrite |
| RELRO | Full | Target __free_hook, __malloc_hook, or return addresses |
| NX | Enabled | Use ROP or ret2win (no stack/heap shellcode) |
| Canary | Present | Heap-based attacks or leak canary first |

## Stack Buffer Overflow

1. Find offset: `cyclic 200` then `cyclic -l <value>`
2. Check protections: `checksec --file=binary`
3. No PIE + No canary = direct ROP
4. Canary brute-force byte-by-byte on forking servers (7×256 max)

**ret2win pattern:** Overflow → ret (alignment) → pop rdi; ret → magic → win()

## ROP Chain Building

Leak libc via `puts@PLT(puts@GOT)`, return to vuln, stage 2 with `system("/bin/sh")`.

**DynELF:** `pwntools.DynELF(leak_func, pointer_in_libc)` resolves libc symbols remotely.

**ret2csu:** `__libc_csu_init` gadgets control rdx, rsi, edi for 3-argument calls without libc gadgets.

**rdx control:** After `puts()`, rdx is clobbered. Use `pop rdx; pop rbx; ret` from libc, or jump into canary XOR epilogue `xor rdx, fs:28h` which zeros RDX.

## Format String

Send `%p.%p.%p` — if hex addresses appear, format string vulnerability exists.

Leak: `%Ns` reads string at address in slot N. Write: `%n` family writes byte count.

On x86-64 GOT entries are 8 bytes — use `%lln` not `%n`.

## Heap Techniques

- House of Apple 2 (+ setcontext SUID variant) for glibc 2.34+
- Tcache poisoning (glibc 2.26+)
- House of Einherjar, Orange, Spirit, Lore, Force
- UAF, unsafe unlink, tcache stashing unlink
- See heap-techniques.md, heap-techniques-2.md, heap-fsop.md

## Kernel

See kernel.md (fundamentals), kernel-techniques.md (techniques), kernel-bypass.md (bypass).

## Sandbox Escape

See sandbox-escape.md — Python jail (ctf-misc), custom VM, FUSE/CUSE, busybox, shell tricks.

## When to Pivot

- Binary unclear → /ctf-reverse first
- Restricted shell/encoding puzzle → /ctf-misc
- Web endpoint bug → /ctf-web
- Cryptographic primitive → /ctf-crypto
