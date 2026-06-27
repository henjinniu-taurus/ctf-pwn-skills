# CTF Pwn - Overflow Basics

## Stack Buffer Overflow

1. Find offset: `cyclic 200` then `cyclic -l <crash_address>`
2. Check protections: `checksec --file=binary`
3. No PIE + No canary = direct ROP
4. Canary leak via format string or partial overwrite
5. Canary brute-force byte-by-byte on forking servers (7×256 max)

## ret2win with Magic Value

```python
payload = b"A" * offset + p64(ret) + p64(pop_rdi_ret) + p64(magic) + p64(win_func)
```

**Stack alignment:** SIGSEGV in `movaps` = add extra `ret` gadget. **Offset:** buffer at `rbp - N`, return at `rbp + 8`, total = N + 8.

## Input Filtering

Some challenges filter input via `memmem()` to block certain strings.

## Struct Pointer Overwrite (Heap Menu)

Overflow name into pointer field with GOT address, then write win address via modify. See heap menu GOT target selection table in advanced.md.

## Signed Integer Bypass

`scanf("%d")` without sign check; negative quantity * price = negative total, bypasses balance check.

## Canary-Aware Partial Overflow

Overflow `valid` flag between buffer and canary. Use `./` as no-op path padding for precise length control. See advanced.md.

## Global Buffer Overflow (CSV Injection)

Adjacent global variables; overflow via extra CSV delimiters changes filename pointer.

## Parser Stack Overflow via Unchecked memcpy

Custom file parser allocates fixed stack buffer but input records can exceed it. `memcpy` copies before length validation, overflowing saved registers and return address. Must restore callee-saved registers (rbx, r12-r15) before returning. See advanced.md.

## OOB Read via Stride/Rate Leak

String processing function with user-controlled stride skips past null terminator, leaking stack canary and return address one byte at a time.

## Stack Canary Brute Force (Forking Servers)

Brute-force canary byte-by-byte: 7×256 attempts max. See advanced.md.

## Protocol Length Field Stack Bleeding

Custom network protocol echoes data based on length field. Length exceeds actual data → Heartbleed-style leak.

## Hidden Gadgets in CMP Immediates

CMP immediates contain gadget bytes. Use `ropr --no-uniq -R "pop"` to find non-standard pops.
