# CTF Pwn - Format String Exploitation

## Detection

Send `%p.%p.%p` as input — if hex addresses appear in output, user input is passed directly to `printf`/`sprintf`.

## Primitives

| Primitive | Specifier | Use |
|-----------|-----------|-----|
| Leak stack | `%p.%p.%p.%p.%p.%p` | Dump multiple values |
| Leak specific offset | `%7$p` | Direct positional access |
| Arbitrary read | `%Ns` | Read string at address in slot N |
| Arbitrary write | `%n` family | Write byte count to pointer |

## Write Size Specifiers (x86-64)

| Specifier | Bytes | Note |
|-----------|-------|------|
| `%n` | 4 | Leaves garbage in upper bytes |
| `%hn` | 2 | Split 16-bit writes |
| `%hhn` | 1 | Precise byte control |
| `%lln` | 8 | Full 64-bit address (use this!) |

On x86-64 GOT entries are 8 bytes. **Use `%lln`** not `%n`.

## Offset Calculation

Buffer typically at offset 6 (after register args). Addresses start at `6 + N/8` where N = format byte length.

- 16-byte format → addresses at offset 8
- 32-byte format → addresses at offset 10
- 64-byte format → addresses at offset 14

## Arbitrary Write with GOT Targets

- Try `exit@GOT`, `printf@GOT`, `puts@GOT`, `putchar@GOT`
- Target functions called **AFTER** the format string vulnerability
- Check call order in disassembly

## Core Techniques

### Argument Retargeting (Non-Positional %n)

Overwrite a *future* argument pointer before it's used via `%n`, then write through it.

### Blind Pwn

1. Confirm: `%p-%p-%p-%p`
2. Leak stack for canary (~offset 39), saved RBP (~40), return (~41-43)
3. Identify PIE base from return address
4. Dump GOT entries
5. Cross-reference libc: https://libc.blukat.me/ or https://libc.rip/

### __free_hook Overwrite (glibc < 2.34)

Full RELRO + format string. `free(ptr)` passes `ptr` in rdi. If `__free_hook = system`, then `free("cat flag")` executes `system("cat flag")`.

### .rela.plt Patching (No Writable GOT)

Overwrite `Elf64_Rela` entry in `.rela.plt` to redirect PLT stub to `system`.

### saved EBP Overwrite for .bss Pivot

saved_ebp at known stack offset → points to buffer. Overwrite with .bss address. On `leave; ret`: `rsp = saved_ebp` → jumps to .bss ROP chain.

### .fini_array Loop (Multi-Stage)

Overwrite `.fini_array[0]` with `main()` for re-run loop. Stage 1: leak libc. Stage 2: `printf@GOT` → `system`, `.fini_array[0]` → `__stack_chk_fail`. Stage 3: corrupt canary → `__stack_chk_fail` → `main()` → `printf(input)` is `system(input)`.

### ROT13 Input Bypass

Input is ROT13-transformed before reaching `printf`. Pre-encode format string with inverse ROT13.
