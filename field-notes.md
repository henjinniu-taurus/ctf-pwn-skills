# CTF Pwn - Field Notes

## Quick Reference

### Heap
| Technique | Requirements | Effect |
|-----------|-------------|--------|
| House of Apple 2 | UAF + heap leak + glibc 2.34+ | FSOP → shell |
| House of Einherjar | Off-by-one null byte | Backward consolidation → overlapping chunks |
| House of Orange | Top chunk overwrite | Unsorted bin free → libc attack |
| House of Spirit | Controlled pointer freed | Reallocation → arbitrary write |
| House of Lore | Smallbin corruption | Fake chunk in smallbin |
| House of Force | Top chunk overwrite + large alloc | Move top → arbitrary address |
| Tcache poisoning | Double-free or UAF | fd pointer → arbitrary alloc |
| Tcache stashing | Fastbin + tcache | bk write to target |
| Unsorted bin attack | Unsorted bin bk write | Overwrite global_max_fast |
| Fastbin dup | Double-free into fastbin | Alloc → arbitrary address |

### Kernel
| Technique | Requirements | Effect |
|-----------|-------------|--------|
| modprobe_path | AAW | Root shell on any execution |
| core_pattern | AAW | Root shell on core dump |
| tty_struct kROP | Sequential write 0x200+ | ROP chain in tty_struct |
| userfaultfd | UAF + threading | Deterministic race |

### Format String
| Primitive | Method |
|-----------|--------|
| Stack leak | `%p` × N |
| Arbitrary read | `%N$s` with addr at %N$p |
| Arbitrary write | `%N$n` or `%hhn` family |
| GOT overwrite | Write target addr, call via GOT |
| .fini_array loop | Ret2libc multi-stage |

### ROP
| Gadget | Use |
|--------|-----|
| `pop rdi; ret` | First argument |
| `pop rsi; pop rdx; ret` | Second + third args |
| `pop rax; ret` | Syscall number |
| `syscall; ret` | Make syscall |
| `leave; ret` | Stack pivot |
| `xchg rax, rsp; ret` | Stack pivot (alternative) |
| `ret` | Stack alignment |

### glibc Versions
| Version | Notable Changes |
|---------|----------------|
| 2.23 | No `_IO_file_jumps` validation, `__free_hook`/`__malloc_hook` present |
| 2.26 | Tcache introduced, no safe-linking |
| 2.27 | Tcache default, fastbin double-free slightly hardened |
| 2.29 | Tcache stashing unlink, safe-linking |
| 2.32 | Safe-linking uses xor with shift |
| 2.34 | `__free_hook`/`__malloc_hook`/`__realloc_hook` removed |

---

## pwntools One-Liners

```python
from pwn import *
context.binary = './binary'

# Leak
p.send(b'%p.' * 20)  # format string leak

# Offset finding
cyclic(200); cyclic_find(cyclic(200))  # find crash offset
pwnlib.elf.elf.ELF('binary').symbols  # symbols

# ROP
rop = ROP(elf)
rop.raw(rop.rdi.address)  # pop rdi gadget
rop.call(elf.symbols['win'], [arg1, arg2])

# DynELF
d = DynELF(leak_func, elf=elf)
system = d.lookup('system', 'libc')

# Shellcode
shellcraft.amd64.linux.sh()  # generate shellcode
asm(shellcraft.sh())  # assemble
```

---

## Common Offsets

| Vulnerability | Offset Pattern |
|--------------|----------------|
| Stack overflow (64-bit) | Buffer + 8 (saved RBP) + 8 (return) |
| Format string (direct) | `%N$p` where N = position of buffer |
| Heap overflow | Prev chunk size + PREV_INUSE + curr chunk header |
| Off-by-one null byte | Next chunk's size field |

---

## Common One-Gadget Constraints

```python
# one_gadget libc.so.6 output:
# 0xe1b6e execve("/bin/sh", r12, rdx)
# constraints: [rsi is null OR rsi == null OR r12 == null]
# 0xe1b6f execve("/bin/sh", r12, rdx)
# constraints: [rsi is null OR r12 is null OR rsi==0xdevnull]
# 0xe1b73 execve("/bin/sh", r12, rdx)
# constraints: [rdx == null AND r12 is null]

# Verify with libc_db or empirically
one_gadget -f libc.so.6  # find all
# Test each: find state where constraint is satisfied
```

---

## Checklist

- [ ] `checksec --file=binary` — protections
- [ ] `cyclic(200)` + `cyclic_find()` — overflow offset
- [ ] `%p.%p.%p...` — format string leak
- [ ] `vmmap` / `info proc mappings` — memory layout
- [ ] GOT/PLT entries — `objdump -d binary | grep @plt`
- [ ] `ROPgadget --binary binary` — gadget list
- [ ] `one_gadget libc.so.6` — one_gadgets
- [ ] libc search: `https://libc.blukat.me/` or `https://libc.rip/`
