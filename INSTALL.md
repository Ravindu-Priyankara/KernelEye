# ⚙️ KernelEYE - Installation Guide

> This guide walks you through building and running KernelEye correctly.

---

## 📌 Requirements

### System Requirements

- Linux kernel **5.8+** (recommended 5.10+)
- Root privileges (`sudo`)
- x86_64 architecture

---

### Dependencies

#### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    gcc \
    make \
    linux-headers-$(uname -r) \
    bpftool
````

---

#### Arch Linux

```bash
sudo pacman -S clang llvm libbpf libelf gcc make linux-headers bpftool
```

---

## 🔧 Clone Repository

```bash
git clone https://github.com/<your-username>/KernelEye.git
cd KernelEye
```

---

## ⚡ Build

KernelEye must be built from the **core directory**:

```bash
cd core
make
```

This will:

* generate `vmlinux.h`
* compile eBPF program
* generate skeleton (`.skel.h`)
* build userland binary

---

## ⚡ Run (Important ⚠️)

You **must run from the `build` directory**.

```bash
cd build
sudo ./kerneleye
```

---

### ❗ Why `cd build` is required?

KernelEye loads detection rules using a **relative path**:

```c
#define KE_RULES_PATH "../detections/config/rules.conf"
```

If you run from another directory, rules **will not load**.

---

## ⚡ Expected Output

```text
[+] Initializing eBPF probes...
[+] Loading detection rules...
```

Then:

* UI will start
* system begins monitoring syscalls

---

## 🛑 Stop

Press:

```text
CTRL + C
```

This will safely:

* detach eBPF programs
* release resources

---

## ⚠️ Troubleshooting

---

### 1. BPF Program Fails to Load

```text
Failed to load BPF program
```

👉 Fix:

```bash
sudo ./kerneleye
```

---

### 2. Missing vmlinux.h

If build fails:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > core/common/vmlinux.h
```

Then rebuild:

```bash
make clean
make
```

---

### 3. libbpf Errors

Ensure:

```bash
libbpf-dev installed
```

---

### 4. Kernel Too Old

Check:

```bash
uname -r
```

If < 5.8 → upgrade required

---

### 5. Rules Not Loading ❗

Symptoms:

* detection not working
* no alerts

👉 Fix:

```bash
cd core/build
sudo ./kerneleye
```

---

### 6. BPF Verifier Errors

Check logs:

```bash
sudo dmesg | tail
```

---

## 🔄 Rebuild

```bash
cd core
make clean
make
```

---

## ⚡ Developer Notes

* Execution path matters due to **relative file loading**
* KernelEye prioritizes **low overhead kernel filtering**
* Userland handles detection, policy, and response

---

## 📌 Next Step

👉 Read documentation: [docs](docs/README.md)

---

## ⚡ Tip

If you modify detection rules:

```bash
nano ../detections/config/rules.conf
```

Then just restart KernelEye (no rebuild required).
