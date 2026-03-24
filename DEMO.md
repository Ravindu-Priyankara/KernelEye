# 🎬 KernelEye Demo

> Real-time syscall monitoring, behavioral correlation, and active threat detection.

---

## ⚡ What This Demo Shows

- Syscall tracking (`connect`, `dup2`, `execve`)
- Kernel-level filtering and correlation
- Reverse shell detection
- Policy-based decision making
- Active response execution
- Real-time monitoring UI

---

## 🚀 Quick Demo

### Step 1 — Start KernelEye

```bash
cd core/build
sudo ./kerneleye
````

---

## ⚡ Test Scenarios (Built-in)

KernelEye includes **controlled test programs** to simulate different reverse shell behaviors.

### 📂 Build Test Programs

```bash
cd tests/v1_tests/
make
```

---

### ▶️ Run Tests

```bash
./revsh_fast
./revsh_slow
./revsh_partial
./revsh_evasion
./revsh_fname
./revsh_fname_timing
```

---

## ⚡ What Each Test Represents

| Test            | Description                                   |
| --------------- | --------------------------------------------- |
| `revsh_fast`    | Immediate reverse shell (no delay)            |
| `revsh_slow`    | Delayed execution to test timing correlation  |
| `revsh_partial` | Partial syscall pattern (incomplete behavior) |
| `revsh_evasion` | Attempts to bypass detection logic            |
| `revsh_fname`   | Filename obfuscation using renamed shell binary |
| `revsh_fname_timing` | Combined evasion using filename obfuscation + timing delays  |

---

## 🎯 Detection Flow (Example)

```text
connect → dup2 → execve
        ↓
kernel correlation
        ↓
filtered event → userland
        ↓
detection engine
        ↓
policy engine
        ↓
response engine
```

---

## ⚡ Expected Behavior

* `revsh_fast` → 🔴 Detected (high confidence)
* `revsh_slow` → 🟡 Detected but reduce score (timing evasion)
* `revsh_fname` → 🔴 Detected (critical, filename bypass ineffective)
* `revsh_fname_timing` → 🟡 Detected with lower score (~80) due to timing delays + file name bypass
* `revsh_partial` → ⚪ Ignored
* `revsh_evasion` → 🧪 Used for testing detection limits

---

## 📺 Demo Videos

> (Will be added)

- Installation = https://youtu.be/prt3Gwnnl0I
- v1 Testing = https://youtu.be/hEUJ0AeZ9YI

---

## 🧠 Key Insight

KernelEye does not rely on:

* ❌ Single syscall detection
* ❌ Static signatures

Instead, it uses:

* ✔ Behavioral correlation
* ✔ Timing analysis
* ✔ Descriptor tracking
* ✔ Rule-based scoring

---

## 🧊 Notes

* All tests are executed in a **controlled environment**
* Designed for **research and educational purposes**
* Detection logic is continuously evolving

---

## 🚀 Next

👉 Full documentation: [docs](./docs/README.md)
