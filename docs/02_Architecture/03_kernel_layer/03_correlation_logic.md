# KernelEye - Correlation Logic

> This document explains how Kernel Eye correlates multiple syscalls (`connect`, `dup2`, `execve`) to detect complex behaviors such as reverse shells.  
> Instead of treating syscalls independently, Kernel Eye builds a **stateful behavioral model inside the kernel**.

---

## 1. Overview

Traditional monitoring systems analyze syscalls in isolation.  
Kernel Eye takes a different approach:

> **Detection is based on syscall relationships over time, not individual events.**

The system correlates:

``` id="c4v9an"
connect → dup2 → execve
````

to identify **interactive shell behavior over a network connection**.

---

## 2. Why Correlation is Needed

A single syscall is not enough:

* `connect` → could be normal network usage
* `dup2` → common in process I/O handling
* `execve` → normal process execution

- Individually: **low signal**
- Combined: **high-confidence detection**

---

## 3. State Tracking via Maps

Kernel Eye maintains partial state across syscalls using eBPF maps.

### Maps involved:

* `connect_map` → network context
* `dup2_map` → descriptor redirection state
* `execve_hash_map` → execution context

Each map stores data keyed by `pid`.

---

### Example State Evolution

```id="r8d3fp"
Step 1: connect()
    → store network info in connect_map

Step 2: dup2()
    → increment stdio_redirects in dup2_map

Step 3: execve()
    → store execution data in execve_map
```

---

## 4. Correlation Trigger Point

Correlation is evaluated during the **execve stage**.

### Why execve?

* Represents process execution (final action)
* Ensures prior behavior is complete
* Avoids premature detection

---

## 5. Detection Logic

The core detection function:

```c
is_reverse_shell(pid)
```

---

### Conditions

```id="k8m1zs"
1. connect event exists
2. dup2 state exists
3. execve event exists
4. dup2_state->stdio_redirects >= 2
```

---

### Interpretation

* A process establishes a network connection
* Redirects its standard streams (stdin/stdout/stderr)
* Executes a program

This strongly indicates a **reverse shell or remote interactive session**

---

## 6. File Descriptor Signal

The `dup2` probe tracks:

```id="y1t9ap"
stdio_redirects++
```

### Threshold:

```id="m3q2vn"
>= 2
```

### Why not strictly 3?

* Some payloads skip `stderr`
* Using 2 improves detection coverage while maintaining accuracy

---

## 7. Event Correlation Model

```id="z5n8wu"
connect_map      → network origin
dup2_map         → interaction capability
execve_map       → execution trigger
        ↓
   correlation logic
        ↓
   detection decision
```

---

## 8. Event Emission

If detection succeeds:

```c
ke_reverse_shell_type_event(pid)
```

---

### Event Includes:

* PID / PPID
* Execution timestamp
* Network timestamp
* Filename
* Socket address
* Dup2 redirection count

---

### Output Flow:

```id="p7r4xt"
kernel correlation → ring buffer → userland
```

Only **validated events** are sent.

---

## 9. Map Lifecycle

After detection:

* `connect_map` → cleared
* `dup2_map` → cleared
* `execve_map` → cleared

### Purpose:

* Prevent duplicate detections
* Reset state for next behavior
* Reduce memory usage

---

### Design Note

Current cleanup is immediate.
Future improvement may introduce **delayed cleanup** for deeper analysis.

---

## 10. Performance Considerations

### High Throughput Environment

```id="h2n6zk"
~500,000 syscalls/sec
↓
0–5 detections/sec
```

---

### Key Optimizations:

* Kernel-side filtering
* Stateful correlation via maps
* Minimal ring buffer usage
* Avoid unnecessary userland communication

---

## 11. Limitations & Future Improvements

### Current Limitations:

* No full process tree tracking (fork/clone gaps)
* Limited descriptor tracking (`dup2` only)
* Immediate state cleanup

---

### Planned Enhancements:

* PPID / fork tracking improvements
* Support for `dup3` and `fcntl`
* Extended correlation windows
* More behavioral rules

---

## 12. Design Philosophy

> **Detect behavior, not events.**

Kernel Eye focuses on:

* Relationships between syscalls
* Temporal sequencing
* Stateful analysis

This approach enables:

* High accuracy
* Low noise
* Efficient detection inside the kernel

---

## 13. Summary

Kernel Eye’s correlation logic transforms:

```id="s2k9wp"
raw syscalls → structured state → behavioral detection
```

By combining multiple signals into a unified model, the system achieves **reliable and efficient runtime threat detection**.
