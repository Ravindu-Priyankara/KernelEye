# KernelEye - Event Output (Ring Buffer & ABI)

> This document explains how Kernel Eye delivers validated events from the kernel to userland using a ring buffer, and how structured data is defined through a stable ABI.

---

## 1. Overview

After syscall correlation and filtering, Kernel Eye emits only **validated suspicious events** to userland.

This is done using:

- **eBPF Ring Buffer** → efficient data transfer
- **Structured event format** → stable ABI contract

---

## 2. Output Pipeline

``` id="k3n8yr"
Detection (kernel)
        ↓
Event Construction
        ↓
Ring Buffer (kernel → userland)
        ↓
Userland Consumer
````

---

## 3. Ring Buffer Design

Kernel Eye uses a **BPF ring buffer** for streaming events.

### Characteristics:

* Kernel writes events
* Userland reads via polling
* Zero-copy (memory-mapped)
* High-performance and low overhead

---

### Event Flow

```id="z9m1rx"
kernel detection → bpf_ringbuf_reserve()
                → populate event
                → bpf_ringbuf_submit()
                → userland reads
```

---

## 4. Event Structure Design (ABI)

All events follow a **strict ABI contract** shared between:

* eBPF programs (kernel)
* Userland loader

> ⚠️ Layout must remain stable — any change breaks compatibility.

---

## 5. Common Event Header

```c id="p4k2mn"
struct ke_event_header {
    __u32 type;
    __u32 pid;
    __u64 ts;
    __u32 ppid;
};
```

### Purpose:

* Identifies event type
* Provides process context
* Ensures consistent parsing in userland

---

## 6. Reverse Shell Event Payload

```c id="w1r9zt"
struct ke_reverse_shell_payload {
    char filename[256];
    __u64 execve_ts;
    __u64 net_ts;
    __u64 last_dup2_ts;
    struct ke_sockaddr addr;
    __u8 stdio_redirects;
};
```

### Contains:

* Executed binary (`/bin/sh`, etc.)
* Timing correlation data
* Network origin (IP + port)
* Descriptor behavior

---

## 7. Final Streaming Event

```c id="m6y2vb"
struct ke_suspicious_event {
    struct ke_event_header hdr;
    struct ke_reverse_shell_payload data;
};
```

---

### Total Size

```id="g7t3kl"
336 bytes per event
```

---

## 8. Performance Model

### Assumptions:

```id="n2v8qx"
500,000 syscalls/sec
0–5 detections/sec
```

### Data Throughput:

```id="c5z1hp"
5 × 336 bytes = ~1.6 KB/sec
```

---

### Insight:

> Kernel Eye reduces massive syscall noise into minimal, high-value data.

---

## 9. Memory Layout & Alignment

* All structs are **8-byte aligned**
* Padding is explicitly controlled
* Verified using `_Static_assert`

### Why this matters:

* Prevents verifier issues
* Ensures consistent layout across kernel/userland
* Avoids undefined behavior

---

## 10. ABI Stability Guarantees

Kernel Eye enforces ABI stability using:

* Fixed struct sizes
* Offset validation (`offsetof`)
* Enum consistency checks

### Example:

```c id="x8p4dr"
_Static_assert(sizeof(struct ke_suspicious_event) == 336);
```

---

## 11. Event Emission Logic

Inside kernel:

```c id="b2k7ys"
r_event = bpf_ringbuf_reserve(&alert_map, sizeof(*r_event), 0);
```

Steps:

1. Reserve buffer space
2. Populate header + payload
3. Submit event

```c
bpf_ringbuf_submit(r_event, 0);
```

---

## 12. Data Included in Event

Each emitted event contains:

* Process metadata (PID, PPID)
* Execution details (filename, timestamp)
* Network context (IP, port)
* Behavioral data (dup2 count)
* Correlation timestamps

---

## 13. Design Considerations

* **Minimal data transfer** → only suspicious events
* **Compact structure** → predictable size
* **Efficient streaming** → ring buffer
* **Strict ABI control** → stability across components

---

## 14. Optimization Opportunities

Future improvements:

* Reduce filename size (`256 → 64`)
* String deduplication (hash-based)
* Event compression
* Batched event processing

---

## 15. Design Philosophy

> **High-volume input → low-volume, high-quality output**

Kernel Eye ensures:

* Only meaningful events leave the kernel
* Userland receives structured, ready-to-use data
* Performance remains stable under heavy load

---

## 16. Summary

Kernel Eye transforms:

```id="h4z9mc"
kernel detection → structured event → efficient streaming
```

By combining ring buffer efficiency with strict ABI design, the system achieves:

* High performance
* Low overhead
* Reliable event delivery
