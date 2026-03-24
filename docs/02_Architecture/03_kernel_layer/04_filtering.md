# KernelEye - Filtering Strategy

> This document explains how Kernel Eye filters syscall events inside the kernel to reduce noise, improve performance, and ensure that only high-value events reach userland.

---

## 1. Overview

Kernel Eye follows a core principle:

> **Filter early, send only meaningful data.**

Instead of streaming all syscall events to userland, the system performs **in-kernel filtering and validation**, drastically reducing overhead.

---

## 2. The Problem

In a real system:

``` id="n3k9vz"
~500,000 syscalls/sec
````

If all events were forwarded:

* High CPU overhead
* Ring buffer congestion
* Userland bottlenecks
* Massive noise

- **Result:** inefficient and unusable system

---

## 3. Kernel Eye Approach

```id="b8t2xp"
Raw syscalls → State tracking → Correlation → Filtering → Output
```

Filtering happens **after correlation**, not at capture time.

---

## 4. Filtering Stages

### Stage 1 — Input Validation

Each probe performs early checks:

* Null pointer validation
* Safe memory access
* PID sanitization

Example:

```id="v6x1md"
if(!ctx->args[1]) return 0;
if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
```

---

### Stage 2 — Signal Reduction

Probes reduce noise by tracking only meaningful data.

Examples:

* `dup2` → only `fd <= 2` (stdio)
* ignore unrelated file descriptors
* skip kernel threads

---

### Stage 3 — Correlation-Based Filtering

The most important stage.

```id="r5j7zm"
if(!is_reverse_shell(pid)) return 0;
```

Only events that satisfy **multi-syscall behavioral conditions** are considered valid.

---

## 5. Decision Model

```id="p2x9cf"
Is behavior suspicious?
        /      \
      No        Yes
      |          |
   Drop       Send Event
```

---

## 6. Event Dropping

Non-suspicious events are:

* Not stored long-term
* Not sent to userland
* Removed from pipeline early

This ensures minimal system overhead

---

## 7. Event Forwarding

Only validated events are:

* Structured into `ke_suspicious_event`
* Written to ring buffer
* Consumed by userland

---

## 8. Ring Buffer Protection

Filtering directly protects the ring buffer:

```id="m8w4zt"
500k events/sec → filter → 0–5 events/sec
```

### Benefits:

* Prevents buffer overflow
* Reduces memory pressure
* Ensures consistent performance

---

## 9. Design Benefits

* **High performance:** minimal data transfer
* **Low noise:** only meaningful events
* **Efficient userland processing:** no unnecessary parsing
* **Scalability:** works under heavy syscall load

---

## 10. Design Philosophy

> **Detection happens in the kernel. Userland only reacts.**

Kernel Eye avoids:

* Blind event streaming
* Heavy userland filtering
* Unnecessary data duplication

Instead, it ensures:

* Early decision making
* Controlled data flow
* High signal-to-noise ratio

---

## 11. Future Improvements

* Adaptive filtering thresholds
* Advanced behavioral scoring
* Additional syscall integration (`dup3`, `fcntl`)

---

## 12. Summary

Kernel Eye’s filtering strategy transforms:

```id="z3q8wy"
high-volume noise → low-volume, high-confidence signals
```

By filtering inside the kernel, the system achieves **efficiency, accuracy, and scalability**.
