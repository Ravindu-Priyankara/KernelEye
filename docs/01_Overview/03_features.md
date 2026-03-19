# KernelEye - Features

> Current Version: v1.0.0

Kernel Eye focuses on efficient syscall-level monitoring and behavior-based detection using eBPF, with careful attention to performance, memory constraints, and signal quality.

---

## Core Capabilities

### • Multi-Syscall Monitoring
Captures and correlates critical syscalls involved in process execution and network behavior:
- `execve` (process execution)
- `connect` (network activity)
- `dup2` (file descriptor redirection)

These signals form the foundation for behavior-based detection.

---

### • Reverse Shell Detection (Behavior-Based)
Implements a syscall correlation strategy to detect reverse shell activity:

- Observes `connect` → network initiation  
- Tracks `dup2` with `fd >= 2` → descriptor redirection  
- Confirms execution via `execve`

Only when this sequence is satisfied, the event is classified as suspicious.

---

### • Signal-Based Event Filtering (Kernel-Side)
Detection logic is executed inside the kernel (eBPF layer).  
Only validated suspicious events are forwarded to user space.

This approach:
- Prevents event flooding
- Reduces unnecessary data transfer
- Keeps user-space processing minimal and focused

---

### • Structured Event Storage via Maps
Each syscall event maintains its state using dedicated eBPF hash maps.  
Data is stored in structured formats to enable correlation across multiple syscall stages.

---

### • Per-CPU Scratchpad Optimization
Uses per-CPU buffers to safely handle large temporary data (e.g., `filename[255]`) without exceeding eBPF stack limits.

This avoids:
- Stack overflow issues
- Verifier rejections
- Unsafe memory patterns

---

### • Ring Buffer-Based Event Delivery
Suspicious events are streamed to user space via a ring buffer.

Design considerations:
- Each event ~336 bytes
- Only high-signal events are emitted
- Optimized for low-frequency, high-value detections

---

## Performance Characteristics

- Designed for high syscall environments (~500k syscalls/sec assumption)
- Detection output remains extremely low (~0–5 events/sec)
- Approximate data output: ~1.6 KB/sec

This ensures:
- Scalability under heavy load
- Minimal overhead in production scenarios

---

## 🚧 In Progress / Planned Enhancements

- `dup3` syscall tracking (extended descriptor handling)
- `fcntl` tracking for advanced descriptor manipulation detection
- Stronger syscall correlation logic

---

###  Optimization Ideas

- Reduce event size by limiting filename buffer (e.g., 255 → 64 bytes)
- Implement string deduplication:
  - Hash filenames
  - Transmit only when unseen

These optimizations aim to further reduce bandwidth and improve efficiency.

---

## Design Philosophy

- Detect **behavior**, not just events  
- Filter **at the source (kernel)**, not in user space  
- Prioritize **signal over volume**  
- Build for **high performance and low noise**