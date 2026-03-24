# KernelEye - Change Log

All notable changes to Kernel Eye are documented in this file.

The format is inspired by Keep a Changelog and follows semantic versioning principles.

---

## [v1.0.0] - Initial Release (2026-03-25)

### Added
- eBPF-based syscall monitoring framework
- `execve` syscall tracing for process execution visibility
- `connect` syscall tracking for network activity detection
- `dup2` syscall tracking for file descriptor redirection analysis

### Detection
- Implemented behavior-based reverse shell detection using syscall correlation:
  - `connect` → `dup2 (fd >= 2)` → `execve`

### Kernel-Side Processing
- In-kernel event filtering to ensure only validated suspicious events are sent to user space
- Reduced event noise by avoiding unnecessary ring buffer submissions

### Data Handling
- Structured event storage using eBPF hash maps for cross-syscall correlation
- Per-CPU scratchpad buffers for safe handling of large temporary data (e.g., filename)

### Performance
- Designed for high-throughput environments (~500k syscalls/sec assumption)
- Detection-focused output (~0–5 events/sec)
- Efficient ring buffer usage (~336 bytes per event, ~1.6 KB/sec output)

### Reliability
- Handling of failed reads and edge cases to prevent silent data loss
- Stable event capture across repeated or rapid syscall activity

---

## [Unreleased]

### In Progress
- `dup3` syscall tracking
- `fcntl` syscall monitoring for advanced descriptor manipulation
- **PPID / parent-child tracking for improved reverse shell detection**

### Planned
- Enhanced syscall correlation engine
- Process relationship mapping (parent-child tracking)
- Detection rule abstraction layer

### Optimization Ideas
- Reduce event size by shrinking filename buffer (e.g., 255 → 64 bytes)
- Implement string deduplication using hashing to minimize repeated data transfer