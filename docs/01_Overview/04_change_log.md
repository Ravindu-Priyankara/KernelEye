# KernelEye - Change Log

All notable changes to Kernel Eye are documented in this file.

The format is inspired by Keep a Changelog and follows semantic versioning principles.

---
## [v1.1.0] - Tracking process lineage(2026-03-25)
### Added

- context ID-based tracking to prevent parent + child bypasses.
- Improve map ABI correctness.
- Remove unsafe kill and implement the logic for safely terminating the process(for kill pid should be > 100).
- ABI Stabilization & Struct Layout Hardening
  - Added:
    - Introduced explicit `__reserved` fields across shared structs to enforce stable memory layout.
    - Added `_Static_assert` checks for:
      - struct sizes
      - field offsets
      - alignment guarantees
  - Changed
    - Reworked `ke_sockaddr` layout:
      - Ensured fixed 24-byte size across IPv4/IPv6
      - Eliminated reliance on implicit compiler padding
      - Reordered fields for consistent ABI layout
    - Standardized padding strategy:
      - Replaced `__pad` with `__reserved` for ABI clarity and future extensibility
  - Improved
    - Strengthened kernel ↔ userland ABI contract
    - Prevented silent breakage due to compiler differences or struct reordering
    - Documented union sizing behavior for IPv4/IPv6 compatibility



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