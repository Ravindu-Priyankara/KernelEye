# KernelEye - Change Log

All notable changes to Kernel Eye are documented in this file.

The format is inspired by Keep a Changelog and follows semantic versioning principles.

---
## [v1.1.0] - Major Internal Improvements & ABI Stabilization(2026-03-25)

- Added
  - Introduced CID-based tracking model (replacing PID-only correlation)
  - Added bitmask-based syscall state tracking (connect, execve, dup2)
  - Added strict ABI validation using _Static_assert (size, offset, alignment)
  - Added a new filter for the kernel side to work efficiently(use bitmask flags).

- Changed
  - Reworked shared structs to ensure stable kernel ↔ userland ABI
  - Standardized padding using __reserved fields for future extensibility
  - Improved ke_sockaddr layout for consistent IPv4/IPv6 handling
  - Removed kernel side old filter(is_reverse_shell helper). 

- Improved
  - Detection accuracy through multi-syscall correlation
  - Memory layout predictability across compiler versions
  - Code readability and structural consistency



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
- change hash map to LRU hashmap(best for map filling issue)
- change sigterm -> sigkill or better approach.

### Optimization Ideas
- Reduce event size by shrinking filename buffer (e.g., 255 → 64 bytes)
- Implement string deduplication using hashing to minimize repeated data transfer