# Kernel Eye — System Overview

> This document provides a high-level view of the Kernel Eye security framework.  
> The accompanying diagram illustrates the main components and the data flow from kernel-level monitoring to userland detection and response.

<img src="./images/System_Overview.png">

---

## 1. High-Level Architecture

Kernel Eye is a runtime security framework that combines **kernel-level monitoring** via eBPF with a **userland detection and response engine**.  
The architecture is designed to maximize **visibility, performance, and signal quality**, while minimizing overhead and false positives.

The system consists of three primary layers:

1. **Kernel Layer (eBPF)** 
    <!--- Tracks parent-child relationships (PPID) for forked processes {next update}-->
   - Hooks critical syscalls: `execve`, `connect`, `dup2`  
   - Uses per-CPU scratchpad buffers for safe temporary storage  
   - Stores structured event data in dedicated hash maps  
   - Executes in-kernel filtering and correlation logic

2. **Data Transport**  
   - Suspicious events are sent to userland via a **ring buffer**  
   - Only validated events are emitted, preventing event flooding and reducing overhead

3. **Userland Layer**  
   - **Event Processor**: receives events from the ring buffer  
   - **Detection Engine**: applies behavioral correlation and detection rules  
   - **Policy Engine**: evaluates detection results and determines which response should be taken  
   - **Response Engine**: triggers actions (allow, block, alert)  
   - **Dashboard**: visualizes alerts, logs, and system status

---

## 2. Event Lifecycle (Summary)

1. **Syscall Trigger** (Kernel) → `connect`, `dup2`, `execve`  
2. **Event Capture** → per-CPU scratchpad + hash map storage  
3. **Correlation & Filtering** → in-kernel detection logic (reverse shell patterns, anomalies)  
4. **Ring Buffer Delivery** → only validated events  
5. **Userland Processing** → detection engine evaluates rules and scoring 
6. **Response & Logging** → actions triggered and logged for operators  

---

## 3. Design Highlights

- **Performance-first monitoring**: low CPU/memory overhead  
- **Signal over volume**: userland sees only meaningful events  
- **Modular & extensible**: easy to add new syscalls, detection logic, or response rules  
- **Scalable**: designed for high syscall environments (~500k syscalls/sec)  

---

This document and diagram provide a **bird’s-eye view** of Kernel Eye’s architecture.  
Subsequent architecture documents will zoom in to cover **data flow**, **kernel and userland modules**, **detection logic**, **response handling**, and **map structures**.