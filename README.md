# KernelEye

**KernelEye** is a kernel-level behavioral detection engine focused on identifying post-exploitation activity, suspicious process behavior, and stealthy persistence techniques on Linux systems.

Rather than relying on signatures or static indicators, KernelEye observes low-level system behavior — process lifecycles, syscall activity, and network interactions — to surface patterns commonly associated with active compromise.

The project is designed as an evolving research platform for exploring how modern attacks manifest at kernel level and how they can be detected through behavioral correlation.

---

## Why KernelEye Exists

Most endpoint detection tools operate heavily in userland and depend on known indicators.

KernelEye explores a different question:

**What does malicious activity look like when observed directly from the kernel?**

By answering this, KernelEye aims to:

* Detect post-exploitation activity even when payloads are obfuscated
* Identify abuse of legitimate binaries (LOLBins)
* Surface suspicious process and network relationships
* Study how stealthy persistence techniques leave behavioral traces

---

## Core Philosophy

* Behavior over signatures
* Correlation over single events
* Minimal assumptions about attacker tooling
* Focus on visibility and research clarity

KernelEye is intentionally built as a transparent research project.
Every detection is meant to be explainable.

---

## What KernelEye Observes

Depending on the module or research stage, KernelEye may observe:

* Process creation and termination
* Execve and argument patterns
* File descriptor duplication
* Network connections
* Parent/child process relationships
* TTY presence or absence
* Timing relationships between events

These signals are correlated to identify suspicious activity patterns.

---

## Example Research Areas

* Kernel-level detection of reverse shells
* Behavioral identification of suspicious shells
* Process ancestry anomaly detection
* Post-exploitation behavior correlation
* Persistence signal exploration

---

## Architecture Overview

KernelEye is organized as a modular research framework:

* Kernel instrumentation layer (eBPF / kernel hooks)
* Event collection layer
* Correlation and scoring layer
* Userland reporting tools

Each research iteration is implemented as a self-contained module inside the repository.

---

## Repository Structure

```
KernelEye/
├── modules/
│   ├── reverse_shell_detection/
|   |       ├── README.md
|   |       ├── ebpf/
|   |       |     └──monitor-syscalls.bpf.c
|   |       ├── userland/
|   |       |       └── user_loader.c
|   |       ├── tests/
|   |       |       ├── README.md
|   |       |       └── payloads
|   |       |            ├── reverse_shell.asm
|   |       |            └── reverse_shell.c
|   |       └── documents/
|   |               ├── 01_problem_scope.md
|   |               ├── 02_detection_signals.md
|   |               ├── 03_event_flow.md
|   |               ├── 04_known_bypasses.md
|   |               └── 05_future_work.md
│   ├── behavior_correlation/
│   └── persistence_signals/
├── tools/
├── docs/
└── experiments/
```

Folder names may evolve as research progresses.

---

## Status

KernelEye is an active research project.
Features and modules are added incrementally as new detection ideas are explored.

This repository prioritizes clarity, documentation, and reproducibility over rapid feature growth.

---

## Intended Audience

* Security researchers
* Blue team engineers
* Malware analysts
* Students exploring kernel-level detection

---

## Ethical Use

KernelEye is intended strictly for defensive security research and educational purposes.

It does not provide offensive tooling or weponized payloads.

---

## Disclaimer

This project is provided for research and educational purposes only.
The author is not responsible for misuse.

---
