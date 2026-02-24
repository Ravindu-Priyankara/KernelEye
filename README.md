# KernelEye

**Version Reference:** See `docs/updates.md` for full version history  
**Author:** Ravindu  

---

## Overview
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

For **current modules, features, and research status**, see [`docs/updates.md`](docs/updates.md).

---

## Core Philosophy

* Behavior over signatures  
* Correlation over single events  
* Minimal assumptions about attacker tooling  
* Focus on visibility and research clarity  

KernelEye is intentionally built as a transparent research project.  
Every detection is meant to be explainable.

---

## Architecture Overview

KernelEye is organized as a modular research framework:

* Kernel instrumentation layer (eBPF / kernel hooks)  
* Event collection layer  
* Correlation and scoring layer  
* Userland reporting tools  

Each research iteration is implemented as a self-contained module inside the repository.

For diagrams or detailed architecture, see `docs/architecture.md`.

---

## Intended Audience

* Security researchers  
* Blue team engineers  
* Malware analysts  
* Students exploring kernel-level detection  

---

## Ethical Use

KernelEye is intended strictly for defensive security research and educational purposes.  
It does **not** provide offensive tooling or weaponized payloads.

---

## Disclaimer

This project is provided for research and educational purposes only.  
The author is not responsible for misuse.

---

## Documentation

* `docs/architecture.md` – Full architecture diagram & workflow  
* `docs/maps.md` – Versioned map reference  
* `docs/features.md` – Current and planned features  
* `docs/updates.md` – Version history & module updates