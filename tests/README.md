# Payload Test Artifacts

This directory contains **minimal test payloads** used exclusively to validate KernelEye’s detection logic in controlled lab environments.

These payloads simulate common post-exploitation behaviors (such as reverse shells) so that kernel-level detection signals can be verified and evaluated.

They are **not designed for stealth, persistence, or real-world exploitation**.

---

## Purpose

The payloads in this directory exist only to:

* Generate known behavioral patterns
* Trigger KernelEye detection rules
* Validate event correlation logic
* Support reproducible research

They are intentionally simple and transparent.

---

## What These Payloads Are

* Small proof-of-concept programs
* Educational test artifacts
* Lab-only execution samples

---

## What These Payloads Are NOT

* Offensive frameworks
* Weaponized implants
* Evasion-capable loaders
* Stealth backdoors

No obfuscation, packing, or persistence mechanisms are included.

---

## Intended Usage

1. Compile a payload
2. Execute inside an isolated test VM
3. Observe KernelEye alerts
4. Compare results with documented expectations

All testing should occur in a controlled environment.

---

## Ethical Notice

These payloads are provided solely for defensive security research and educational purposes.

Any misuse is strictly discouraged.

---

## Example Files

```
reverse_shell.asm   - minimal assembly reverse shell
reverse_shell.c     - simple C reverse shell
bind_shell.c        - simple bind shell
```

File names may vary as new test cases are added.

---

## Disclaimer

The author assumes no responsibility for misuse of these artifacts.

---
