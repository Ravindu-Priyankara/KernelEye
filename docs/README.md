# 📚 Documentation

> Kernel Eye is fully documented with a structured architecture-first approach.  
> Start from the overview and progressively dive deeper into each subsystem.

---

### 🧭 01 — Overview

- [Project Description](01_Overview/01_project_description.md)
- [Objectives](01_Overview/02_objectives.md)
- [Features](01_Overview/03_features.md)
- [Change Log](01_Overview/04_change_log.md)

---

### 🏗️ 02 — Architecture

#### 🔹 System Level

- [System Overview](02_Architecture/01_system_overview.md)
- [Data Flow](02_Architecture/02_data_flow.md)

---

#### 🔸 Kernel Layer (eBPF)

- [Kernel Layer Overview](02_Architecture/03_kernel_layer/01_overview.md)

**Probes**
- [Connect Probe](02_Architecture/03_kernel_layer/02_probes/01_connect_probe.md)
- [dup2 Probe](02_Architecture/03_kernel_layer/02_probes/02_dup2_probe.md)
- [execve Probe](02_Architecture/03_kernel_layer/02_probes/03_execve_probe.md)

**Core Logic**
- [Correlation Logic](02_Architecture/03_kernel_layer/03_correlation_logic.md)
- [Filtering](02_Architecture/03_kernel_layer/04_filtering.md)
- [Event Output](02_Architecture/03_kernel_layer/05_event_output.md)

---

#### 🔸 Userland Layer

- [Userland Overview](02_Architecture/04_userland/01_overview.md)
- [Event Processor](02_Architecture/04_userland/02_event_processor.md)

---

##### 🔍 Detection Engine

- [Detection Overview](02_Architecture/04_userland/03_detection/01_overview.md)
- [Detection Registry](02_Architecture/04_userland/03_detection/02_detection_registry.md)
- [Reverse Shell Detector](02_Architecture/04_userland/03_detection/03_reverse_shell_detector.md)

---

##### ⚖️ Decision & Action

- [Policy Engine](02_Architecture/04_userland/04_policy_engine.md)
- [Response Engine](02_Architecture/04_userland/05_response_engine.md)

---

##### 🖥️ UI Layer

- [UI Overview (Minimal)](02_Architecture/04_userland/06_UI.md)

---

### 🖼️ Diagrams

Architecture diagrams and visual representations:

- [System Overview Diagram](02_Architecture/images/System_Overview.png)
- [Data Flow Diagram](02_Architecture/images/Data_Flow.png)
- [Kernel Layer Overview](02_Architecture/images/kernel_layer_overview.png)
- [Userland Overview](02_Architecture/images/userland_overview.png)
- [Detection Engine](02_Architecture/images/Detection_engine.png)
- [Response Engine](02_Architecture/images/response_engine.png)

**Probes**
- [Connect Probe Diagram](02_Architecture/images/connect_probe.png)
- [dup2 Probe Diagram](02_Architecture/images/dup2_probe.png)
- [execve Probe Diagram](02_Architecture/images/execve_probe.png)

**Detection**
- [Detection Registry](02_Architecture/images/Detection_registry.png)
- [Reverse Shell Detector](02_Architecture/images/reverse_shell_detector.png)

---

## 📌 Suggested Reading Path

If you're new, follow this order:

```text
Project Description
    ↓
System Overview
    ↓
Data Flow
    ↓
Kernel Layer
    ↓
Userland Layer
    ↓
Detection → Policy → Response
````

---

## Note

> The documentation is structured to reflect real system design layers:
>
> * Kernel (data collection & filtering)
> * Userland (analysis & decision making)
> * Response (action execution)
>
> This separation ensures clarity, scalability, and maintainability.