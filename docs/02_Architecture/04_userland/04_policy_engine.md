# KernelEye - Policy Engine

> This document describes the Policy Engine in Kernel Eye.  
> It is responsible for translating detection results into actionable decisions.

---

## 1. Overview

The Policy Engine evaluates detection results and determines what action should be taken.

It acts as the **decision-making layer** between:

``` id="pe_flow1"
Detection Engine → Policy Engine → Response Engine
````

---

## 2. Purpose

The Policy Engine ensures:

* separation between detection and enforcement
* flexible decision-making
* consistent handling of detection results

---

## 3. Core Function

```c id="pe_core"
enum ke_policy_result evaluate_policy(struct ke_detection_result *result);
```

---

### Responsibilities:

* analyze detection result
* apply policy rules
* return action decision

---

## 4. Policy Decision Model

The decision is based on:

```id="pe_inputs"
1. severity
2. score
```

---

### Important Design Rule

> Either **severity OR score** can independently trigger an action.

---

## 5. Decision Logic

```c id="pe_logic"
if(result->severity == KE_SEV_CRITICAL || result->score >= BLOCK_SCORE)
    return KE_POLICY_BLOCK;

if(result->severity == KE_SEV_WARNING || result->score >= ALERT_SCORE)
    return KE_POLICY_ALERT;

return KE_POLICY_ALLOW;
```

---

## 6. Policy Actions

```c id="pe_actions"
enum ke_policy_result{
    KE_POLICY_ALLOW = 0,
    KE_POLICY_ALERT,
    KE_POLICY_BLOCK,
};
```

---

### Action Definitions

#### • ALLOW

* No action taken
* Event considered safe or low-risk

---

#### • ALERT

* Suspicious activity detected
* Logged or displayed for investigation

---

#### • BLOCK

* High-confidence malicious behavior
* Active response required

---

## 7. Score Thresholds

```c id="pe_thresholds"
#define BLOCK_SCORE 70
#define ALERT_SCORE 40
```

---

### Interpretation

| Score | Action |
| ----- | ------ |
| < 40  | ALLOW  |
| 40–69 | ALERT  |
| ≥ 70  | BLOCK  |

---

## 8. Decision Examples

### Example 1 — Strong Detection

```id="pe_ex1"
score = 80
severity = WARNING
→ BLOCK (score override)
```

---

### Example 2 — Severity Override

```id="pe_ex2"
score = 30
severity = CRITICAL
→ BLOCK (severity override)
```

---

### Example 3 — Medium Risk

```id="pe_ex3"
score = 50
severity = INFO
→ ALERT
```

---

### Example 4 — Safe Event

```id="pe_ex4"
score = 10
severity = INFO
→ ALLOW
```

---

## 9. Design Characteristics

### • Decoupled Architecture

* Detection ≠ action
* Policies define behavior independently

---

### • Flexible

* Thresholds can be tuned
* Severity or score can trigger decisions

---

### • Simple & Efficient

* Minimal logic
* Fast evaluation
* No unnecessary overhead

---

## 10. Design Philosophy

> **Detection tells what happened.
> Policy decides what to do.**

---

## 11. Advantages

* Prevents hardcoded responses inside detectors
* Allows future customization (per environment)
* Supports scalable decision-making

---

## 12. Limitations

* Static thresholds
* No dynamic or adaptive policies
* No context-aware decisions (e.g., per process/user)

---

## 13. Future Improvements

* Configurable policies (external config file)
* Environment-based rules (production vs dev)
* Risk-based adaptive thresholds
* User-defined policy plugins
* Machine learning-assisted decisions

---

## 14. Role in System

```id="pe_flow2"
event → detection → policy → response → UI
```

The Policy Engine converts:

```id="pe_transform"
detection result → actionable decision
```

---

## 15. Summary

The Policy Engine is responsible for:

* interpreting detection results
* applying decision logic
* selecting system response

It ensures Kernel Eye remains:

* modular
* flexible
* production-ready
