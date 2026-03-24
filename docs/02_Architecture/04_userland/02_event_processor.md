# KernelEye - Event Processor

> This document describes the Event Processor in Kernel Eye.  
> It acts as the entry point for all kernel-generated events and orchestrates the full userland pipeline: detection, policy evaluation, response execution, and visualization.

---

## 1. Overview

The Event Processor is responsible for:

- Consuming events from the kernel (ring buffer)
- Dispatching events to the detection engine
- Passing results to the policy engine
- Executing responses
- Updating UI and runtime statistics

---

## 2. High-Level Flow

``` id="epflow1"
Ring Buffer
    ↓
handle_event()
    ↓
Detection Engine
    ↓
Policy Engine
    ↓
Response Engine
    ↓
UI / Stats / Display
````

---

## 3. Entry Point (Main Loop)

The Event Processor initializes and continuously polls the ring buffer.

### Responsibilities:

* Load eBPF programs
* Initialize detection rules
* Setup UI
* Register ring buffer callback
* Poll for incoming events

---

### Ring Buffer Setup

```c id="ep_rb_setup"
rb = ring_buffer__new(
    bpf_map__fd(kern->maps.alert_map),
    handle_event,
    NULL,
    NULL
);
```

* `alert_map` → kernel ring buffer
* `handle_event` → callback function

---

### Polling Loop

```c id="ep_poll_loop"
while(!stop){
    ring_buffer__poll(rb, 100);
}
```

* Timeout: 100ms
* Non-blocking event consumption
* Graceful shutdown via signals

---

## 4. Signal Handling

The processor supports clean termination:

* `SIGINT` (Ctrl+C)
* `SIGTERM`

```id="ep_signal"
stop = 1;
```

---

## 5. Event Handling Function

```c id="ep_handler"
int handle_event(void *ctx, void *data, size_t size)
```

This function is called **for every event received from the kernel**.

---

## 6. Event Parsing

```c id="ep_parse"
struct ke_event_header *hdr = data;
struct ke_suspicious_event *event = data;
```

* Uses shared ABI structures
* Interprets raw data as structured event

---

## 7. Processing Pipeline

### Step 1 — Statistics Update

```c id="ep_stats"
ke_stats.events++;
```

Tracks total number of processed events.

---

### Step 2 — Detection Engine

```c id="ep_detect"
if(run_detections(event, &result))
```

* Executes detection logic
* Populates `ke_detection_result`

---

### Step 3 — Policy Evaluation

```c id="ep_policy"
enum ke_policy_result action = evaluate_policy(&result);
```

* Determines what action should be taken
* Based on severity and detection type

---

### Step 4 — Response Execution

```c id="ep_response"
ke_execute_response(action, hdr);
```

* Executes action (allow, alert, block)
* Uses response engine

---

### Step 5 — Statistics Update

```c id="ep_stats2"
ke_stats.reverse_shells++;
ke_stats.alerts++;
ke_stats.blocks++;
```

Tracks:

* detection types
* severity levels

---

### Step 6 — Event Buffering (UI)

```c id="ep_buffer"
add_event_to_buffer(event, &result);
```

* Stores event for display
* Enables UI rendering

---

### Step 7 — UI Refresh

```c id="ep_ui"
printf("\033[2J\033[H");
ke_print_banner();
ke_display_all_events();
ke_print_stats(&ke_stats);
```

* Clears screen
* Renders updated state
* Displays real-time monitoring

---

## 8. Data Flow Summary

```id="epflow2"
kernel event
    ↓
parse event
    ↓
run detections
    ↓
evaluate policy
    ↓
execute response
    ↓
store + display
```

---

## 9. Design Characteristics

### • Event-Driven

* No polling logic beyond ring buffer
* Fully reactive system

---

### • Centralized Orchestration

* Single entry point controls entire pipeline
* Easy to trace execution flow

---

### • Modular Integration

* Detection, policy, and response are decoupled
* Easily extendable

---

### • Real-Time Processing

* Events handled immediately
* UI updates instantly

---

## 10. Performance Considerations

* Only filtered events reach userland
* Low event rate (~0–5 events/sec)
* Minimal processing overhead

---

## 11. Strengths

* Clean pipeline execution
* Strong separation of concerns
* Efficient event handling
* Real-time visibility

---

## 12. Limitations

* UI refresh clears full screen (not incremental)
* Single-threaded processing
* No event batching

---

## 13. Future Improvements

* Async / multi-threaded processing
* Incremental UI updates
* Event prioritization
* Integration with external systems (SIEM, logs)

---

## 14. Role in System

The Event Processor acts as the **bridge between kernel and userland intelligence**.

```id="epflow3"
kernel detection → userland processing → actionable response
```

Without this component, the system cannot:

* interpret kernel output
* make decisions
* respond to threats

---

## 15. Summary

The Event Processor transforms:

```id="epflow4"
ring buffer events → detection → decision → action → visualization
```

It is the **central execution engine** of the Kernel Eye userland pipeline.

