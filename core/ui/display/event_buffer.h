#pragma once

#include "../../common/common_structs.h"
#include "../../detections/detection_results.h"
#include <stdint.h>

#define MAX_EVENTS 100

// stat
extern struct stats ke_stats; 

struct event_entry {
    int pid;
    int type;
    int severity;
    uint64_t flags;
};

struct event_buffer {
    struct event_entry events[MAX_EVENTS];
    int count;  // current number of events
    int start;  // ring buffer start index
};

extern struct event_buffer ke_event_buf;

void add_event_to_buffer(struct ke_event_header *event);

void ke_display_all_events(void);