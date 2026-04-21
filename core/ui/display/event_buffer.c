#include "event_buffer.h"
#include "display.h"

// Global circular buffer to store events temporarily
struct event_buffer ke_event_buf = {0};

// Add a new suspicious event to the circular buffer
void add_event_to_buffer(struct ke_event_header *event)
{
    if(!event) return; // sanity check

    int idx;
    // If buffer not full, append at end
    if(ke_event_buf.count < MAX_EVENTS) {
        idx = (ke_event_buf.start + ke_event_buf.count) % MAX_EVENTS;
        ke_event_buf.count++;
    } else { // If buffer full, overwrite oldest event (circular behavior)
        idx = ke_event_buf.start;
        ke_event_buf.start = (ke_event_buf.start + 1) % MAX_EVENTS;
    }

    // Copy event data into buffer slot
    ke_event_buf.events[idx].pid          = event->pid;
    ke_event_buf.events[idx].type         = event->type;
    ke_event_buf.events[idx].severity     = event->stage;
}

// Display all events currently in the buffer
void ke_display_all_events(void)
{
    for(int i = 0; i < ke_event_buf.count; i++) {
        int idx = (ke_event_buf.start + i) % MAX_EVENTS; // circular index
        struct event_entry *e = &ke_event_buf.events[idx];
        // Print event using UI function
        ke_display_event(
            e->pid,
            e->type,
            e->severity
        );
    }
}