#include "event_buffer.h"
#include "display.h"

struct event_buffer ke_event_buf = {0};

void add_event_to_buffer(struct ke_reverse_shell_event *event,
                         struct ke_detection_result *result)
{
    if(!event || !result) return;

    int idx;
    if(ke_event_buf.count < MAX_EVENTS) {
        idx = (ke_event_buf.start + ke_event_buf.count) % MAX_EVENTS;
        ke_event_buf.count++;
    } else {
        idx = ke_event_buf.start;
        ke_event_buf.start = (ke_event_buf.start + 1) % MAX_EVENTS;
    }

    ke_event_buf.events[idx].pid          = event->hdr.pid;
    ke_event_buf.events[idx].type         = event->hdr.type;
    ke_event_buf.events[idx].severity     = result->severity;
    ke_event_buf.events[idx].detection_id = result->detection_id;
    ke_event_buf.events[idx].score        = result->score;
}

void ke_display_all_events(void)
{
    for(int i = 0; i < ke_event_buf.count; i++) {
        int idx = (ke_event_buf.start + i) % MAX_EVENTS;
        struct event_entry *e = &ke_event_buf.events[idx];
        ke_display_event(
            e->pid,
            e->type,
            e->severity,
            e->detection_id,
            e->score
        );
    }
}