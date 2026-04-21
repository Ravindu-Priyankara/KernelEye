#pragma once

#include "../common/common_headers.h"
#include "../common/common_validation.h"
#include "common_helpers.h"
#include "../common/common_structs.h"
#include "../maps/maps.h"
#include "../common/common_sockets.h"


static __always_inline int emit_event(__u16 stage, __64 flags){

    __u32 pid;

    struct ke_event_header *event;

    pid = get_tgid();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return ERR_FAILURE;

    // reserve the space
    event = bpf_ringbuf_reserve(&alert_map, sizeof(*event), 0);
    if(!event) return ERR_FAILURE;

    // assign the data
    event->type = KE_EVENT_REVERSE_SHELL;
    event->pid = pid;
    event->stage = stage;
    event->flags = flags;

    bpf_ringbuf_submit(event, 0);

    return ERR_SUCCESS;
}