#pragma once

#include "../common/common_headers.h"
#include "../common/common_validation.h"
#include "common_helpers.h"
#include "../common/common_structs.h"
#include "../maps/maps.h"
#include "../common/common_sockets.h"

/*
*   This helper use to check connect + dup2 events happen before and dup2 file descripter >= 2 ,(stdin/out/err)
*   Arguments: pid
*   Return: true or false
*   Stack Allocation: 16 bytes
*/
static __always_inline int is_reverse_shell(__u32 pid){
    // for extract given pid has connect events.
    // Stack Allocation: 8 bytes
    struct connect_event *conn_event = check_map_data_availability(&connect_map, &pid);

    // for extract given pid has dup2 states.
    // Stack Allocation: 8 bytes
    struct dup2_state *dup2_state = check_map_data_availability(&dup2_map, &pid);

    // for extract givent pid has execve events.
    // Stack Allocation: 8 bytes
    struct execve_event *execve_event = check_map_data_availability(&execve_hash_map, &pid);

    if(!conn_event || !dup2_state || !execve_event) return 0;

    // if every checks true return true(1) otherwise false(0)
    return dup2_state->stdio_redirects >= 2; // some payloads skip stderr thats why i choose 2 rather than strictly depend on 3
}

/*
*   This helper is used to detect reverse shell-type events and pass that data to the streaming map.
*   Arguments :  process id
*   Return : success or fail
*   Stack Allocation : 24 bytes
*/
static __always_inline int ke_reverse_shell_type_event(__u32 pid){
    //prevent null values
    if(validate_not_null_u32(pid) != ERR_SUCCESS) return ERR_FAILURE;

    //sanitize the pid
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return ERR_FAILURE;

    // for extract given pid has connect events.
    // Stack Allocation: 8 bytes
    struct connect_event *conn_event;

    // for extract given pid has execve events.
    // Stack Allocation: 8 bytes
    struct execve_event *exe_event;

    // for extract given pid has dup2 events
    // Stack Allocation: 8 bytes
    struct dup2_state *dup2_state;

    // for hold reverse shell type events
    // Stack Allocation: 8 bytes
    struct ke_suspicious_event *r_event;

    // extract the connect data
    conn_event = check_map_data_availability(&connect_map, &pid);
    if(!conn_event) return ERR_FAILURE;

    // extract the execve data
    exe_event = check_map_data_availability(&execve_hash_map, &pid);
    if(!exe_event) return ERR_FAILURE;

    // extract the dup2 data
    dup2_state = check_map_data_availability(&dup2_map, &pid);
    if(!dup2_state) return ERR_FAILURE;

    // reserve a space
    r_event = bpf_ringbuf_reserve(&alert_map, sizeof(*r_event), 0);
    if(!r_event) return ERR_FAILURE;

    // header values
    r_event->hdr.type = KE_EVENT_REVERSE_SHELL; // event type
    r_event->hdr.pid = pid; // process id
    r_event->hdr.ts = get_trigger_time();   // detect time
    r_event->hdr.ppid = conn_event->ppid;   // parent process id

    // payload
    r_event->data.execve_ts = exe_event->execve_ts;
    r_event->data.net_ts = conn_event->net_ts;
    __builtin_memcpy(r_event->data.filename, exe_event->filename, sizeof(r_event->data.filename));
    r_event->data.last_dup2_ts = dup2_state->last_dup2_ts;
    r_event->data.stdio_redirects = dup2_state->stdio_redirects;

    //copy the ke_sockaddr struct
    __builtin_memcpy(&r_event->data.addr, &conn_event->addr, sizeof(struct ke_sockaddr));
    
    // submit the values
    bpf_ringbuf_submit(r_event, 0);

    /*
    *   this used for delete dectected event data from hash maps
    * Developer Note
    *   - but in the future this should be delay. because this is too early to delete
    */
    if(delete_map_elements(&connect_map, &pid) != ERR_SUCCESS) return ERR_FAILURE;
    if(delete_map_elements(&execve_hash_map, &pid) != ERR_SUCCESS) return ERR_FAILURE;
    if(delete_map_elements(&dup2_map, &pid) != ERR_SUCCESS) return ERR_FAILURE;
    
    return ERR_SUCCESS;
}