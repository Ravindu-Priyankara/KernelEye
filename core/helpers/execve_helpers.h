#pragma once

#include "../common/common_headers.h"
#include "common_helpers.h"

//forward declaration
static __always_inline void *check_map_data_availability(void *map, const void *key);
static __always_inline int update_map_element(void *map, const void *key, const void *value, __u64 flags);

static __always_inline int copy_the_execve_event_data(__u32 pid){
    // execve event struct for copying data from the temporary hash map
    // Stack Allocation: 8 bytes
    struct execve_event *event;

    // for hold return value
    // 4 bytes of stack allocation
    int ret;

    // check availability
    event =check_map_data_availability(&execve_hash_map, &pid);
    if(!event) return ERR_FAILURE;

    // update the map
    ret = update_map_element(&execve_hash_map, &pid, event, BPF_ANY);
    if(ret != ERR_SUCCESS) return ERR_FAILURE;


    return ERR_SUCCESS;
}