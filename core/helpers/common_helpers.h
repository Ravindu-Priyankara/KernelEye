#pragma once

#include "../common/common_headers.h"
#include "../common/common_status.h"
#include "../common/common_validation.h"


// This helper used for get the TGID from events
static __u32 __always_inline get_tgid(void){
    return bpf_get_current_pid_tgid() >> 32; // return tgid
}

// This heler used for get the PID from events
static __u32 __always_inline get_pid(void){
    return (__u32)bpf_get_current_pid_tgid();
}

// This helper used for get the PPID from task struct
static __u32 __always_inline get_ppid(void){
    // get current task pointer
    struct task_struct  *task = (struct task_struct *)bpf_get_current_task();
    if(validate_not_null(task)!= ERR_SUCCESS) return ERR_FAILURE;

    // prepare a parent pointer for parent
    struct task_struct *parent = NULL;

    // read real parent safly
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if(validate_not_null(parent) != ERR_SUCCESS) return ERR_FAILURE;

    //for hold ppid
    __u32 ppid = 0;

    // get parent tgid
    bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);

    return ppid;

}

/*
*   This function use for check hash map data availability
*   Argivements:
*       1. map
*       2. key (Mainly PID is the key)
*   Return:
*       1. NULL (not found valid data)
*       2. Generic pointer(void *) to the value associated with the key.
*/
static void * __always_inline check_hash_map_data_availability(void *map, const void *key){
    //prevent null data
    if(validate_not_null_duel(map, key) != ERR_SUCCESS) return ERR_FAILURE;

    return bpf_map_lookup_elem(map, key);
}

/*
*   This helper function used for update hash maps element
*       Task 1:
*           * Check data already stored or not.
*       Task 2:
*           * If there wasn't data. Write values from maps
*   Argivements:
*       1. map
*       2. key (Mainly PID is the key)
*       3. value (data fields ex:- ipv4 addr, ipv6 addr, port)
*       4. flags (commonly used BPF_ANY, but it depends on incident)
*   Return:
*       0 / -1 {0 = Success, -1 = failure}
*/
static int __always_inline update_hash_map_element(void *map, const void *key, const void *value, __u64 flags){
    //prevent null data
    if(validate_not_null_multiple(map, key, value) != ERR_SUCCESS) return ERR_FAILURE;
    if(validate_not_null_u64(flags) != ERR_SUCCESS) return ERR_FAILURE;

    void *state = check_hash_map_data_availability(map, key);

    // not existing data
    if(!state){
        int ret = bpf_map_update_elem(map, key, value, flags);  // update the elements
        return ret == 0 ? ERR_SUCCESS : ERR_FAILURE;
    }else return ERR_SUCCESS; // Key already exists
}