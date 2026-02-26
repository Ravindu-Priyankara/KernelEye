#pragma once

#include "../common/common_headers.h"
#include "../common/common_status.h"


// This helper used for get the TGID from events
static __u32 __always_inline get_tgid(void){
    return bpf_get_current_pid_tgid() >> 32; // return tgid
}

// This heler used for get the PID from events
static __u32 __always_inline get_pid(void){
    return (__u32)bpf_get_current_pid_tgid();
}

// This function use for read maps has data or not
static void * __always_inline check_hash_map_data_availability(void *map, const void *key){
    return bpf_map_lookup_elem(map, key);
}

static int __always_inline update_hash_map_element(void *map, const void *key, const void *value, __u64 flags){
    void *state = check_hash_map_data_availability(map, key);

    if(!state){
        bpf_map_update_elem(map, key, value, flags);
        state = check_hash_map_data_availability(map, key);
        if(!state){
            return ERR_FAILURE;
        }else{
            return ERR_SUCCESS;
        }
    }
}