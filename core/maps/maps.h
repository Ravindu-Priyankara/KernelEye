#pragma once

//header file
#include "../common/common_headers.h"

// maps sizes
#define RINGBUF_SIZE 1024
#define HASHMAP_SIZE 4096

/* Used hashmap for:
*   1. track events
*   2. stop streaming every events to userland
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);    // map type
    __uint(max_entries, HASHMAP_SIZE);  // hashmap maximum entries
    __type(key, __u32); // key = pid
    __type(value, struct proc_state);   // events data holding struct
}process_map SEC(".maps");  // hashmap name

