#pragma once

//header file
#include "../common/common_headers.h"

// maps sizes
#define RINGBUF_SIZE 1 << 24
#define HASHMAP_SIZE 10240

// This hashmap used for track connect events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);    // map type
    __uint(max_entries, HASHMAP_SIZE);  // hashmap maximum entries
    __type(key, __u32); // key = pid
    __type(value, struct net_event);   // connect events data holding this struct
}connect_map SEC(".maps");  // hashmap name

