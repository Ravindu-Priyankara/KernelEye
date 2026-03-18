#pragma once

#ifdef DEBUG_MODE
// debugging map 
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} debug_map SEC(".maps");

// Increment counter helper
static __always_inline void debug_counter(__u64 val) {
    __u32 key = 0;
    __u64 *curr = bpf_map_lookup_elem(&debug_map, &key);
    if (curr) {
        val += *curr;
    }
    bpf_map_update_elem(&debug_map, &key, &val, BPF_ANY);
}

#else
static __always_inline void debug_counter(__u64 val) { }
#endif