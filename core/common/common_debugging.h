#pragma once

#ifdef DEBUG_MODE

// Single-slot debug map
struct bpf_map_def SEC("maps") debug_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 1,
};

// Helper to increment counter or set a value
static __always_inline void debug_counter(__u64 val) {
    __u32 key = 0;
    __u64 *curr = bpf_map_lookup_elem(&debug_map, &key);
    if (curr) {
        val += *curr;
    }
    bpf_map_update_elem(&debug_map, &key, &val, BPF_ANY);
}

#else
// If DEBUG_MODE is not set, empty inline (optimized out)
static __always_inline void debug_counter(__u64 val) { }
#endif