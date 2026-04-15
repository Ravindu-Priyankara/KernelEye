// for testing purposes

static __always_inline void print_score(__u32 score, __u64 cid){
    bpf_printk("CID: %llu, Score %u \n", cid, score);
}

static __always_inline void print_flags_and_score(__u64 cid, __u32 score, __u32 flags){
    bpf_printk("CID: %llu, Score: %u, Flags: 0x%x \n", cid, score, flags);
}

// will be display sys/kernel/debug/tracing/trace_pipe