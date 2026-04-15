// for testing purposes

static __always_inline void print_score(__u32 score, __u64 cid){
    bpf_printk("CID: %d, Score %d \n", cid, score);
}

static __always_inline void print_flags_and_score(__u64 cid, __u32 score, __u32 flags){
    bpf_printk("CID: %d, Score: %d, Flags: 0x%x \n");
}

// will be display sys/kernel/debug/tracing/trace_pipe