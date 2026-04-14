// for testing purposes

static __always_inline void print_score(__u32 score, __u64 cid){
    bpf_printk("CID: %d, Score %d \n", cid, score);
}