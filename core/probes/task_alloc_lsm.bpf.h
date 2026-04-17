// this will break ur system(High risk module)

SEC("lsm/task_alloc")
int BPF_PROG(trace_process_create, struct task_struct *task){

    __u64 cid;
    __u32 pid;

    struct ke_ctx_state *ke_state;

    pid = get_tgid();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        struct ke_ctx_state ke_new_state = {};
        bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    #ifdef DEBUG_MODE
    if(ke_state->stage >= STAGE_HIGH_RISK){
        bpf_printk("Process Blocked!, CID: %llu \n", cid);
        return -EPERM;
    }
    #endif

    return 0;
}