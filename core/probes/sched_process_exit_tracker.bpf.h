
/*
*   Defined in:
*       - sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
*/
SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit_handler(struct trace_event_raw_sched_process_exit *ctx){

    __u64 *cid;
    __u64 pid;

    struct ke_ctx_state *ke_state;

    pid = ctx->pid; // stable rather than bpf helper
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    cid = bpf_map_lookup_elem(&ctx_map, &pid);
    if(!cid) return 0;

    // extract and clear context state map
    /*ke_state = bpf_map_lookup_elem(&ctx_state_map, cid);
    if(ke_state){
        ke_state->last_time = 0;
        ke_state->flags = 0;
        ke_state->stage = STAGE_NORMAL;
        ke_state->fd_mutation_count = 0;
    }*/
    
    bpf_map_delete_elem(&execve_hash_map, cid);
    bpf_map_delete_elem(&dup_map, cid);
    bpf_map_delete_elem(&connect_map, cid);
    bpf_map_delete_elem(&ctx_map, &pid); // otherwise innocent process will stay same cid

    return 0;
}