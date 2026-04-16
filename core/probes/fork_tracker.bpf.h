
/*
*   Argument info:
*       - sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
*/
SEC("tracepoint/sched/sched_process_fork")
int fork_handler(struct trace_event_raw_sched_process_fork *ctx){

    /*
    *   For hold parent thread group id
    *   Stack Allocation: 4 bytes
    */
    __u32 ppid;

    /*
    *   For hold child thread group id
    *   Stack Allocation: 4 bytes
    */
    __u32 pid;

    /*
    *   For hold context id
    *   Stack Allocation: 8 bytes
    */
    __u64 cid;

    /*
    *   For hold parent context id
    *   Stack Allocation: 8 bytes
    */
    __u64 *parent_cid;

    struct ke_ctx_state *ke_state;

    /*
    *   Developer Note:
    *       - shedule tracepoints does not use args[0-6].
    */
    pid = ctx->child_pid;
    ppid = ctx->parent_pid;

    /*
    * Sanitize the pid and ppid.
    *
    * Defined in:
    *   - common/common/validation.h
    *
    * Purpose:
    *   - Avoid track the kernel threads or idle tasks
    */
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;

    /*
    *   If the parent drops, we lose lineage silently. So the goal is to protect lineage.
    *   KernelEye never kills ppid = 0, but shows the warning. That's why we assign ppid as 0.
    */
    if(sanitize_the_pid(ppid) != ERR_SUCCESS) ppid = 0;

    parent_cid = bpf_map_lookup_elem(&ctx_map, &ppid);
    if(!parent_cid) return 0;

    // for cid, assign the value of parent cid.
    cid = *parent_cid;

    /*
    *   Save the child thread group ID under the parent context ID.
    *   Developer Note:
    *       - Why BPF_ANY?
    *           - Fork can happen multiple times
    *           - Child PID might be reused (rare but possible)
    *           - We don't care if it's overwritten because CID must stay consistent.
    */
    bpf_map_update_elem(&ctx_map, &pid, &cid, BPF_ANY);

    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        struct ke_ctx_state ke_new_state = {};

        bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    if(!(ke_state->flags & FORK_SEEN)){
        update_state(ke_state, FORK_SEEN);
    }
    // for debugging
    print_flags_and_score(cid, ke_state->flags, ke_state->stage);


    // for debugging
    #ifdef DEBUG_MODE
        debug_counter(1); // increment debug counter
    #endif

    return 0;
}