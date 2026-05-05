
/*
*   Defined in:
*       - sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
*/
SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit_handler(struct trace_event_raw_sched_process_exit *ctx){

    __u64 *cid;
    __u32 pid;
    bool group_dead;

    struct ke_ctx_state *ke_state;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    pid = BPF_CORE_READ(task, tgid);

    group_dead = ctx->group_dead;
    if(sanitize_the_pid(pid) != ERR_SUCCESS) goto cleanup;
    cid = bpf_map_lookup_elem(&ctx_map, &pid);
    if(!cid) goto cleanup;

    if(!group_dead) goto cleanup;
    // extract and clear context state map
    ke_state = bpf_map_lookup_elem(&ctx_state_map, cid);
    if(ke_state){
        ke_state->last_time = 0;
        ke_state->flags = 0;
        ke_state->stage = STAGE_NORMAL;
        ke_state->fd_mutation_count = 0;
    }
    
    bpf_map_delete_elem(&execve_hash_map, cid);
    bpf_map_delete_elem(&dup_map, cid);
    bpf_map_delete_elem(&connect_map, cid);
    bpf_map_delete_elem(&ctx_map, &pid); // otherwise innocent process will stay same cid

cleanup:
    return 0;
}