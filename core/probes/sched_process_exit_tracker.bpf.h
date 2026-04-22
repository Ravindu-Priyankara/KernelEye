
/*
*   Defined in:
*       - sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
*/
SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit_handler(struct trace_event_raw_sched_process_exit *ctx){

    __u64 *cid;
    __u64 pid;

    pid = get_tgid();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    cid = bpf_map_lookup_elem(&ctx_map, &pid);
    if(!cid) return 0;

    // for test
    bpf_map_delete_elem(&ctx_state_map, cid);

    return 0;
}