
// defined in: fs/file.c:1477
SEC("kprobe/__x64_sys_dup")
int BPF_KPROBE(dup_enter, unsigned int oldfd){

    __u32 pid;
    __u32 fd_copy = oldfd;
    __u64 cid;
    __u64 dup_ts;
    struct ke_ctx_state *ke_state; // for state


    dup_ts = get_trigger_time();
    pid = get_tgid();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;

    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    // Load per-process correlation state (used to track syscall chain behavior)
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    /*
    *   Initialize the state if it's the first time the process has been seen.
    */
    if(!ke_state){
        struct ke_ctx_state ke_new_state = {};

        bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST);

        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    // Update the last time, and it helps to map cleanup.
    ke_state->last_time = dup_ts;
    // Mark the flag
    if(!(ke_state->flags & DUP_SEEN)){
        ke_state->flags |= DUP_SEEN;
        ke_state->score += 5; // weak signal
    }

    // update the map with oldfd
    bpf_map_update_elem(&dup_temp_map, &cid, &fd_copy, BPF_ANY);

    return 0;

}

SEC("kretprobe/__x64_sys_dup")
int BPF_KRETPROBE(dup_exit){

    struct ke_ctx_state *ke_state;
    struct connect_event *conn_event;

    __u64 cid;
    int *val;
    __u32 pid;
    __u32 oldfd;
    int newfd;

    pid = get_tgid();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;

    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;
    
    val = bpf_map_lookup_elem(&dup_temp_map, &cid);
    if(!val) return 0;
    oldfd = *val;

    // get the return value(newfd)
    newfd = PT_REGS_RC(ctx);
    if(newfd < 0) goto cleanup;

    // Load the pre process correlation state
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state) goto cleanup;

    // only process there was a network activity
    if(!(ke_state->flags & CONNECT_SEEN)) goto cleanup;

    // extract the connect event
    conn_event = bpf_map_lookup_elem(&connect_map, &cid);
    if(!conn_event) goto cleanup;

    /*
    *   checks:
    *       1. connect fd should equal to dup old fd
    *       2. newfd <= 2 {0,1,2}
    */
    if(conn_event->fd == oldfd && newfd <= 2 && !(ke_state->flags & SOCKET_MATCH_SEEN)){
        ke_state->flags |= SOCKET_MATCH_SEEN;
        ke_state->score += 20; // strong signal {connect + dup with fd trick}
    }

        // for testing
    print_flags_and_score(cid, ke_state->score, ke_state->flags);

    // for cleanup the maps
    cleanup:
        bpf_map_delete_elem(&dup_temp_map, &cid);
        return 0;
} 