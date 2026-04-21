
SEC("tracepoint/syscalls/sys_enter_dup3")
int dup3_handler(struct trace_event_raw_sys_enter *ctx){

    __u64 cid;
    __u64 dup3_ts;
    __u32 pid;
    __u32 ppid;
    __s32 old_fd;
    __s32 new_fd;

    struct ke_ctx_state *ke_state;
    struct dup_state *dup3_state;
    struct connect_event *conn = NULL;

    pid = get_tgid();
    ppid = get_ppid();
    dup3_ts = get_trigger_time();
    old_fd = (__s32)ctx->args[0];
    new_fd = (__s32)ctx->args[1];

    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(new_fd > 2 || new_fd < 0) return 0;

    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    // get the context state data of this process
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    // first time seen this process
    if(!ke_state){
        struct ke_ctx_state new_state = {};

        // store the state
        bpf_map_update_elem(&ctx_state_map, &cid, &new_state, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;

    }
    // cut off the cost
    if(!(ke_state->flags & SOCKET_SEEN)) return 0;

    //extract the connect data
    if(ke_state->flags & CONNECT_SEEN){
        conn = bpf_map_lookup_elem(&connect_map, &cid);
    }

    // for reduce false positives
    if(conn){
        __u64 delta = dup3_ts > conn->net_ts
        ? dup3_ts - conn->net_ts
        : conn->net_ts - dup3_ts;

        // connect + dup2 should trigger withing 5 seconds
        if(delta > 5000000000ULL) return 0;
    }

    ke_state->last_time = dup3_ts;
    if(!(ke_state->flags & DUP3_SEEN)){
        update_state(ke_state, DUP3_SEEN);
    }

    // extract dup3 state data
    dup3_state = bpf_map_lookup_elem(&dup_map, &cid);
    // first dup3
    if(!dup3_state){
        struct dup_state new_dup3_state = {};
        new_dup3_state.stdio_redirects = 0;

        bpf_map_update_elem(&dup_map, &cid, &new_dup3_state, BPF_NOEXIST);
        dup3_state = bpf_map_lookup_elem(&dup_map, &cid);
        if(!dup3_state) return 0;
    }

    dup3_state->oldfd = old_fd;
    dup3_state->ppid = ppid;
    dup3_state->last_dup_ts = dup3_ts;

    // for reduce false positives
    if(conn && conn->fd == old_fd){
        dup3_state->stdio_redirects++;
        update_state(ke_state, SOCKET_MATCH_SEEN);
    }

    // check redirects
    if(dup3_state->stdio_redirects >= 2 
        && (ke_state->flags & SOCKET_MATCH_SEEN)
        && !(ke_state->flags & FD_REDERECTS_SEEN))
    {
        update_state(ke_state, FD_REDERECTS_SEEN);
    }

    // for debugging
    #ifdef DEBUG_MODE
        debug_counter(1); // increment debug counter
    #endif

    return 0;
}