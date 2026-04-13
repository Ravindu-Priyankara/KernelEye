SEC("tracepoint/syscalls/sys_enter_openat2")
int openat2_handler(struct trace_event_raw_sys_enter *ctx){

    __u64 cid;
    __u64 openat2_ts;
    __u32 pid;
    __u32 key = 0;
    int ret;

    struct ke_ctx_state *ke_state;
    struct scratch_buf *scratch_buf;

    pid = get_tgid();
    openat2_ts = get_trigger_time();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;

    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;
    
    // extract the state data
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        struct ke_ctx_state ke_new_state = {};

        bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    // set openat2 flag
    ke_state->last_time = openat2_ts;
    if(!(ke_state->flags & OPENAT2_SEEN)){
        ke_state->flags |= OPENAT2_SEEN;
    }

    // get the percpu map for copy filename
    scratch_buf = bpf_map_lookup_elem(&scratch_buf_map, &key);
    if(!scratch_buf) return 0;

    // use scratchpad for copy filename
    ret = bpf_probe_read_user_str(scratch_buf->buffer, sizeof(scratch_buf->buffer), (void *)ctx->args[1]);
    if(ret < 0){
        scratch_buf->buffer[0] = '\0'; //unknown
        return 0;
    }

    if (!(ke_state->flags & PTMX_SEEN)) {
        /*
        * Reduces cost a lot
        * Now, memory compares only if this passes.
        */
        if(!(scratch_buf->buffer[0] == '/' && scratch_buf->buffer[5] == 'p')) return 0;
        // PTY creation signal
        if(__builtin_memcmp(scratch_buf->buffer, "/dev/ptmx", 10) == 0){
            ke_state->flags |= PTMX_SEEN;
            ke_state->score += 10;
        }
    }

    return 0;
}