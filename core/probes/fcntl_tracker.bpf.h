SEC("tracepoint/syscalls/sys_enter_fcntl")
int fcntl_handler(struct trace_event_raw_sys_enter *ctx){

    __u64 cid;
    __u64 fcntl_ts;
    __u32 pid;
    int fd;
    unsigned int cmd;
    unsigned long arg;

    struct ke_ctx_state *ke_state;

    pid = get_tgid();
    fcntl_ts = get_trigger_time();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;

    // extract data
    fd = (int)ctx->args[0];
    cmd = (unsigned int)ctx->args[1];
    arg = (unsigned long)ctx->args[2];

    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        struct ke_ctx_state ke_new_state = {};
        ke_new_state.fd_mutation_count = 0; // for increment

        bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    if(!(ke_stage->flags & SOCKET_SEEN)) return 0;
    
    ke_state->last_time = fcntl_ts;
    if(!(ke_state->flags & FCNTL_SEEN)){
        update_state(ke_state, FCNTL_SEEN);
    }

    // fd duplication attempt
    if(cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC){
        ke_state->fd_mutation_count++; // increment the fd counter

        if(!(ke_state->flags & FD_DUPLICATION_SEEN) && (ke_state->flags & CONNECT_SEEN)){
            update_state(ke_state, FD_DUPLICATION_SEEN);
        }

        // STDIO hijack suspicion
        if(!(ke_state->flags & STDIO_HIJACK_SEEN) && arg <= 2){
            update_state(ke_state, STDIO_HIJACK_SEEN);
        }
    }

    if ((ke_state->flags & CONNECT_SEEN) && ke_state->fd_mutation_count > 0 && !(ke_state->flags & FD_REWIRING_SEEN)) {
        update_state(ke_state, FD_REWIRING_SEEN);
    }

    return 0;
}