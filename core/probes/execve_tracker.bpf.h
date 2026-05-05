
SEC("tracepoint/syscalls/sys_enter_execve")
int execve_enter(struct trace_event_raw_sys_enter *ctx){

    //  needs to cast because `trace_event_raw_sys_enter` has args type is unsigned long
    const char *filename = (const char *)ctx->args[0]; 
    const char *const *argv = (const char *const *)ctx->args[1];
    const char *const *envp = (const char *const *)ctx->args[2];

    __u64 cid;
    __u64 execve_ts;
    __u32 key = 0;
    __u32 pid;
    const char *p;
    struct scratch_buf *sb;
    struct ke_ctx_state *ke_state;
    int ret;
    int len;
    int name_idx = 0;

    // assign the data
    pid = get_tgid();
    execve_ts = get_trigger_time();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    // extract the state
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        struct ke_ctx_state ke_new_state = {};

        bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    // assign data to map
    ke_state->last_time = execve_ts;
    if(!(ke_state->flags & EXECVE_SEEN)){
        update_state(ke_state, EXECVE_SEEN);
    }

    // selected events pass to ring buffer
    if (ke_state->stage == STAGE_BEHAVIORAL)
        emit_event(STAGE_BEHAVIORAL, ke_state->flags);

    else if (ke_state->stage == STAGE_HIGH_RISK)
        emit_event(STAGE_HIGH_RISK, ke_state->flags);

    else if (ke_state->stage == STAGE_CONFIRMED)
        emit_event(STAGE_CONFIRMED, ke_state->flags);

    // get the buffer
    sb = bpf_map_lookup_elem(&scratch_buf_map, &key);
    if(!sb) return 0;

    // extract the filename
    len = bpf_probe_read_user_str(sb->buffer, SB_SIZE, filename);
    if(len <= 1) return 0;

    /*
    *   for extract last name:
    *       - Usually filename came like this
    *           - /usr/bin/last_name
    *           - /bin/last_name
    */
    #pragma unroll
    for(int i = 0; i < SB_SIZE; i++){
        if(i < len && sb->buffer[i] == '/' && (i+1) < SB_SIZE){// need to prove bounds
            name_idx = i + 1;
        } 
    }

    // check sh
    if(
        /*
        *   sh\0 thats why 3 bytes. otherwise it will some letter + null terminator
        */
        name_idx + 2 <= len
    ){
        if(__builtin_memcmp(&sb->buffer[name_idx], "sh", 2) == 0){
            update_state(ke_state, INTERPRETER_REAL_SEEN);
        }
    }

    // check php
    if(
        name_idx + 3 <= len
    ){
        if(__builtin_memcmp(&sb->buffer[name_idx], "php", 3) == 0){
            update_state(ke_state, INTERPRETER_REAL_SEEN);
        }
    }

    // check bash and perl
    if(
        name_idx + 4 <= len // need to prove no OOB
    ){
        if(__builtin_memcmp(&sb->buffer[name_idx], "bash", 4) == 0){
            update_state(ke_state, INTERPRETER_REAL_SEEN);
        }

        if(__builtin_memcmp(&sb->buffer[name_idx], "perl", 4) == 0){
            update_state(ke_state, INTERPRETER_REAL_SEEN);
        }
    }

    // check python
    if(
        name_idx + 6 <= len
    ){
        if(__builtin_memcmp(&sb->buffer[name_idx], "python", 6) == 0){
            update_state(ke_state, INTERPRETER_REAL_SEEN);
        }
    }

    // extract the argv[0] pointer
    ret = bpf_probe_read_user(&p, sizeof(p), &argv[0]);
    if(ret < 0) return 0; 

    // check first argument
    if((p) && !(ke_state->flags & INTERPRETER_ARGV_SEEN)){
        len = bpf_probe_read_user_str(sb->buffer, SB_SIZE, p);
        if(len > 0){

            if(
                (__builtin_memcmp(sb->buffer, "bash", 4) == 0) || 
                (__builtin_memcmp(sb->buffer, "python", 6) == 0) ||
                (__builtin_memcmp(sb->buffer, "perl", 4) == 0) ||
                (__builtin_memcmp(sb->buffer, "php", 3)) ||
                (__builtin_memcmp(sb->buffer, "sh", 2) == 0)
            ){
                update_state(ke_state, INTERPRETER_ARGV_SEEN);
            }
        }

    }

    //extract the argv[1] pointer
    ret = bpf_probe_read_user(&p, sizeof(p), &argv[1]);
    if(ret < 0) return 0;

    // check second argument
    if((p) && !(ke_state->flags & SHELL_INLINE_SEEN)){
        len = bpf_probe_read_user_str(sb->buffer, SB_SIZE, p);
        if(len > 0){

            // bash -i | python -c | perl -e
            if(sb->buffer[0] == '-' && 
                ((sb->buffer[1] == 'c') || 
                (sb->buffer[1] == 'i') || 
                (sb->buffer[1] == 'e') || 
                (sb->buffer[1] == 'l')))
            {
                update_state(ke_state, SHELL_INLINE_SEEN);
            }
        }
    }

    // extract the argv[2] pointer
    ret = bpf_probe_read_user(&p, sizeof(p), &argv[2]);
    if(ret < 0) return 0;

    // check third argument
    if((p) && !(ke_state->flags & NETWORK_INTENT_SEEN)){
        len = bpf_probe_read_user_str(sb->buffer, SB_SIZE, p);
        if(len < 0) return 0;
        
        // /dev/tcp
        if (len >= 8 &&
            sb->buffer[0] == '/' &&
            sb->buffer[1] == 'd' &&
            sb->buffer[2] == 'e' &&
            sb->buffer[3] == 'v' &&
            sb->buffer[4] == '/' &&
            sb->buffer[5] == 't' &&
            sb->buffer[6] == 'c' &&
            sb->buffer[7] == 'p') {

            update_state(ke_state, NETWORK_INTENT_SEEN);
            return 0;
        }

        // socket
        if (len >= 6 &&
            __builtin_memcmp(sb->buffer, "socket", 6) == 0) {

            update_state(ke_state, NETWORK_INTENT_SEEN);
            return 0;
        }

        // connect
        if (len >= 7 &&
            __builtin_memcmp(sb->buffer, "connect", 7) == 0) {

            update_state(ke_state, NETWORK_INTENT_SEEN);
            return 0;
        }
    }

    return 0;
}