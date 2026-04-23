
SEC("kprobe/__x64_sys_execve")
int execve_enter(struct pt_regs *ctx){

    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    const char *const *argv = (const char *const *)PT_REGS_PARM2(ctx);
    const char *const *envp = (const char *const *)PT_REGS_PARM3(ctx);

    __u64 cid;
    __u64 execve_ts;
    __u32 key = 0;
    __u32 pid;
    const char *p;
    struct scratch_buf *sb;
    struct ke_ctx_state *ke_state;
    int ret;
    int len;

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
    len = bpf_probe_read_user_str(sb->buffer, 256, filename);
    if(len > 0){
        if(
            (sb->buffer[0] == 'b' && sb->buffer[1] == 'a') || 
            (sb->buffer[0] == 'p' && sb->buffer[1] == 'y') ||
            (sb->buffer[1] == 'e' && sb->buffer[3] == 'l') ||
            (sb->buffer[1] == 'h' && sb->buffer[2] == 'p') ||
            (sb->buffer[0] == 's' && sb->buffer[1] == 'h')
        ){
            update_state(ke_state, INTERPRETER_REAL_SEEN);
        }
    }

    // extract the argv[0] pointer
    ret = bpf_probe_read_user(&p, sizeof(p), &argv[0]);
    if(ret < 0) return 0; 

    // check first argument
    if((p) && !(ke_state->flags & INTERPRETER_ARGV_SEEN)){
        len = bpf_probe_read_user_str(sb->buffer, 256, p);
        if(len > 0){

            if(
                (sb->buffer[0] == 'b' && sb->buffer[1] == 'a') || 
                (sb->buffer[0] == 'p' && sb->buffer[1] == 'y') ||
                (sb->buffer[1] == 'e' && sb->buffer[3] == 'l') ||
                (sb->buffer[1] == 'h' && sb->buffer[2] == 'p') ||
                (sb->buffer[0] == 's' && sb->buffer[1] == 'h')
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
        len = bpf_probe_read_user_str(sb->buffer, 256, p);
        if(len > 0){

            // bash -i | python -c | perl -e
            if(sb->buffer[0] == '-' && ((sb->buffer[1] == 'c') || (sb->buffer[1] == 'i') || (sb->buffer[1] == 'e'))){
                update_state(ke_state, SHELL_INLINE_SEEN);
            }
        }
    }

    // extract the argv[2] pointer
    ret = bpf_probe_read_user(&p, sizeof(p), &argv[2]);
    if(ret < 0) return 0;

    // check third argument
    if((p) && !(ke_state->flags & NETWORK_INTENT_SEEN)){
        len = bpf_probe_read_user_str(sb->buffer, 256, p);
        if(len > 0){

            if(
                ((sb->buffer[1] == 'd') && (sb->buffer[3] == 'v') && (sb->buffer[5] == 't') && (sb->buffer[7] == 'p')) || // /dev/tcp
                ((sb->buffer[0] == 's') && (sb->buffer[3] == 'k')) || // socket 
                ((sb->buffer[0] == 'c') && (sb->buffer[2] == 'n')) // connect
            ){
                update_state(ke_state, NETWORK_INTENT_SEEN);
            }
        }
    }

    return 0;
}