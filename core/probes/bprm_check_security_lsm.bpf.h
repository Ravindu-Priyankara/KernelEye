
SEC("lsm/bprm_check_security")
int BPF_PROG(trace_process_execute, struct linux_binprm *bprm){

    __u64 cid;
    __u64 execve_ts;
    __u32 pid;

    struct ke_ctx_state *ke_state;
    char filename[64];

    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(bprm, filename));

    // check filename
    if (filename[0] == 0) return 0; 

    pid = get_tgid();
    execve_ts = get_trigger_time();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;

    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    // get the context state
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        struct ke_ctx_state ke_new_state = {};

        bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    apply_decay(ke_state, execve_ts);
    ke_state->last_time = execve_ts;
    if(!(ke_state->flags & EXECVE_SEEN)){
        ke_state->flags |= EXECVE_SEEN;
        ke_state->score += 5;
    }

    const char *bin = filename + 9;
    if (filename[0]=='/' && filename[1]=='u' && filename[2]=='s' && 
        filename[3]=='r' && filename[4]=='/' && filename[5]=='b' &&
        filename[6]=='i' && filename[7]=='n' && filename[8]=='/') {

        switch(bin[0]){ 
            case 'p':{ // python | perl | php
                if(!(ke_state->flags & SUSPICIOUS_FILENAME_SEEN) && (ke_state->flags & CONNECT_SEEN)){
                    ke_state->flags |= SUSPICIOUS_FILENAME_SEEN;
                    ke_state->score += 10; 
                }

                if(!(ke_state->flags & SUSPICIOUS_FILENAME_SEEN) && (ke_state->flags & CONNECT_SEEN) && (ke_state->flags & FD_REDERECTS_SEEN)){
                    ke_state->flags |= SUSPICIOUS_FILENAME_SEEN;
                    ke_state->score += 20; 
                }

                break;
            }
        }
    }

    #ifdef DEBUG_MODE
        debug_counter(1);
    #endif

    return 0;
}