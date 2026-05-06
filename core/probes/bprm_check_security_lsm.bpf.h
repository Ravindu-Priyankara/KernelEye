
SEC("lsm/bprm_check_security")
int BPF_PROG(trace_process_execute, struct linux_binprm *bprm){

    __u64 cid;
    __u32 pid;

    struct ke_ctx_state *ke_state;

    pid = get_tgid();
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

    if(ke_state->stage >= STAGE_HIGH_RISK){
        //print_flags_and_score(cid, ke_state->flags, ke_state->stage);
        
        // pass to ringbuffer
        emit_event(ke_state->stage, ke_state->flags);

        bpf_send_signal(SIGKILL);
        
        return -EPERM;
    }

    #ifdef DEBUG_MODE
        debug_counter(1);
    #endif

    return 0;
}