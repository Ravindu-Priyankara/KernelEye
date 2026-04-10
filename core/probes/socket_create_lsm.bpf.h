
SEC("lsm/socket_create")
int BPF_PROG(trace_socket_create, int family, int type, int protocol, int kern){
    
    /*
    *   for holds context id
    *   Stack allocation: 8 bytes
    */
    __u64 cid;

    /*
    *   for update last time
    *   stack allocation: 8 bytes
    */
    __u64 sock_ts;

    /*
    *   for hold thread group id;
    *   stack allocation: 4 bytes
    */
    __u32 pid;

    /*
    *   pointer for extract context state map entries
    *   stack Allocation: 8 bytes
    */
    struct ke_ctx_state *ke_state;

    /*
    *   kern 1 = kernel thread
    *   kern 0 = user process
    *
    *   We always kernel threads allowed.
    */
    if(kern) return 0;

    // pid handling
    pid = get_tgid();
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return -EPERM;

    // sock timestamp
    sock_ts = get_trigger_time();

    // get a context id
    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    // get the state map data
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        /*
        *   create new struct for hold state data
        *   Stack Allocation: 16 bytes
        */
        struct ke_ctx_state new_state = {};

        // update the map
        bpf_map_update_elem(&ctx_state_map, &cid, &new_state, BPF_NOEXIST);

        // pointing to updated map
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    // assign state values
    ke_state->last_time = sock_ts;
    ADVANCE_STAGE(ke_state->stage, STAGE_SOCKET);
    // first socket creation for add score and flag
    if(!(ke_state->flags & SOCKET_FLAG)){
        ke_state->flags |= SOCKET_FLAG;
        ke_state->score += 10;
    }

    #ifdef DEBUG_MODE
        debug_counter(1);
    #endif
    
    // future: add socket rate tracking
    return 0;
}