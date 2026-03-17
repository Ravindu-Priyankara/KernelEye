
SEC("tracepoint/syscalls/sys_enter_dup2")
int dup2_enter_handler(
    struct trace_event_raw_sys_enter *ctx
)
{
    /*
    *   This struct use for hold our dup2 data
    *   Stack Allocation: 8 bytes
    */
    struct dup2_state *event;

    /* 
    * This variable used for hols tgid.
    * Stack Allocation: 4 bytes
    */
    __u32 pid;

    /* 
    * This variable used for hols parent tgid.
    * Stack Allocation: 4 bytes
    */
    __u32 ppid;

    /*
    * This variable used for handle return values.
    * Stack Allocation: 4 bytes
    */
    int ret;

    /* 
    * This variable used for hold timestamp.
    * Stack Allocation: 8 bytes
    */
    __u64 dup2_ts;

    /*
    * This variable use for hold file descriptor;
    * Stack Allocation: 4 bytes
    */
    __u32 fd_new;

    // get the process details
    pid = get_tgid();
    ppid = get_ppid();
    dup2_ts = get_trigger_time(); // capture the timestamp
    fd_new = (__u32)ctx->args[1];   // casting is important because it return __u64


    // prevent null values
    if(validate_not_null_u32(pid) != ERR_SUCCESS) return 0;
    if(validate_not_null_u32(ppid) != ERR_SUCCESS) return 0;
    if(validate_not_null_u64(dup2_ts) != ERR_SUCCESS) return 0;
    if(validate_not_null_u32(fd_new) != ERR_SUCCESS) return 0;

    // Only track stdin/out/err
    if(fd_new > 2) return 0;

    //sanitize the data
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(sanitize_the_pid(ppid) != ERR_SUCCESS) return 0;

    // This helps to prevent always create new struct with zero initialized. Because we need increase existing redirectors.
    event = check_map_data_availability(&dup2_map, &pid);
    if(event){
        // Assign the values to the struct to pass values to the HashMap
        event->last_dup2_ts = dup2_ts;
        event->stdio_redirects++;
    }else{
        /*
        *   This struct use for hold our dup2 data
        *   Stack Allocation: 16 bytes
        */
        struct dup2_state new_state = {};
        new_state.last_dup2_ts = dup2_ts;
        new_state.ppid = ppid;
        new_state.stdio_redirects = 1;

        ret = update_map_element(&dup2_map, &pid, &new_state, BPF_ANY); // save dup2 event on dup2 map
        if(ret != ERR_SUCCESS) return ERR_SUCCESS;
    }

        /*
    * check is that reverse shell
    * conditions:
    *   - connect syscalls should be triggered
    *   - dup2 should be triggered and it must have descripter count 3 {stdin/out/err}
    */
    if(!is_reverse_shell(pid)){
        return 0;
    }
    
    // pass data to userland via ring buffer
    if(ke_reverse_shell_type_event(pid) != ERR_SUCCESS) return 0;

    // for debugging
    #ifdef DEBUG_MODE
        debug_counter(1); // increment debug counter
    #endif

    return ERR_SUCCESS;
}