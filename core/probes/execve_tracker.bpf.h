

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_enter_handler(struct trace_event_raw_sys_enter *ctx){

    /*
    *   This variable use for hold tgid.
    *   Stack Allocation: 4 bytes
    */
    __u32 pid;
    /*
    *   This variable use for hold parent tgid
    *   Stack Allocation: 4 bytes
    */
    __u32 ppid;

    /*
    *   This variable is used for passing the key to the PERCPU map.
    *   Stack Allocation: 4 bytes
    */
    __u32 key = 0;

    /*
    *   This variable use for hold execve trigger timestamp
    *   Stack Allocation: 8 bytes
    */
    __u64 execve_ts;

    /*
    *   This struct hold the execve data.
    *   Stack Allocation: 8 bytes
    */
    struct execve_event *tmp_event;


    // Assign the values
    pid = get_tgid();
    ppid = get_ppid();
    execve_ts = get_trigger_time();

    // validation for prevent null values
    if(validate_not_null_u32(pid) != ERR_SUCCESS) return 0;
    if(validate_not_null_u32(ppid) != ERR_SUCCESS) return 0;
    if(validate_not_null_u64(execve_ts) != ERR_SUCCESS) return 0;

    // sanitize the pid and ppid
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(sanitize_the_pid(ppid) != ERR_SUCCESS) return 0;

    // check percpu map available
    tmp_event = check_map_data_availability(&tmp_execve_map, &key);
    if(!tmp_event) return 0;

    // copy to scratchpad(PERCPU ARRAY)
    if(bpf_probe_read_user_str(tmp_event->filename, sizeof(tmp_event->filename), (void *)ctx->args[0]) < 0) return 0;

    // assign values{ppid, execution time}
    tmp_event->ppid = ppid;
    tmp_event->execve_ts = execve_ts;

    // Copy scratchpad → HASH map (persistent storage)
    if(update_map_element(&tmp_execve_hash_map, &pid, tmp_event, BPF_ANY) != ERR_SUCCESS) return 0;

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int execve_exit_handler(struct trace_event_raw_sys_exit *ctx){
    /*
    *   For hold return value
    *   Stack Allocation: 4 bytes
    */
    long ret;

    /*
    *   for hold pid value
    *   Stack Allocation: 4 bytes
    */
    __u32 pid;

    //get the return value
    ret = ctx->ret;

    // get the pid
    pid = get_tgid();

    //prevent null values 
    if(validate_not_null_u32(pid) != ERR_SUCCESS) return ERR_SUCCESS;
    if(validate_not_null_long(ret) != ERR_SUCCESS) return ERR_SUCCESS;

    //sanitize the pid
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return ERR_SUCCESS;

    // update the correct map
    ret = identify_the_return_request_type(ret, EXECVE, pid);
    if(ret != ERR_SUCCESS) return ERR_SUCCESS;

    // remove the temp map data
    ret = delete_map_elements(&tmp_execve_hash_map, &pid);
    if(ret != ERR_SUCCESS) return ERR_SUCCESS;

    // check is that suspiecious
    if(check_map_data_availability(&connect_map ,&pid)){
        if(ke_reverse_shell_type_event(pid) != ERR_SUCCESS) return ERR_SUCCESS;
    }

    return ERR_SUCCESS;
}
