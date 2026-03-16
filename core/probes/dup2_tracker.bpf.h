
SEC("tracepoint/syscalls/sys_enter_dup2")
int dup2_enter_handler(
    struct trace_event_raw_sys_enter *ctx
)
{
    /*
    *   This struct use for hold our dup2 data
    *   Stack Allocation: 16 bytes
    */
    struct dup2_event event = {};

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
    * These variables used for hold file descriptors
    * Stack Allocation: 8 bytes
    */
    __u32 fd_old;
    __u32 fd_new;

    // get the process details
    pid = get_tgid();
    ppid = get_ppid();
    dup2_ts = get_trigger_time(); // capture the timestamp

    // get the file descriptors
    fd_old = (__u32)ctx->args[0];
    fd_new = (__u32)ctx->args[1];

    // Only track stdin/out/err
    if(fd_new > 2) return 0;

    // prevent null values
    if(validate_not_null_u32(pid) != ERR_SUCCESS) return 0;
    if(validate_not_null_u32(ppid) != ERR_SUCCESS) return 0;
    if(validate_not_null_u64(dup2_ts) != ERR_SUCCESS) return 0;
    if(validate_not_null_u32(fd_old) != ERR_SUCCESS) return 0;
    if(validate_not_null_u32(fd_new) != ERR_SUCCESS) return 0;

    //sanitize the data
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(sanitize_the_pid(ppid) != ERR_SUCCESS) return 0;

    // Assign the values to the struct to pass values to the HashMap
    event.dup2_ts = dup2_ts;
    event.ppid = ppid;
    event.fd_old = fd_old;
    event.fd_new = fd_new;

    // update the hashmap
    ret = update_map_element(&dup2_map, &pid, &event, BPF_ANY); // save dup2 event on dup2 map
    if(ret != ERR_SUCCESS) return ERR_SUCCESS;

    // for debugging
    #ifdef DEBUG_MODE
        debug_counter(1); // increment debug counter
    #endif

    return ERR_SUCCESS;
}