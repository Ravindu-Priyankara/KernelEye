/* SPDX-License-Identifier: GPL-2.0 */
/*
* Kernel Eye - eBPF Runtime Security Framework
*
* File: dup2_tracker.bpf.h
* Description:
*   This is an eBPF program that is used to track `dup2 syscall`.
*   This keep record of every process that triggered the `dup2 syscall`.
*
* Author: Ravindu Priyankara
* Year: 2026
*
* ============ Stack Usage ===============================================
*
*  Real Verifier Stack Depth:
*    Command: sudo bpftool prog dump xlated id <id>
*    Result : Maximum stack depth = 32 bytes
*
* ==================== KernelEye eBPF Stack Map (r10) ====================
*
* r10: frame pointer (top of stack)
* │
* │  r10 -0           : scratch / temporary usage
* │
* │  r10 -4           : __u32 ppid
* |  r10 -8           : __u32 pid
* |  r10 -12          : __u8 dup2_state.stdio_redirects
* |  r10 -16          : __u32 dup2_state.ppid
* |  r10 -24          : __u64 dup2_state.last_dup2_ts
* │
* Total stack used: 32 bytes
* Max allowed: 512 bytes -> safe 
*
* Notes:
*  - r10 -12 offset has 1 byte but veryfier align it with additional 3 bytes.
*  - Helps debugging, verifier checks, and future maintenance
* ========================================================================
*
* ============ Instruction Count =========================================
*
*  Real Instruction Count:
*    sudo bpftool prog dump xlated id <id>
*    Result: 82 instructions
*
*  Byte Size:
*    xlated 656B  (656 / 8 = 82 instructions)
* =========================================================================
*/

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
    *   This struct used for check state already declared or not
    *   Stack Allocation: 8 bytes
    */
    struct ke_ctx_state *ke_state;

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

    /*
    *  This variable used for hold context id
    *   Stack Allocation : 8 bytes
    */
    __u64 cid;

    /*
    * Defined in:
    *   - helpers/common_helpers.h
    */
    pid = get_tgid();
    ppid = get_ppid();
    dup2_ts = get_trigger_time(); // capture the timestamp
    fd_new = (__u32)ctx->args[1];   // casting is important because it return __u64


    // Only track stdin/out/err, and there were no negative file descriptors.
    if(fd_new > 2) return 0;

    //sanitize the data
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(sanitize_the_pid(ppid) != ERR_SUCCESS) return 0;

    /*
    * This helper is used to get the context ID. And context ID is the key for storing our syscall flags inside the ke_ctx_state.
    */
    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    // check already stored or not
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        // first time seeing this project{zero initialized}
        struct ke_ctx_state ke_new_state = {};

        // assign the values
        ke_new_state.flags |= CONNECT_FLAG;
        ke_new_state.start_time = net_ts;

        /*
        *   No need to use the update map element helper. because we already checked this state.
        *
        *   Developer Note:
        *       - Used `BPF_NOEXIST` for prevent race condition.
        *       ex:
        *           Thread A -> No ke_ctx_state -> create new state
        *           Thread B -> No ke_ctx_state -> create new state
        * 
        *           Thread A -> Assign values to state -> Update the map
        *           Thread B -> Assign values to state -> Update the map
        *
        *           So both threads will update, and the issue is timestamp will be overwritten with the last thread's timestamp.
        */
        if(bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST) != 0) return 0;

    }else {
        // already exists -> just update, not reset
        ke_state->flags |= CONNECT_FLAG;
        ke_state->start_time = net_ts;
    }

    // This helps to prevent always create new struct with zero initialized. Because we need increase existing redirectors.
    event = check_map_data_availability(&dup2_map, &pid);
    if(event){
        // rewrite the values if data exists
        event->last_dup2_ts = dup2_ts;
        event->stdio_redirects++;   // for a reverse shell, we strictly check file descriptor >= 2.
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

    // for debugging
    #ifdef DEBUG_MODE
        debug_counter(1); // increment debug counter
    #endif

    return ERR_SUCCESS;
}