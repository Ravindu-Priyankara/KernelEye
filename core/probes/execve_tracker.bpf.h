/* SPDX-License-Identifier: GPL-2.0 */
/*
* Kernel Eye - eBPF Runtime Security Framework
*
* File: execve_tracker.bpf.h
* Description:
*   This is an eBPF program that is used to track `execve syscall`.
*   This keep record of every process that triggered the `execve syscall`.
*
* Author: Ravindu Priyankara
* Year: 2026
*
* ============ Stack Usage ===============================================
*
*  Real Verifier Stack Depth:
*    Command: sudo bpftool prog dump xlated id <id>
*    Result : Maximum stack depth = 24 bytes
*
* ==================== KernelEye eBPF Stack Map (r10) ====================
*
* r10: frame pointer (top of stack)
* │
* │  r10 -0           : scratch / temporary usage
* │
* |  r10 -8            : struct task_struct *parent, pointer for extract parent ppid(helpers/common_helpers.h)
* |  r10 -12           : __u32 ppid {inside the parent ppid extraction helper function}
* |  r10 -16           : __u32 pid
* │  r10 -20           : __u32 key
* │
* Total stack used: 24 bytes
* Max allowed: 512 bytes -> safe 
*
* Notes:
*  - Stack size = max depth reached thats why additional 4 bytes have => [8 bytes pointer][4 bytes ppid][4 bytes pid][4 bytes key][4 bytes unused] , usage = 20 bytes but allocation 24 bytes
*  - Helps debugging, verifier checks, and future maintenance
* ========================================================================
*
* ============ Instruction Count =========================================
*
*  Real Instruction Count:
*    sudo bpftool prog dump xlated id <id>
*    Result: 277 instructions
*
*  Byte Size:
*    xlated 2216B  (2216 / 8 = 277 instructions)
* =========================================================================
*/

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

    /*
    *   This struct used for check state already declared or not
    *   Stack Allocation: 8 bytes
    */
    struct ke_ctx_state *ke_state;

    /*
    *   This variable use for error handling.
    *   Stack Allocation: 4 bytes
    */
    int ret;

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
    execve_ts = get_trigger_time();

    // sanitize the pid and ppid
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(sanitize_the_pid(ppid) != ERR_SUCCESS) return 0;

    // check percpu map available
    tmp_event = check_map_data_availability(&tmp_execve_map, &key);
    if(!tmp_event) return 0;

    /*
    * BUG NOTE:
    * Previously, execve events were dropped because:
    * - argv/envp could be NULL
    * - bpf_probe_read_user_str fails silently in that case
    * - map update logic skipped duplicate keys
    *
    * Fix:
    * - handle NULL safely
    * - ensure event always written
    * - force update maps
    */
    // copy to scratchpad(PERCPU ARRAY), This removed stack pressure otherwise it eats half of the eBPF stack limit.{filename[256]}
    ret = bpf_probe_read_user_str(tmp_event->filename, sizeof(tmp_event->filename), (void *)ctx->args[0]);
    if(ret < 0){
        tmp_event->filename[0] = 0; // mark filename as unknown
    }

    // assign values{ppid, execution time}
    tmp_event->ppid = ppid;
    tmp_event->execve_ts = execve_ts;

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
        ke_new_state.flags |= EXECVE_FLAG;
        ke_new_state.start_time = execve_ts;

        /*
        *   We just removed old __builtin_memcpy. because we use a stable ABI and the same struct. So we can copy data without memcpy.
        *   Benefits:
        *       - reduce the verifier complexity.
        */
        ke_new_state.exec = *tmp_event;
        ke_new_state.has_exec = 1;
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
        ke_state->flags |= EXECVE_FLAG;
        ke_state->start_time = execve_ts;

        ke_state->exec = *tmp_event;
        if(!ke_state->has_exec) ke_state->has_exec = 1;
    }

    // Copy scratchpad -> HASH map (persistent storage)
    if(force_update_map_element(&execve_hash_map, &pid, tmp_event, BPF_ANY) != ERR_SUCCESS) return 0;

    /*
    * check is that reverse shell
    * conditions:
    *   - connect syscalls should be triggered
    *   - dup2 should be triggered and it must have descripter count 2 or higher {stdin/out/err}
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

    return 0;
}