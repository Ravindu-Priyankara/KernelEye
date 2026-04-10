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
*    Result : Maximum stack depth = 48 bytes
*
* ==================== KernelEye eBPF Stack Map (r10) ====================
*
* r10: frame pointer (top of stack)
* │
* │  r10               : frame pointer (read-only)
* │
* |  r10 -4            : tmp hold ppid(u32)
* |  r10 -8            : key(u32)
* |  r10 -16           : reused slot, ppid(u32), key(u32), cid(u64), follows paadding
* |  r10 -24           : temporary zero struct buffer
* |  r10 -32           : heavily reused slot, pointer for parent struct(8 bytes), reuse for cid(u64), temp key storage
* |  r10 -40           : tmp_event pointer, reuse for cid(u64)
* │
* Logical stack usage : 40 bytes
* Verifier stack depth: 48 bytes (8-byte aligned)
* Max allowed: 512 bytes -> safe 
*
* Notes:
*  - Helps debugging, verifier checks, and future maintenance
* ========================================================================
*
* ============ Instruction Count =========================================
*
*  Real Instruction Count:
*    sudo bpftool prog dump xlated id <id>
*    Result: 352 instructions
*
*  Byte Size:
*    xlated 2816B  (2816 / 8 = 352 instructions)
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
        // Stack Allocation: 16 bytes
        struct ke_ctx_state zero = {};
        bpf_map_update_elem(&ctx_state_map, &cid, &zero, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    // update the values
    ke_state->last_time = execve_ts;
    ke_state->flags |= EXECVE_SEEN;

    // Copy scratchpad -> HASH map (persistent storage)
    if(force_update_map_element(&execve_hash_map, &cid, tmp_event, BPF_ANY) != ERR_SUCCESS) return 0;

    /*
    * check is that suspicious event
    * conditions:
    *   - connect, dup2, execve syscalls should be triggered
    *   - dup2 should be triggered and it must have descripter count 2 or higher {stdin/out/err}
    */
    if(!identify_the_suspicious_event(cid)) return 0;
    
    // pass data to userland via ring buffer
    if(ke_reverse_shell_type_event(cid, pid) != ERR_SUCCESS) return 0;

    // for debugging
    #ifdef DEBUG_MODE
      debug_counter(1); // increment debug counter
    #endif

    return 0;
}