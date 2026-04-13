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
*    Result : Maximum stack depth = 48 bytes
*
* ==================== KernelEye eBPF Stack Map (r10) ====================
*
* r10: frame pointer (top of stack)
* │
* │  r10              : frame pointer (read-only)
* │
* |  r10 -4           : temp hold pid for sanitize(u32)
* |  r10 -8           : pid(tgid, 4 bytes)
* |  r10 -16          : reused slot = ppid(u32), key(u32), cid (u64)
* |  r10 -24          : start of dup2_state struct, stdio_redirects (u8), padding follows
* |  r10 -32          : temp struct space (8 bytes chunk)
* |  r10 -40          : reused heavily= parent pointer (u64), new_cid (u64), struct zero padding, dup2_state temp storage
* │
* Logical stack usage : 40 bytes
* Verifier stack depth: 48 bytes (8-byte aligned)
* Max allowed: 512 bytes -> safe 
*
* Notes:
*  - few slots reused, and stdio_redirects (u8) followed by compiler-inserted padding for alignment
*  - Helps debugging, verifier checks, and future maintenance
* ========================================================================
*
* ============ Instruction Count =========================================
*
*  Real Instruction Count:
*    sudo bpftool prog dump xlated id <id>
*    Result: 167 instructions
*
*  Byte Size:
*    xlated 1336B  (1336 / 8 = 167 instructions)
* =========================================================================
*/

SEC("tracepoint/syscalls/sys_enter_dup2")
int dup2_enter_handler(
    struct trace_event_raw_sys_enter *ctx
)
{
    /*
    *   This struct used for check state already declared or not
    *   Stack Allocation: 8 bytes
    */
    struct ke_ctx_state *ke_state;

    /*
    *   For hold dup2 data
    *   Stack Allocation: 8 bytes
    */
    struct dup2_state *dup2_state;

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
    * ABI NOTE:
    *   - For ABI correctness, this should be signed.
    */
    __s32 fd_new; 

    /*
    * For hold old fd.
    * value of old fd:
    *   - can check connect fd is equal to dup2 old fd.
    *   - That helps to prevent fake connect syscalls-based bypass.
    * Stack Allocation: 4 bytes
    */
    __s32 old_fd;

    /*
    *  This variable used for hold context id
    *  Stack Allocation : 8 bytes
    */
    __u64 cid;

    /*
    * Defined in:
    *   - helpers/common_helpers.h
    */
    pid = get_tgid();
    ppid = get_ppid();
    dup2_ts = get_trigger_time(); // capture the timestamp
    fd_new = (__s32)ctx->args[1]; // casting is important because it return __u64
    old_fd = (__s32)ctx->args[0]; 


    // Only track stdin/out/err, Negative FDs are ignored for safety.
    // After converting to signed, we should also check negative cases.
    if(fd_new > 2 || fd_new < 0) return 0;

    //sanitize the data
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
    if(sanitize_the_pid(ppid) != ERR_SUCCESS) return 0;

    /*
    * This helper is used to get the context ID. And context ID is the key for storing our syscall flags inside the ke_ctx_state.
    */
    if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    if(!ke_state){
        // make a copy and update it. 
        // Stack Allocation : 16 bytes
        struct ke_ctx_state zero = {};
        bpf_map_update_elem(&ctx_state_map, &cid, &zero, BPF_NOEXIST);
        ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
        if(!ke_state) return 0;
    }

    // update the map
    ke_state->last_time = dup2_ts;
    ke_state->flags |= DUP2_SEEN;

    // check dup2 map data availability
    dup2_state = bpf_map_lookup_elem(&dup2_map, &pid);
    if(!dup2_state){
        // stack Allocation: 24 bytes
        struct dup2_state new_dup2_state = {};
        // for counter redirects
        new_dup2_state.stdio_redirects = 0;
        bpf_map_update_elem(&dup2_map, &cid, &new_dup2_state, BPF_NOEXIST);
        dup2_state = bpf_map_lookup_elem(&dup2_map, &cid);
        if(!dup2_state) return 0;
    }

    // Update the dup2_state
    dup2_state->last_dup2_ts = dup2_ts;
    dup2_state->ppid = ppid;
    dup2_state->oldfd = old_fd;
    dup2_state->stdio_redirects++;

    // for debugging
    #ifdef DEBUG_MODE
        debug_counter(1); // increment debug counter
    #endif

    return ERR_SUCCESS;
}