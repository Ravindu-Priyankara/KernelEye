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
    fd_new = (__s32)ctx->args[1];   // casting is important because it return __u64
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
    /*
    *   If there was a valid ke_ctx_state, we used that for data insertion.
    */
    if(ke_state){
        // check the dup2 data inserted
        if(ke_state->has_dup2){
            /*
            * Split increment into explicit read-modify-write.
            *
            * Helps verifier in complex control flows where direct
            * ++ on map value fields may trigger rejection.
            *
            * Slightly increases stack usage but improves verifier stability.
            */
            __u8 count = ke_state->dup2.stdio_redirects;
            count++;
            ke_state->dup2.stdio_redirects = count;

            ke_state->dup2.last_dup2_ts = dup2_ts;
            /*
            *   setup the dup 2 valid flag
            *   Assumption:
            *       - If connect fd and dup2 old fd are equal, it helps to remove false positive events.
            */
            if(ke_state->has_conn && !ke_state->dup2_valid){
                if(old_fd == ke_state->conn.fd){
                    ke_state->dup2_valid = 1;
                }
            }
        /*
        *   No valid dup2 data, so it means the first time of the dup2 syscall was seen for this process.
        */
        }else{
            ke_state->dup2.last_dup2_ts = dup2_ts;
            ke_state->dup2.ppid = ppid;
            ke_state->dup2.stdio_redirects = 1;
            ke_state->has_dup2 = 1;
            ke_state->flags |= DUP2_FLAG;
            ke_state->start_time = dup2_ts;
            /*
            *   setup the dup 2 valid flag
            *   Assumption:
            *       - If connect fd and dup2 old fd are equal, it helps to remove false positive events.
            */
            if(ke_state->has_conn && !ke_state->dup2_valid){
                if(old_fd == ke_state->conn.fd) ke_state->dup2_valid = 1;
            }

        }
    /*
    * No valid ke_ctx_state, so it means the first time of this process context data storing.
    */
    }else{
        struct ke_ctx_state ke_new_state = {};

        ke_new_state.start_time = dup2_ts;
        ke_new_state.flags |= DUP2_FLAG;
        ke_new_state.has_dup2 = 1;
        
        //dup2 state data and removed event temp struct because this method reduces stack pressure.
        ke_new_state.dup2.last_dup2_ts = dup2_ts;
        ke_new_state.dup2.ppid = ppid;
        ke_new_state.dup2.stdio_redirects = 1;

        #ifdef DEBUG_MODE
            ke_state->dup2.oldfd = old_fd;
        #endif

        if(bpf_map_update_elem(&ctx_state_map, &cid, &ke_new_state, BPF_NOEXIST) != ERR_SUCCESS) return 0;

    }

    // for debugging
    #ifdef DEBUG_MODE
        debug_counter(1); // increment debug counter
    #endif

    return ERR_SUCCESS;
}