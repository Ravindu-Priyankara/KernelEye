/* SPDX-License-Identifier: GPL-2.0 */
/*
* Kernel Eye - eBPF Runtime Security Framework
*
* File: bprm_check_security_lsm.bpf.h
* Description:
*   This is an eBPF program that is used to enforce.
*
* Author: Ravindu Priyankara
* Year: 2026
*
* ============ Stack Usage ==================================
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
* |  r10 -4           : tgid(__u32);
* |  r10 -16          : key(__u32);
* |  r10 -24          : ke_ctx_state(struct 24 bytes)
* |  r10 -40          : new_cid(ptr __u64);
* │
* Logical stack usage : 40 bytes
* Verifier stack depth: 48 bytes (8-byte aligned)
* Max allowed: 512 bytes -> safe 
*
*
* ============ Instruction Count ============================
*
*  Real Instruction Count:
*    sudo bpftool prog dump xlated id <id>
*    Result: 122 instructions
*
*  Byte Size:
*    xlated 976B  (976 / 8 = 122 instructions)
* ===========================================================
*/

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