/* SPDX-License-Identifier: GPL-2.0 */
/*
* Kernel Eye - eBPF Runtime Security Framework
*
* File: connect_tracker.bpf.h
* Description:
*   This is an eBPF program that is used to track `connect syscall`.
*   This keep record of every process that triggered the `connect syscall`.
*
* Author: Ravindu Priyankara
* Year: 2026
*
* ============ Stack Usage ==================================
*
*  Real Verifier Stack Depth:
*    Command: sudo bpftool prog dump xlated id <id>
*    Result : Maximum stack depth = 112 bytes
*
* ==================== KernelEye eBPF Stack Map (r10) ====================
*
* r10: frame pointer (top of stack)
* │
* │  r10              : frame pointer (read-only)
* │
* |  r10 -8           : sockaddr_in6 sin6{}
* |  r10 -16          : sockaddr_in6 sin6{}
* |  r10 -24          : sockaddr_in sin{}, sockaddr_in6 sin6{}, ke_ctx_state
* |  r10 -32          : sockaddr_in sin{}, sockaddr_in6 sin6{}, pointer for hold task struct parent process data, counter value , ke_ctx_state
* |  r10 -36          : tmp used for hold ppid;
* |  r10 -64          : IPv6 first 8 byte {Network Prefix}
* |  r10 -72          : IPv6 second 8 byte {Interface ID}
* |  r10 -78          : event->addr.port
* |  r10 -80          : event->addr.family
* |  r10 -88          : event.net_ts
* |  r10 -92          : event.ppid
* |  r10 -96          : event.fd
* |  r10 -104         : ppid, key
* │
* Logical stack usage : 104 bytes
* Verifier stack depth: 112 bytes (8-byte aligned)
* Max allowed: 512 bytes -> safe 
*
* Notes:
*  - sin and sin6 reuse the same stack region (-32 area)
*  - safe because verifier sees mutually exclusive branches (family check)
*  - NOT classic lifetime-based reuse, but branch-isolated reuse
*  - All u64 writes are 8-byte aligned, verifier-friendly
*  - For larger structs, consider BPF maps instead of stack
*  - Helps debugging, verifier checks, and future maintenance
* ========================================================================
*
* ============ Instruction Count ============================
*
*  Real Instruction Count:
*    sudo bpftool prog dump xlated id <id>
*    Result: 223 instructions
*
*  Byte Size:
*    xlated 1784B  (1784 / 8 = 223 instructions)
* ===========================================================
*/


/*
* This tracepoint is triggered when programs use the `connect syscall`. 
* Argument info: sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
*/
SEC("tracepoint/syscalls/sys_enter_connect")
int connect_enter_handler(struct trace_event_raw_sys_enter *ctx){
  /*
    * Access the generic sock address
    * Stack Allocation: 16 bytes
  */
  struct sockaddr sa = {};

  /*
    * This struct used for hold our IPV4 or IPV6 data
    * Stack Allocation: 40 bytes
  */
  struct connect_event event = {};

  /*
  *   This struct used for check state already declared or not
  *   Stack Allocation: 8 bytes
  */
  struct ke_ctx_state *ke_state;

  /*
    * This variable used for handle return values.
    * Stack Allocation: 4 bytes
  */
  int ret;
  /* 
    * This variable used for hold tgid.
    * Stack Allocation: 4 bytes
  */
  __u32 pid;
  /* 
    * This variable used for hold parent tgid.
    * Stack Allocation: 4 bytes
  */
  __u32 ppid;
  /* 
    * This variable used for hold timestamp.
    * Stack Allocation: 8 bytes
  */
  __u64 net_ts;

  /*
  *  This variable used for hold context id
  *   Stack Allocation : 8 bytes
  */
  __u64 cid;

  // Check that there was data of `struct sockaddr *uservaddr`
  if(!ctx->args[1]) return 0;

  /*
  * Defined in:
  *   - helpers/common_helpers.h
  */
  pid = get_tgid(); // process id
  ppid = get_ppid(); // parent process id
  net_ts = get_trigger_time(); // connect syscall triggered time(nano seconds)

    //sanitize the data
  /*
  * Sanitize the pid and ppid.
  *
  * Defined in:
  *   - common/common/validation.h
  *
  * Purpose:
  *   - Avoid track the kernel threads or idle tasks
  */
  if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
  if(sanitize_the_pid(ppid) != ERR_SUCCESS) return 0;

  /*
  * This helper is used to get the context ID. And context ID is the key for storing our syscall flags inside the ke_ctx_state.
  */
  if(get_or_create_cid(pid, &cid) != ERR_SUCCESS) return 0;

  // Assign values to the connect event struct and later save it via the connect hash map.
  event.ppid = ppid;
  event.net_ts = net_ts;
  event.fd = (__s32)ctx->args[0]; // cast to signed 32 bit.

  // read values from map
  ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
  if(!ke_state){
    // get temporary struct for update map
    // Stack Allocation: 16 bytes
    struct ke_ctx_state zero = {};
    // quickly update the map
    bpf_map_update_elem(&ctx_state_map, &cid, &zero, BPF_NOEXIST);
    // get the pointer for access data
    ke_state = bpf_map_lookup_elem(&ctx_state_map, &cid);
    // failure cases
    if(!ke_state) return 0;

  }

  ke_state->last_time = net_ts;
  // check there was a connect flag
  if(!(ke_state->flags & CONNECT_SEEN)){
    ke_state->flags |= CONNECT_SEEN;
    ke_state->score += 5; // weak signal
  }

  // Read the generic pointer safely
  ret = bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]); // read struct sockaddr *uservaddr
  if(ret < 0)return 0;

  /*
  * get the socket family {IPV4/IPV6}
  *
  * Defined in:
  *     - helpers/connect_helpers.h
  *
  * Why?
  *     - for copy ip address, we should define the socket struct according to the socket family.
  */
  ret = get_socket_family(&sa);
  if(ret == 0) return 0;

  /*
  * According to socket family, This helps to get IPV4 or IPV6 data
  *
  * Defined in:
  *   - helpers/connect_helpers.h
  * 
  * Purpose:
  *   - parse_socket_address helper task is parse pointers to correct helpers for assign socket data.
  *   - After that, we have the IP and port.
  */
  ret = parse_socket_address(ret, (void *)ctx->args[1], &event);
  if(ret < 0) return 0;

  // scoring

  // for localhost
  if(event.addr.family == FAMILY_IPV4 && event.addr.ipv4 == LOOPBACK_IPV4 && !(ke_state->flags & LOOPBACK_IPV4_SEEN)){
    ke_state->flags |= LOOPBACK_IPV4_SEEN;
    ke_state->score += 5;
  }

  // private ip
  if(event.addr.family == FAMILY_IPV4 && !(ke_state->flags & PRIVATE_IP_SEEN)){
    if(!is_private_ipv4(event.addr.ipv4) && event.addr.ipv4 != LOOPBACK_IPV4){
      ke_state->flags |= PRIVATE_IP_SEEN;
      ke_state->score += 20;
    }
  }

  // suspicious ports
  if(!(ke_state->flags & SUSPICIOUS_PORT_SEEN)){
    if(is_suspicious_port(event.addr.port)) {
      ke_state->flags |= SUSPICIOUS_PORT_SEEN;
      ke_state->score += 25;
    }
  }

  // ephemeral port
  if(is_ephemeral_port(event.addr.port) && !(ke_state->flags & EPHEMERAL_PORT_SEEN)){
    if(ke_state->score > 30){
      ke_state->flags |= EPHEMERAL_PORT_SEEN;
      ke_state->score += 10;
    }
  }

  /*
  * Save the connect struct via connect hash map
  * Defined in:
  *   - helpers/common_helpers.h
  * Developer Note:
  *   - If the same program triggers this syscall twice, it will not update the data. So if we need to fix that, switch to the force_update helper function.
  */
  ret = update_map_element(&connect_map, &cid, &event, BPF_ANY);
  if(ret != ERR_SUCCESS) return ERR_SUCCESS;

      // for testing
    print_flags_and_score(cid, ke_state->score, ke_state->flags);

  // for debugging
  #ifdef DEBUG_MODE
      debug_counter(1); // increment debug counter
  #endif

  return ERR_SUCCESS;

}
