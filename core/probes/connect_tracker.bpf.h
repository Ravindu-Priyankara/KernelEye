/*
 * Kernel Eye - eBPF Runtime Security Framework
 * SPDX-License-Identifier: MIT
 *
 * File: connect_tracker.bpf.c
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
 *    Result : Maximum stack depth = 100 bytes
 *
 *  Manual Stack Estimation (Pre-verifier Calculation):
 *    sys_enter_connect:
 *        - IPv4 path  ≈ 120 bytes
 *        - IPv6 path  ≈ 136 bytes
 *
 *    sys_exit_connect:
 *        - ≈ 96 bytes
 *
 *  Note:
 *    Manual calculations are approximate and may differ due to
 *    compiler optimizations, stack slot reuse, and verifier analysis.
 *
* 
 * ============ Instruction Count ============================
 *
 *  Real Instruction Count:
 *    sudo bpftool prog dump xlated id <id>
 *    Result: 143 instructions
 *
 *  Byte Size:
 *    xlated 1144B  (1144 / 8 = 143 instructions)
 * ===========================================================
*/


/*
* This tracepoint is triggered when programs use the `connect syscall`. 
* Argument info: cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
* If IPV4:
*   1. Stack Allocation: 120 bytes
* If IPV6
*   1. Stack Allocation: 136 bytes
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

  // Check that there was data of `struct sockaddr *uservaddr`
  if(!ctx->args[1]) return 0;

  // Read the generic pointer safely
  ret = bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]); // read struct sockaddr *uservaddr
  if(ret < 0)return 0;

  // Socket family identifier
  ret = get_socket_family(&sa);
  if(ret == 0) return 0;

  // According to socket family, This helps to get IPV4 or IPV6 data
  ret = parse_socket_address(ret, (void *)ctx->args[1], &event);
  if(ret < 0) return 0;

  pid = get_tgid(); // process id
  ppid = get_ppid(); // parent process id
  net_ts = get_trigger_time(); // connect syscall triggered time(nano seconds)

  // prevent null values
  if(validate_not_null_u32(pid) != ERR_SUCCESS) return 0;
  if(validate_not_null_u32(ppid) != ERR_SUCCESS) return 0;
  if(validate_not_null_u64(net_ts) != ERR_SUCCESS) return 0;

  //sanitize the data
  if(sanitize_the_pid(pid) != ERR_SUCCESS) return 0;
  if(sanitize_the_pid(ppid) != ERR_SUCCESS) return 0;

  // assign values
  event.ppid = ppid;
  event.net_ts = net_ts;

  //update the hash map
  ret = update_map_element(&connect_map, &pid, &event, BPF_ANY); // save connection details on connect map
  if(ret != ERR_SUCCESS) return ERR_SUCCESS;

  // for debugging
  #ifdef DEBUG_MODE
      debug_counter(1); // increment debug counter
  #endif

  return ERR_SUCCESS;

}
