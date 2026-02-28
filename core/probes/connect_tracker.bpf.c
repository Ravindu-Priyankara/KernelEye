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
*/

#include "../common/common_headers.h"
#include "../common/common_structs.h"
#include "../maps/maps.h"
#include "../helpers/common_helpers.h"
#include "../helpers/connect_helpers.h"
#include "../common/common_validation.h"
#include "../common/common_status.h"


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
    * This variable used for hols timestamp.
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

  // for get tgid
  pid = get_tgid();
  ppid = get_ppid();
  net_ts = bpf_ktime_get_ns();

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
  ret = update_hash_map_element(&connect_map, &pid, &event, BPF_ANY);
  if(ret != ERR_SUCCESS) return ERR_SUCCESS;

  return ERR_SUCCESS;

}

char LICENSE[] SEC("license") = "GPL";