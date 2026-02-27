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


 SEC("tracepoint/syscalls/sys_enter_connect")
 int connect_enter_handler(struct trace_event_raw_sys_enter *ctx){
    /*
    * Access the generic sock address
    * Stack Allocation: 16 bytes
    */
    struct sockaddr sa = {};

    /*
    * This struct used for temporary hold our IPV4 or IPV6 data
    * Stack Allocation: 24 bytes
    */
    struct ke_sockaddr event = {};

    /*
    * This variable used for handle return values.
    * Stack Allocation: 4 bytes
    */
    int ret;

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



 }