/*
 * Kernel Eye - eBPF Runtime Security Framework
 * SPDX-License-Identifier: MIT
 *
 * File: common_structs.h
 * Description:
 *   Shared event structures between eBPF programs and userland loader.
 *   These structs define the ABI contract for map storage and ring buffer
 *   streaming events. Layout must remain stable.
 *
 * Author: Ravindu Priyankara
 * Year: 2026
 */

#pragma once

/* Only include linux/types.h for userland,
 * BPF programs already get types from vmlinux.h
 */
#ifndef __BPF__
#include <linux/types.h>
#include <stddef.h>
#endif

// used for support ipv4 + ipv6
// total bytes 24 bytes
struct ke_sockaddr {
    __u16 family;   // socket family

    union {
        __u32 ipv4;        // AF_INET
        __u8  ipv6[16];    // AF_INET6
    };

    __u16 port;
};

/*************************************
******* Events Holding Structs *******
**************************************/

// This struct use for tracking connect events with hashmap
// Total byte count is 40 bytes
struct connect_event{
    __s32 fd;    // for track fd{signed}
    __u32 ppid; // parent process id 
    // 3 bytes of padding
    __u64 net_ts;   // timestamp 
    struct ke_sockaddr addr;    // used for support few socket families
};

// This struct use for tracking execve events with hashmap
//Total byte count is 272 bytes
struct execve_event{
    __u32 ppid; // parent process id
    __u64 execve_ts;    // execve triggered timestamp
    char filename[256]; // filename {ex: '/bin/sh'}
};

// This struct use for tracking dup2 state with hashmap
// Total byte count is 24 bytes
struct dup2_state{
    __u64 last_dup2_ts;  // for store last timestamp {stdin/out/err}
    __u32 ppid; // parent process id
    __s32 oldfd; // for check connect fd == dup2 old fd
    __u8 stdio_redirects; // count of redirects
    // 7 bytes of padding
};

/*
*   This struct use for tracking triggered syscalls flags
*
*   Memory Layout:
*       - Total byte count is 16 bytes
*
*   Bitmask Flags Architecture:
*   ==================================================|
*   | Flag             | Binary        | Meaning      |
*   ==================================================|
*   CONNECT_FLAG         0001            Connect seen |
*   EXECVE_FLAG          0010            Execve seen  |
*   DUP2_FLAG            0100            Dup2 seen    |
*   ==================================================|
*
*   Design Notes:
*       - Multiple flags can be set simultaneously
*       - Order-independent detection (behavior correlation)
*       - Used as a lightweight state machine
*
*   Usage:
*       - Add flag = ctx->flags |= CONNECT_FLAG
*       - Remove Flag = ctx->flags &= ~CONNECT_FLAG
*       - Check Flag = if(ctx->flags & CONNECT_FLAG){ connect already happened } 
*
*   Defined in:
*       - common/common_syscalls.h
*
*   Total byte count is 16 bytes
*/
struct ke_ctx_state{
    __u64 start_time; // for cleanup{timeout}
    __u32 flags;    // bitmask flag for hold triggered flags{syscalls}
    // 4 byte of padding   
};
/*************************************
******** Common Event Header *********
*************************************/

// This is the list of our header types
enum ke_event_type {
    KE_EVENT_INVALID = 0,   // used for error handling
    KE_EVENT_EXECVE = 1,    
    KE_EVENT_CONNECT = 2,   
    KE_EVENT_REVERSE_SHELL = 3, 
};

/* 
 * This header is shared by ALL streamed events.
 * Keep this small and stable.
 *
 * ABI NOTE:
 * Layout must remain stable (shared with userland).
 * Size: 24 bytes (aligned to 8).
 *
 */
struct ke_event_header {
    __u32 type;      // event type
    __u32 pid;       // process id
    __u64 ts;        // primary timestamp
    __u32 ppid;      // parent pid 
    // 4 bytes of padding
};

/****************************************
******* Detection Specific Payloads *****
*****************************************/

/* 
* This struct used for transfer `connect + execve` events data to userland for
*    1. Detect suspicious or not
*    2. Analyse data
*
* ABI NOTE:
* Layout must remain stable (shared with userland).
* Size: 312 bytes (aligned to 8).
*
*/
struct ke_reverse_shell_payload {
    char filename[256]; // filename ("/bin/sh"),
    __u64 execve_ts; // execve timestamp 
    __u64 net_ts; // connect timestamp 
    __u64 last_dup2_ts; // helps for detection logic like this {connct_ts < dup2_ts < execve_ts}, andit will implements on future varients.
    struct ke_sockaddr addr;
    __u8 stdio_redirects;   // for check {stdin/out/err}
    // 7 bytes of padding {__u8 pad[7]; if needed}
};

/*****************************
******* Streaming events *****
******************************/

/* 
* This struct use for streaming suspicious events to the userland
*
* ABI NOTE:
* Layout must remain stable (shared with userland).
* Size: 336 bytes (aligned to 8).
* Developper NOTE:
*   - Ring buffer streaming every event take 336 bytes.
*   - We can reduce it via 
*       - shorter filename buffer [64 ?]
*       _ string deduplication -> hash the filename and send only if its unknown
*   My assumption:
*       - 500k syscalls/sec
*       - 0-5 detections/sec
*       - 5 x 336 = 1.6 KB/sec
*
*/
struct ke_suspicious_event {
    struct ke_event_header hdr; 
    struct ke_reverse_shell_payload data;   
};

/*************************************
******* Struct Validations ***********
**************************************/

// connect_event must remain 40 bytes (aligned to 8)
_Static_assert(sizeof(struct connect_event) == 40,"connect_event struct size mismatch!");

// ke_event_header must remain 24 bytes (aligned to 8)
_Static_assert(sizeof(struct ke_event_header) == 24,"ke_event_header size mismatch!");

// ke_reverse_shell_payload must remain 296 bytes
_Static_assert(sizeof(struct ke_reverse_shell_payload) == 312,"ke_reverse_shell_payload size mismatch!");

// execve_event must remain 272 bytes 
_Static_assert(sizeof(struct execve_event) == 272, "execve_event struct size mismatch!");

// Protect reordering structs
_Static_assert(offsetof(struct ke_reverse_shell_payload, net_ts) == 264,"net_ts offset changed!");

// ke_sockaddr must remain 24 bytes (align to 8)
_Static_assert(sizeof(struct ke_sockaddr) == 24,"ke_sockaddr size mismatch");

// protect ke_sockaddr reordering
_Static_assert(offsetof(struct ke_sockaddr, port) == 20,"port offset changed");

// dup2_state must remain 16 bytes
_Static_assert(sizeof(struct dup2_state) == 24, "dup2_state size mismatch");

// Protect header types reordering
_Static_assert(KE_EVENT_EXECVE == 1, "EXECVE enum changed!");
_Static_assert(KE_EVENT_CONNECT == 2, "CONNECT enum changed!");
_Static_assert(KE_EVENT_REVERSE_SHELL == 3, "REVERSE_SHELL enum changed!");