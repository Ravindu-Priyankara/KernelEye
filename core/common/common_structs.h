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

// Supports IPv4 and IPv6
// total bytes 24 bytes
struct ke_sockaddr {
    __u16 family;   // socket family
    __u16 port;
    __u32 __reserved;
    /*
    *   ABI NOTE:
    *       - Union always reserve enough space for the biggest one.
    *       - So this union always 16 bytes.
    */
    union {
        __u32 ipv4;        // AF_INET
        __u8  ipv6[16];    // AF_INET6
    };
};

/*************************************
******* Events Holding Structs *******
**************************************/

// This struct use for tracking connect events with hashmap
// Total byte count is 40 bytes
struct connect_event{
    __s32 fd;    // for track fd{signed}
    __u32 ppid; // parent process id 
    __u64 net_ts;   // timestamp 
    struct ke_sockaddr addr;    // used for support few socket families
};

// This struct use for tracking execve events with hashmap
//Total byte count is 272 bytes
struct execve_event{
    __u32 ppid; // parent process id
    __u32 __reserved;
    __u64 execve_ts;    // execve triggered timestamp
    char filename[256]; // filename {ex: '/bin/sh'}
};

// This struct use for tracking dup2 and dup3 state with LRU hashmap
// Total byte count is 24 bytes
struct dup_state{
    __u64 last_dup_ts;  // for store last timestamp {stdin/out/err}
    __u32 ppid; // parent process id
    __s32 oldfd; // for check connect fd == dup2 old fd
    __u8 stdio_redirects; // count of redirects
    __u8 __reserved[7]; // for stable ABI
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
*   Flags can be change.
*
*   Design Notes:
*       - Multiple flags can be set simultaneously
*       - Order-independent detection (behavior correlation)
*       - Used as a lightweight state machine
*
*   Usage:
*       - Add flag = ctx->flags |= CONNECT_FLAG
*       - Remove Flag = ctx->flags &= ~CONNECT_FLAG
*       - Keep connect flag and other all remove ctx->flags &= CONNECT_FLAG
*       - Check Flag = if(ctx->flags & CONNECT_FLAG){ connect already happened } 
*
*   Defined in:
*       - common/common_syscalls.h
*
*   Total byte count is 24 bytes
*/
struct ke_ctx_state{
    __u64 last_time; // for cleanup{timeout}
    __u32 flags;    // bitmask flag for hold triggered flags{syscalls}
    __u32 score;    // for score
    __u16  stage;    //{defined in common/common/syscalls.h}
    __u8 __reserved[6];
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
    __u32 __reserved;
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
    __u64 last_dup_ts; // helps for detection logic like this {connct_ts < dup2_ts < execve_ts}, andit will implements on future varients.
    struct ke_sockaddr addr;
    __u8 stdio_redirects;   // for check {stdin/out/err}
    __u8 valid_dup2;    // for check {connect fd == dup2 old fd}
    __u8 __reserved[6];
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

/*************************************************
******* ABI invariants - DO NOT MODIFY ***********
**************************************************/

// connect_event must remain 40 bytes (aligned to 8)
_Static_assert(sizeof(struct connect_event) == 40,"connect_event struct size mismatch!");

// context state must remain 24 bytes (aligned to 8)
_Static_assert(sizeof(struct ke_ctx_state) == 24, "context state struct size mismatch!");

// ke_event_header must remain 24 bytes (aligned to 8)
_Static_assert(sizeof(struct ke_event_header) == 24,"ke_event_header size mismatch!");

// ke_reverse_shell_payload must remain 312 bytes
_Static_assert(sizeof(struct ke_reverse_shell_payload) == 312,"ke_reverse_shell_payload size mismatch!");

// execve_event must remain 272 bytes 
_Static_assert(sizeof(struct execve_event) == 272, "execve_event struct size mismatch!");

// ke_sockaddr must remain 24 bytes (align to 8)
_Static_assert(sizeof(struct ke_sockaddr) == 24,"ke_sockaddr size mismatch");

// dup2_state must remain 24 bytes
_Static_assert(sizeof(struct dup_state) == 24, "dup2_state size mismatch");

// streaming event must remain 336 bytes
_Static_assert(sizeof(struct ke_suspicious_event) == 336, "streaming event mismatch!");

// Protect reordering structs
_Static_assert(offsetof(struct ke_reverse_shell_payload, net_ts) == 264,"net_ts offset changed!");

// protect ke_sockaddr reordering
_Static_assert(offsetof(struct ke_sockaddr, port) == 2,"port offset changed");

// check alignment of reverse shell payload
_Static_assert(__alignof__(struct ke_reverse_shell_payload) == 8, "reverse shell payload alignment changed!");

// check alignment of event header
_Static_assert(__alignof__(struct ke_event_header) == 8, "event header alignment changed!");

// Protect header types reordering
_Static_assert(KE_EVENT_EXECVE == 1, "EXECVE enum changed!");
_Static_assert(KE_EVENT_CONNECT == 2, "CONNECT enum changed!");
_Static_assert(KE_EVENT_REVERSE_SHELL == 3, "REVERSE_SHELL enum changed!");