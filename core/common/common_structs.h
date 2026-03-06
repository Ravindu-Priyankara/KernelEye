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
    __u32 ppid; // parent process id 
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
* Size: 296 bytes (aligned to 8).
*
*/
struct ke_reverse_shell_payload {
    char filename[256]; // filename ("/bin/sh"),
    __u64 execve_ts; // execve timestamp 
    __u64 net_ts; // connect timestamp 
    struct ke_sockaddr addr;
    // 2 bytes of padding
};

/*****************************
******* Streaming events *****
******************************/

/* 
* This struct use for streaming `connect + execve` events to the userland
*
* ABI NOTE:
* Layout must remain stable (shared with userland).
* Size: 320 bytes (aligned to 8).
*
*/
struct ke_reverse_shell_event {
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
_Static_assert(sizeof(struct ke_reverse_shell_payload) == 296,"ke_reverse_shell_payload size mismatch!");

// execve_event must remain 272 bytes 
_Static_assert(sizeof(struct execve_event) == 272, "execve_event struct size mismatch!");

// Protect reordering structs
_Static_assert(offsetof(struct ke_reverse_shell_payload, net_ts) == 264,"net_ts offset changed!");

// ke_sockaddr must remain 24 bytes (align to 8)
_Static_assert(sizeof(struct ke_sockaddr) == 24,"ke_sockaddr size mismatch");

// protect ke_sockaddr reordering
_Static_assert(offsetof(struct ke_sockaddr, port) == 20,"port offset changed");

// Protect header types reordering
_Static_assert(KE_EVENT_EXECVE == 1, "EXECVE enum changed!");
_Static_assert(KE_EVENT_CONNECT == 2, "CONNECT enum changed!");
_Static_assert(KE_EVENT_REVERSE_SHELL == 3, "REVERSE_SHELL enum changed!");