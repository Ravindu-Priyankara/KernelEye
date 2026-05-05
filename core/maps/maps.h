/*
 * Kernel Eye - eBPF Runtime Security Framework
 * SPDX-License-Identifier: MIT
 *
 * File: maps.h
 * Description:
 *   Defines all BPF maps used for tracking and streaming events.
 *   Includes hash maps for correlation and ring buffer for userland alerts.
 *
 * Author: Ravindu Priyankara
 * Year: 2026
 */

#pragma once

#include "../common/common_headers.h"   // header file
#include "../common/common_structs.h"   // structs for maps

/******************************
*********** Macros ************
*******************************/

// maps sizes
#define RINGBUF_SIZE (1 << 24)
#define HASHMAP_SIZE 10240

/*******************************
*********** Hash Maps **********
********************************/

// This hashmap used for track execve events {permanent struct}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);   // map type
    __uint(max_entries, HASHMAP_SIZE); // hashmap size
    __type(key, __u64); // cid
    __type(value, struct execve_event); // struct for hold data
} execve_hash_map SEC(".maps");
/*
*   Temporary map. And used for hold dup old fd.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_SIZE);
    __type(key, __u64); //cid
    __type(value, __u32); // oldfd
} dup_temp_map SEC(".maps");

/*
*   This map is used to hold generated context IDs.
*   Benefits:
*       - for track parents and childs.
*   Assumptions:
*       - Keys are always unique, but CIDs don't have to be. Since one parent can have several children, we're letting multiple unique keys share the same CID.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, HASHMAP_SIZE);
    __type(key, __u32); //pid(tgid) not thread id
    __type(value, __u64); // context id(CID)
} ctx_map SEC(".maps");

/***********************************
*********** LRU Hash Maps **********
************************************/

/*
*   This map is used to hold triggered syscall flags. And the key is context ID, not the thread group ID.
*   Benifits:
*       - This struct holds the parent and child-triggered syscall flags.
*       - Prevent the fork based bypasses.
*/
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, HASHMAP_SIZE);
    __type(key, __u64);     // key is the context id
    __type(value, struct ke_ctx_state);
} ctx_state_map SEC(".maps");

// for dup2 and 3 data
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, HASHMAP_SIZE);
    __type(key, __u64);
    __type(value, struct dup_state);
} dup_map SEC(".maps");

// This LRU hashmap used for track outboud connection events
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);    // map type
    __uint(max_entries, HASHMAP_SIZE);  // hashmap maximum entries
    __type(key, __u64); // key = cid
    __type(value, struct connect_event);   // This struct hold the all connect events data
}connect_map SEC(".maps");  // LRU hashmap name

/****************************************
*********** Per CPU Array Maps **********
*****************************************/

// This per cpu array maps are used as temporary storage to hold execve syscall data. And the main purpose is reduce stack size.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);    //MAP TYPE
    __uint(max_entries, 1); // We need only 1 entry per cpu
    __type(key, __u32); // We have only 1 entry, and it means our key is 0.
    __type(value, struct execve_event);    // This struct hold the all execve event data temporary
}tmp_execve_map SEC(".maps");

// used as scratchpad
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch_buf);
}scratch_buf_map SEC(".maps");

/****************************************
*************** Array Maps **************
*****************************************/

/*
*   This map is used for generate context id(CID). 
*   Benefits:
*       - Always exists (index 0)
*       - Fast Lookup
*       - Verifier Safe
*       - Works Everywhere
*   Because the atomic counter is not reliable. limited support depending on the kernel. {BPF_ATOMIC64}
*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1); // For this stage, we need only one counter.
    __type(key, __u32); // key = 0, because we have only one entry
    __type(value, __u64); // Context id(CID)
} cid_counter SEC(".maps");

/*******************************
****** Streaming Maps **********
********************************/

//This ringbuf map is used for streaming events to the userland
struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF); // map type
    __uint(max_entries, RINGBUF_SIZE);  // ringbuf maximum entries
}alert_map SEC(".maps");    // ringbuf name

/*******************************
****** Maps Validation *********
********************************/

_Static_assert(HASHMAP_SIZE > 0, "HASHMAP_SIZE must be > 0"); // validate HashMap size 
_Static_assert(RINGBUF_SIZE >= (1 << 12), "Ringbuf too small"); // validate Ringbuf size