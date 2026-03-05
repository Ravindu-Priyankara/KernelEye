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

// This hashmap used for track outboud connection events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);    // map type
    __uint(max_entries, HASHMAP_SIZE);  // hashmap maximum entries
    __type(key, __u32); // key = pid
    __type(value, struct connect_event);   // This struct hold the all connect events data
}connect_map SEC(".maps");  // hashmap name

//This hashmap used for temporary store connect events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);    // map type
    __uint(max_entries, HASHMAP_SIZE);  // hashmap maximum entries
    __type(key, __u32); // key = pid
    __type(value, struct connect_event);   // This struct hold the all connect events data
}tmp_connect_map SEC(".maps");  // hashmap name

// This hashmap used for temporary store execve events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);   // map type
    __uint(max_entries, HASHMAP_SIZE); // hashmap size
    __type(key, __u32); // pid
    __type(value, struct execve_event); // struct for hold data
} tmp_execve_hash_map SEC(".maps"); // hashmap name

// This hashmap used for track execve events {permenet struct}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);   // map type
    __uint(max_entries, HASHMAP_SIZE); // hashmap size
    __type(key, __u32); // pid
    __type(value, struct execve_event); // struct for hold data
} execve_hash_map SEC(".maps");

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