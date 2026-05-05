#pragma once

#include "../common/common_headers.h"
#include "../common/common_status.h"
#include "../common/common_validation.h"
#include "../common/common_syscalls.h"
#include "connect_helpers.h"

/*
* This helper used for get the TGID from events
* Stack Allocation: 0 bytes
*/
static __always_inline __u32 get_tgid(void){
    return bpf_get_current_pid_tgid() >> 32; // return tgid
}

/*
* This heler used for get the PID from events
* Stack Allocation: 0 bytes
*/
static __always_inline __u32 get_pid(void){
    return (__u32)bpf_get_current_pid_tgid();
}

/*
* This helper used for get syscall trigger time(nano seconds)
* Stack Allocation: 0 bytes
*/
static __always_inline __u64 get_trigger_time(void){
    return bpf_ktime_get_ns();
}

/*
* This helper used for get the PPID from task struct
* Stack Allocation: 24 bytes
*/
static __always_inline __u32 get_ppid(void){
    /* 
    * Get the current task pointer
    * Stack Allocation: 8 bytes
    */
    struct task_struct  *task = (struct task_struct *)bpf_get_current_task();
    if(validate_not_null(task)!= ERR_SUCCESS) return 0;

    /*
    * Prepare a parent pointer for parent
    * Stack Allocation: 8 bytes
    */
    struct task_struct *parent = NULL;

    // read real parent safly
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if(validate_not_null(parent) != ERR_SUCCESS) return 0;

    // for hold ppid
    // Stack Allocation: 4 bytes
    __u32 ppid = 0;

    // get parent tgid
    bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);

    return ppid;

}

/*
*   This helper use for get Context id. 
*   Arguments:
*       - Pointer for defined context id variable
*   Return:
*       - success = 0 and failures = -1
*   Stack Allocation: 16 bytes;
*   Atomic builtin function documentation:
*       - https://docs.ebpf.io/linux/concepts/concurrency/
*
*   BUG NOTE:
*       - Previously, we assumed the first Context ID is 1, but actually `__sync_fetch_and_add(counter, 1);` returns the old value first. So it means the first Context ID is always 0.
*
*       Fix:
*           - Redefine the API and Included:
*               - function return success{0} or Failure{-1} not context id.
*               - directly assign the values to given pointer
*/
static __always_inline int get_cid(__u64 *new_cid){
    /*
    *   We have only one entries and it key is 0.
    *   4 bytes of stack allocation.
    */
    __u32 key = 0 ;

    /*
    *   Get and assign the value of the cid_counter array map to a pointer.
    *   8 bytes of stack allocation
    */
    __u64 *counter = bpf_map_lookup_elem(&cid_counter, &key);
    if(!counter){
        return ERR_FAILURE;
    }

    // atomic: assign old value, then increments counter by 1.
    *new_cid = __sync_fetch_and_add(counter, 1);
    return ERR_SUCCESS;

}

/*
*   This helper is used for get the cid value.
*   Benefits:
*       - check cid
*       - generate cid
*       - store cid
*   Arguments:
*       - pid(tgid)
*       - pointer for declared cid variable
*   Return:
*       - success{0} or Failure{-1}
*   Stack Allocation: 16 bytes
*/
static __always_inline int get_or_create_cid(__u32 pid, __u64 *new_cid){
    /*
    *   For hold context hash map return pointer
    *   8 bytes of stack allocation
    */
    __u64 *cid_ptr;

    /*
    *   For hold newly created context id
    *   8 bytes of stack allocation
    */
    __u64 cid;

    // Get the context ID if it's already stored.
    cid_ptr = bpf_map_lookup_elem(&ctx_map, &pid);
    if(cid_ptr){
        *new_cid = *cid_ptr;    // assign the context id to given pointer
        return ERR_SUCCESS;
    }

    // generate a new cid.
    if(get_cid(&cid) != ERR_SUCCESS) return ERR_FAILURE;

    /*
    *   Store generated CID, and used direct update because we already checked if it is stored or not. 
    *   So there wasn't a point in using the `update_map_element` helper function.
    *
    *   Developer Note:
    *       - Used `BPF_NOEXIST` for prevent race condition.
    *   ex: 
    *       Two threads could do:
    *           Thread A -> no CID -> create CID 5
    *           Thread B -> no CID -> create CID 6
    *       and both assign different CID's to same PID. 
    *       
    */
    if(bpf_map_update_elem(&ctx_map, &pid, &cid, BPF_NOEXIST)!= 0){
        // If another thread inserted it. We just return the Context ID that was inserted rather than just returning 0;
        cid_ptr = bpf_map_lookup_elem(&ctx_map, &pid);
        if(cid_ptr){
            *new_cid = *cid_ptr;
            return ERR_SUCCESS;
        }

        return ERR_FAILURE; // real failure
    }

    *new_cid = cid;

    return ERR_SUCCESS;
}

/*
*   This function use for check map data availability
*   Arguments:
*       1. map
*       2. key (Mainly PID is the key)
*   Return:
*       1. NULL (not found valid data)
*       2. Generic pointer(void *) to the value associated with the key.
*   Stack Allocation: 0 bytes
*/
static __always_inline void *check_map_data_availability(void *map, const void *key){
    //prevent null data
    if(validate_not_null_duel(map, key) != ERR_SUCCESS) return 0;

    return bpf_map_lookup_elem(map, key);
}

/*
*   This helper function used for update hash maps element
*       Task 1:
*           * Check data already stored or not.
*       Task 2:
*           * If there wasn't data. Write values from maps
*   Arguments:
*       1. map
*       2. key (Mainly PID is the key)
*       3. value (data fields ex:- ipv4 addr, ipv6 addr, port)
*       4. flags (commonly used BPF_ANY, but it depends on incident)
*   Return:
*       0 / -1 {0 = Success, -1 = failure}
*   Stack Allocation: 16 bytes
*/
static __always_inline int update_map_element(void *map, const void *key, const void *value, __u64 flags){
    //prevent null data
    if(validate_not_null_multiple(map, key, value) != ERR_SUCCESS) return ERR_FAILURE;

    // 8 bytes of stack allocation
    void *state = check_map_data_availability(map, key);

    // not existing data
    if(!state){
        // 4 bytes of stack allocation
        int ret = bpf_map_update_elem(map, key, value, flags);  // update the elements
        return ret == 0 ? ERR_SUCCESS : ERR_FAILURE;
    }else return ERR_SUCCESS; // Key already exists
}

/*
*   This helper function is used to update the map without checking whether the data has already been saved or not.
*   Arguments:
*       - map(pointer) => map name
*       - key(pointer) => tgid is the key
*       - value(pointer) => struct that hold values
*       - flags(unsigned 64bit integer) => Mainly `BPF_ANY`
*   Return:
*       - 0 / -1 {0 = Success, -1 = failure}
*   Stack Allocation: 4 bytes
*/
static __always_inline int force_update_map_element(void *map, const void *key, const void *value, __u64 flags){
    // 4 bytes of stack allocation
    int ret = bpf_map_update_elem(map, key, value, flags);  // update the elements
    return ret == 0 ? ERR_SUCCESS : ERR_FAILURE;
}

/*
*   This helper is used to delete the hashmap saved data.
*   Arguments:
*       1. map (targeted map)
*       2. key (Hashmap key for data)
*   Return 0 on success and -1 for failure
*   Stack Allocation: 16 bytes
*/
static __always_inline long delete_map_elements(void *map, const void *key){
    //check availability before delete
    // 8 bytes of stack allocation
    void *state = check_map_data_availability(map, key);
    if(!state) return ERR_FAILURE;

    //delete the map
    // 8 bytes of stack allocation
    long ret = bpf_map_delete_elem(map, key);
    return ret == 0 ? ERR_SUCCESS : ERR_FAILURE;
}

