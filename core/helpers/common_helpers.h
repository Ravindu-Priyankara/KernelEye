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
static __u32 __always_inline get_tgid(void){
    return bpf_get_current_pid_tgid() >> 32; // return tgid
}

/*
* This heler used for get the PID from events
* Stack Allocation: 0 bytes
*/
static __u32 __always_inline get_pid(void){
    return (__u32)bpf_get_current_pid_tgid();
}

/*
* This helper used for get syscall trigger time(nano seconds)
* Stack Allocation: 0 bytes
*/
static __u64 get_trigger_time(void){
    return bpf_ktime_get_ns();
}

/*
* This helper used for get the PPID from task struct
* Stack Allocation: 24 bytes
*/
static __u32 __always_inline get_ppid(void){
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
static int __always_inline update_map_element(void *map, const void *key, const void *value, __u64 flags){
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
*   This helper function is used for categorizing request types and parsing the data
*   Arguments:
*       1. ret (return value)
*       2. request type(syscall name)
*       3. pid
*   Return:
*       0 / -1 {0 = Success, -1 = failure}
*   Stack Allocation: 0 bytes
*/
static __always_inline int identify_the_return_request_type(int ret, common_syscalls request, __u32 pid){
    //validate the argument
    if(validate_not_null_int(ret) != ERR_SUCCESS) return ERR_FAILURE;
    if(validate_not_null_int(request) != ERR_SUCCESS) return ERR_FAILURE;
    if(validate_not_null_u32(pid) != ERR_SUCCESS) return ERR_FAILURE;

    //sanitize the pid
    if(sanitize_the_pid(pid) != ERR_SUCCESS) return ERR_FAILURE;

    if(ret == ERR_SUCCESS){
        //  successful attempts
        switch(request){
            case CONNECT:{
                //This helper function located at `connect_helpers.h` file 
                return copy_the_connect_event_data(pid);
            }default: return ERR_FAILURE;   // default handler
        }
    }else return ERR_FAILURE;
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