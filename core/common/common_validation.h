#pragma once

#include "common_status.h"

// Max pid
#define MAX_PID 4194304 // rather than hardcode we should this read via "/proc/sys/kernel/pid_max"

//single pointer validation
static int __always_inline validate_not_null(const void *ptr){return ptr ? ERR_SUCCESS : ERR_FAILURE;}

//duel pointer validation
static int __always_inline validate_not_null_duel(const void *ptr1, const void *ptr2){
    if (!ptr1 || !ptr2) return ERR_FAILURE;
    return ERR_SUCCESS;
}

//multiple pointer validation
static int __always_inline validate_not_null_multiple(const void *ptr1, const void *ptr2, const void *ptr3){
    if(!ptr1 || !ptr2 || !ptr3) return ERR_FAILURE;
    return ERR_SUCCESS;
}

// integer validations
static int __always_inline validate_not_null_u64(const __u64 key){ return key ? ERR_SUCCESS : ERR_FAILURE; }
static int __always_inline validate_not_null_u32(const __u32 key){ return key ? ERR_SUCCESS : ERR_FAILURE; }
static int __always_inline validate_not_null_long(const long key){ return key ? ERR_SUCCESS : ERR_FAILURE; }
static int __always_inline validate_not_null_int(const int key){ return key ? ERR_SUCCESS : ERR_FAILURE; }

// Checking is that valid pid. I don’t want to track kernel threads or idle tasks
static int __always_inline sanitize_the_pid(__u32 key){
    if(key == 0 || key > MAX_PID) return ERR_FAILURE;
    return ERR_SUCCESS;
}