#pragma once

#include "../common/common_headers.h"

// This helper used for get the TGID from events
static __u32 __always_inline get_tgid(void){
    return bpf_get_current_pid_tgid() >> 32; // return tgid
}

// This heler used for get the PID from events
static __u32 __always_inline get_pid(void){
    return (__u32)bpf_get_current_pid_tgid();
}