#include <stdio.h>
#include "../common/common_validation.h"
#include "../common/common_status.h"

bool reverse_shell_time_correlation(__u64 execve_ts, __u64 net_ts){

    // prevent missing timestamps
    if(execve_ts == 0 || net_ts == 0){
        fprintf(stderr,"[ERROR] Missing timestamp\n");
        return false;
    }

    /*
    *   Assumptions
    *       1. An attacker can reorder the syscall pattern
    *       2. If the attacker reorder syscall pattern, the delta value take huge positive number because of the `__u64` data type.{unsigned integer underflow}
    */
    __u64 delta = (execve_ts > net_ts)? execve_ts - net_ts : net_ts - execve_ts;

    // check is it under 60 seconds
    if(delta < 60ULL * 1000000000ULL) return true;

    return false;
} 