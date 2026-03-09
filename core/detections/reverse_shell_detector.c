#include <stdio.h>
#include "../common/common_validation.h"
#include "../common/common_status.h"

struct ke_detection_result reverse_shell_time_correlation(__u64 execve_ts, __u64 net_ts){

    // for hold detection result
    struct ke_detection_result result = {0};

    // prevent missing timestamps & also return empty result
    if(execve_ts == 0 || net_ts == 0){
        fprintf(stderr,"[ERROR] Missing timestamp\n");
        return result;
    }

    /*
    *   This function is called when the kernel sees
    *       1. connect syscall
    *       2. execve syscall
    *   Therefore, we should add a 40 score for this.
    */
    result.detection_id = KE_DET_CONNECT_WITHEXECVE;
    result.score = 40;
    result.severity = KE_SEV_INFO;
    result.detected = true;

    /*
    *   Assumptions
    *       1. An attacker can reorder the syscall pattern
    *       2. If the attacker reorder syscall pattern, the delta value take huge positive number because of the `__u64` data type.
    */
    __u64 delta = (execve_ts > net_ts)? execve_ts - net_ts : net_ts - execve_ts;

    // check is it under 60 seconds
    if(delta < 60ULL * 1000000000ULL){
        // This helps to decide policies
        result.detection_id = KE_DET_REVERSE_SHEL;
        result.score += 20;
        result.severity = KE_SEV_WARNING;
        result.detected = true;
    }

    return result;
} 