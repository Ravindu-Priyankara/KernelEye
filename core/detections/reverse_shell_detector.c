#include <stdio.h>
#include "../common/common_validation.h"
#include "../common/common_status.h"
#include "exec_rules.h"

/*
*   This function is used to check `connect` + `execve` trigger duration is under 60 seconds or not. And it helps a lot to prevent false positives.
*   Arguments:
*       1. execve syscall trigger time
*       2. connect syscall trigger time
*   Return:
*       1. pointer {reference ke_detection_result}
*/
struct ke_detection_result *reverse_shell_time_correlation(__u64 execve_ts, __u64 net_ts){

    // for hold detection result
    struct ke_detection_result *result;

    // prevent missing timestamps & also return empty result
    if(execve_ts == 0 || net_ts == 0){
        fprintf(stderr,"[ERROR]. Missing timestamp\n");
        return result;
    }

    /*
    *   This function is called when the kernel sees
    *       1. connect syscall
    *       2. execve syscall
    *   Therefore, we should add a 40 score for this.
    */
    result->detection_id = KE_DET_CONNECT_WITHEXECVE;
    result->score = 40;
    result->severity = KE_SEV_INFO;
    result->detected = true;

    /*
    *   Assumptions
    *       1. An attacker can reorder the syscall pattern
    *       2. If the attacker reorder syscall pattern, the delta value take huge positive number because of the `__u64` data type.
    */
    __u64 delta = (execve_ts > net_ts)? execve_ts - net_ts : net_ts - execve_ts;

    // check is it under 60 seconds
    if(delta < 60ULL * 1000000000ULL){
        // This helps to decide policies
        result->detection_id = KE_DET_REVERSE_SHEL;
        result->score += 20;
        result->severity = KE_SEV_WARNING;
        result->detected = true;
    }

    return result;
} 

/*
*   This function is used to check `execve syscall` contain filename.
*   Arguments:
*       1. filename { execve->filename}
*       2. pointer for access detection result struct
*   Return:
*       1. Pointer {reference ke_detection_result}
*/
struct ke_detection_result *reverse_shell_filename_correlation(const char *filename, struct ke_detection_result *result){

    // get the file name and convert to lowercase
    const char *file = get_basename_lower(filename);

    // get the severity
    exec_rule *rules = exec_rules_find(file);
    if(rules){
        // update the results
        result->detection_id = KE_DET_REVERSE_SHEL;
        result->score += rules->severity;
        result->severity = KE_SEV_WARNING;
        result->detected = true;
    }

    return result;
}