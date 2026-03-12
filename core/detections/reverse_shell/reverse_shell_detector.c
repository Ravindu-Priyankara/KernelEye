#include <stdio.h>
#include "../../common/common_status.h"
#include "../../common/common_structs.h"
#include "../rules/exec_rules.h"
#include "../detector.h"

/*
*   This function is used to check `connect` + `execve` trigger duration is under 60 seconds or not. And it helps a lot to prevent false positives.
*   Arguments:
*       1. execve syscall trigger time
*       2. connect syscall trigger time
*   Return:
*       0 = success 
*       1 = failure
*/
int reverse_shell_time_correlation(
    __u64 execve_ts,
    __u64 net_ts,
    struct ke_detection_result *result
)
{
    // prevent missing timestamps & also return empty result
    if(execve_ts == 0 || net_ts == 0){
        fprintf(stderr,"[ERROR]. Missing timestamp\n");
        return 1;
    }

    // prevent pass null pointers
    if(!result) {
        fprintf(stderr, "[ERROR]. Detection result is null pointer!\n");
        return 1;
    }

    /*
    *   This function is called when the kernel sees
    *       1. connect syscall
    *       2. execve syscall
    *   Therefore, we should add a 40 score for this.
    *   severity:
    *       1. for syscall pattern trigger = info
    */
    result->detection_id = KE_DET_CONNECT_WITH_EXECVE; // TODO: In the future, we should change the detection id overwrite design bug.
    result->score += 40;
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
        // severity = if it trigger quick enough = warning
        result->detection_id = KE_DET_REVERSE_SHELL; // TODO: In the future, we should change the detection id overwrite design bug.
        result->score += 20;
        result->severity = KE_SEV_WARNING;
        result->detected = true;
    }

    return 0;
} 

/*
*   This function is used to check `execve syscall` contain filename.
*   Arguments:
*       1. filename { execve->filename}
*       2. pointer for access detection result struct
*   Return:
*       0 = success 
*       1 = failure
*/
int reverse_shell_filename_correlation(
    const char *filename,
    struct ke_detection_result *result
)
{
    // prevent pass null pointers
    if(!result) {
        fprintf(stderr, "[ERROR]. Detection result is null pointer!\n");
        return 1;
    }

    if(!filename) {
        fprintf(stderr, "[ERROR]. Filename is a null pointer!\n");
        return 1;
    }

    // get the file name and convert to lowercase
    const char *file = get_basename_lower(filename);
    if(!file){
        fprintf(stderr, "[ERROR]. Missing filename!\n");
        return 1;
    }

    // get the severity
    exec_rule *rule = exec_rules_find(file);
    if(rule){
        // update the results
        // if it has suspicious filename = warning
        // if it quick trigger + suspicious filnemae = critical
        result->detection_id = KE_DET_REVERSE_SHELL;
        result->severity = (result->score >= 60) ? KE_SEV_CRITICAL : KE_SEV_WARNING;
        result->score += rule->severity;
        result->detected = true;
    }

    return 0;
}

/*
*   This is the reverse shell detector calling function and it link time correlation + filename based correlation.
*   Arguments:
*       event header struct = for identify event category
*       detection result = for store detection result
*   Return:
*       0 = detection executed
*       1 = not my event type
*/
int detect_reverse_shell(
    struct ke_reverse_shell_event *event,
    struct ke_detection_result *result
)
{
    // prevent null value passing
    if(!event || !result) return 0;

    if(event->hdr.type != KE_EVENT_REVERSE_SHELL) return 0; 

    // for err handling
    int err;
        
    /*
    *   Reverse shell Detection 01 
    *   Assumptions:
    *       1. Check is that duration between `connect` + `execve` under 60 seconds or not?
    *       2. The attacker can set a delay between syscalls, which is why we set 60 seconds rather than just 5 seconds.
    */
    err = reverse_shell_time_correlation(
        event->data.execve_ts,
        event->data.net_ts,
        result
    );

    if(err) return 0;

    /*
    *   Reverse shell Detection 02
    *   Assumptions:
    *       1. Check file name and identify common reverse shells using patterns.
    *       2. Fix common bypasses { capitalized or white space based techniques}
    *   
    */
    err = reverse_shell_filename_correlation(
        event->data.filename, 
        result
    );

    if(err) return 0;

    return result->detected;
}