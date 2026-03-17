#include <stdio.h>

#include "../../common/common_status.h"
#include "../../common/common_structs.h"
#include "../rules/exec_rules.h"
#include "../detector.h"


/*
*   This function is used to check `connect` + `execve` trigger duration is under 5 seconds or not. 
*   Arguments:
*       1. execve syscall trigger time
*       2. connect syscall trigger time
*   Return:
*       0 = success 
*       1 = failure
*   Developer note:
*       - Attacker can keep delay. and it helps to lost 20 score.
*       - dup3, fork() -> should monitor parent also.
*/
int reverse_shell_time_correlation(
    __u64 execve_ts,
    __u64 net_ts,
    __u64 dup2_ts,
    __u8 redirects,
    struct ke_detection_result *result
)
{
    // prevent missing timestamps & also return empty result
    if(execve_ts == 0 || net_ts == 0){
        fprintf(stderr,"[ERROR]. Missing timestamp\n"); // should be change otherwise it will be break the UI.{fix: just convert to log rather than just print.}
        return 1;
    }

    // prevent pass null pointers
    if(!result) {
        fprintf(stderr, "[ERROR]. Detection result is null pointer!\n"); // should be change otherwise it will be break the UI.{fix: just convert to log rather than just print.}
        return 1;
    }

    /*
    *   This function is called when the kernel sees
    *       1. connect syscall
    *       2. execve syscall
    *       3. dup2 syscall
    *   Therefore, we should add a 30 score for this.
    *   severity:
    *       1. for syscall pattern trigger = info
    */
    result->detection_id = KE_DET_CONNECT_WITH_EXECVE; // TODO: In the future, we should change the detection id overwrite design bug.{fix: use bit flags `|=` and also it will effect to policies and ui.}
    result->score += 30;
    result->severity = KE_SEV_INFO;
    result->detected = true;

    /*
    *   Usually kernel streamed every events have redirects >= 2.
    */
    if(redirects >= 2){
        // common pattern {stdin/out/err}
        result->detection_id = KE_DET_REVERSE_SHELL;
        result->score += 40;
        result->severity = KE_SEV_INFO;
        result->detected = true;

        // strong signal -> upgrade severity
        if (execve_ts > dup2_ts && (execve_ts - dup2_ts < 5ULL * 1000000000ULL)) {
            result->score += 20;
            result->severity = KE_SEV_CRITICAL;
            // others not overwrite
        }

        // connect -> dup2 -> execve
        if (net_ts <= dup2_ts && dup2_ts <= execve_ts) {
            result->score += 10; // ordering bonus
        }
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
    struct ke_suspicious_event *event,
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
    *       1. Check is that duration between `connect` + `execve` under 5 seconds or not?
    *       2. The attacker can set a delay between syscalls, but without that timing gap we already proved it is reverse shell.
    */
    err = reverse_shell_time_correlation(
        event->data.execve_ts,
        event->data.net_ts,
        event->data.last_dup2_ts,
        event->data.stdio_redirects,
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

    // 100 is the highest score. so if its exeed we should fix that.
    if (result->score > 100)
    result->score = 100;

    if(err) return 0;

    return result->detected;
}