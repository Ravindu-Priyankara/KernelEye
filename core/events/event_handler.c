#include <stdio.h>
#include "../common/common_structs.h"
#include "../detections/detection_headers.h"

int handle_event(void *ctx, void *data, size_t size){
    // helps to categorize the data by header type
    struct ke_event_header *hdr = data;

    switch(hdr->type){
        case KE_EVENT_REVERSE_SHELL: {  // reverse shell type
            struct ke_reverse_shell_event *event = data;

            /*
            *   Reverse shell Detection 01 
            *   Assumptions:
            *       1. Check is that duration between `connect` + `execve` under 60 seconds or not?
            *       2. The attacker can set a delay between syscalls, which is why we set 60 seconds rather than just 5 seconds.
            */
            struct ke_detection_result *result = reverse_shell_time_correlation(
                event->data.execve_ts,
                event->data.net_ts
            );

            if(!result){
                // allocate temp result for prevent crash
                static struct ke_detection_result temp_result = {0};
                result = &temp_result;
            }

            /*
            *   Reverse shell Detection 02
            *   Assumptions:
            *       1. Check file name and identify common reverse shells using patterns.
            *       2. Fix common bypasses { capitalized or white space based techniques}
            *   
            */
            result = reverse_shell_filename_correlation(event->data.filename, result);
            
            // TODO: Add dup2 check{dup2 > 2}

            
            break;
        }
        default: break;
    }
}