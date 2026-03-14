#include <stdio.h>

#include "../common/common_structs.h"
#include "../detections/detection_results.h"
#include "../detections/detection_headers.h"
#include "../policies/policy_header.h"
#include "../responses/response_engine.h"
#include "../ui/display/display.h"


int handle_event(void *ctx, void *data, size_t size){
    // helps to categorize the data by header type
    struct ke_event_header *hdr = data;

    // get all data from reverse shell event
    struct ke_reverse_shell_event *event = data;

    // zero-initialized struct to hold event results
    struct ke_detection_result result = {0};

    // initialize stats
    struct stats ke_stats = {0};

    // A new event happened
    ke_stats.events++;

    // 1 = detected
    // 0 = not detected
    if(run_detections(event, &result)){
        // get the policies
        enum ke_policy_result action = evaluate_policy(&result);

        ke_execute_response(action, hdr);

        // If it’s a reverse shell
        if(result->detection_id == KE_DET_REVERSE_SHELL)
            ke_stats.reverse_shells++;

        // If severity is warning or higher, consider it an alert
        if(result->severity >= KE_SEV_WARNING)
            ke_stats.alerts++;

        // If you implement auto-blocking, increase blocks
        if(policy_blocked_event(result))
            ke_stats.blocks++;

        // update the event table
        ke_display_event(
            event->hdr.pid,
            event->hdr.type,
            result.severity,
            result.detection_id,
            result.score
        );

    }

    ke_print_stats(&ke_stats);

    return 0;
    
}