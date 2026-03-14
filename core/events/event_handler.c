#include <stdio.h>

#include "../common/common_structs.h"
#include "../detections/detection_results.h"
#include "../detections/detection_headers.h"
#include "../policies/policy_header.h"
#include "../responses/response_engine.h"
#include "../ui/display/display.h"
#include "../ui/banner/banner.h"


int handle_event(void *ctx, void *data, size_t size){
    // helps to categorize the data by header type
    struct ke_event_header *hdr = data;

    // get all data from reverse shell event
    struct ke_reverse_shell_event *event = data;

    // zero-initialized struct to hold event results
    struct ke_detection_result result = {0};

    // 1 = detected
    // 0 = not detected
    if(run_detections(event, &result)){
        // get the policies
        enum ke_policy_result action = evaluate_policy(&result);

        ke_execute_response(action, hdr);

        ke_stats.events++;
        if(result.detection_id == KE_DET_REVERSE_SHELL)
            ke_stats.reverse_shells++;
        if(result.severity == KE_SEV_WARNING)
            ke_stats.alerts++;
        if(result.severity == KE_SEV_CRITICAL)
            ke_stats.blocks++;

        // add to buffer
        add_event_to_buffer(event, &result);

        // refresh screen
        printf("\033[2J\033[H");  // clear screen + move cursor top
        ke_print_banner();
        ke_description();
        ke_display_init();
        ke_display_all_events();
        ke_print_stats(&ke_stats);

    }

    return 0;
    
}