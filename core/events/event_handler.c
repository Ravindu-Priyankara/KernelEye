#include <stdio.h>

#include "../common/common_structs.h"
#include "../detections/detection_results.h"
#include "../detections/detection_headers.h"
#include "../policies/policy_header.h"
#include "../responses/response_engine.h"
#include "../ui/display/display.h"
#include "../ui/banner/banner.h"
#include "../ui/display/event_buffer.h"

/*
*   Kernel-streamed events data comes to this function.
*/
int handle_event(void *ctx, void *data, size_t size){
    // fix unused parameter warnings
    (void)ctx;
    (void)size;

    // get all data from event header
    struct ke_event_header *event = data;

    // accurately increase events
    ke_stats.events++;
    // amount of reverse shells
    if(event->type == KE_EVENT_REVERSE_SHELL){
        ke_stats.reverse_shells++;
    }

    // alert & blocks
    if(event->stage < STAGE_HIGH_RISK){
        ke_stats.alerts++;
    }else{
        ke_stats.blocks++;
    }


    // add to buffer (for ui)
    /*
    * Defined in:
    *   - ui/display/event_buffer.h
    */
    add_event_to_buffer(event);

    // refresh screen
    printf("\033[2J\033[H");  // clear screen + move cursor top
    ke_print_banner();
    ke_description();
    ke_display_init();
    ke_display_all_events();
    ke_print_stats(&ke_stats);

    return 0;
    
}