#include <stdio.h>
#include "../common/common_structs.h"
#include "../detections/detection_results.h"
#include "../detections/detection_headers.h"
#include "../policies/policy_header.h"


int handle_event(void *ctx, void *data, size_t size){
    // helps to categorize the data by header type
    struct ke_event_header *hdr = data;

    // zero-initialized struct to hold event results
    struct ke_detection_result result = {0};

    // 1 = detected
    // 0 = not detected
    if(run_detections(hdr, &result)){
        enum ke_policy_result action = evaluate_policy(&result);
    }
    
}