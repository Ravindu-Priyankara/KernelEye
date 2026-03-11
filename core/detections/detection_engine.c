#include "detector.h"
#include "detection_results.h"

// link dtectors and its count
extern ke_detector detectors[];
extern int detector_count;  

int run_detections (
    struct ke_event_header *event,
    struct ke_detection_result *result
)
{
    // iterate for pass data to all detectors
    for(int i = 0; i < detector_count; i++){
        if(detector[i].detect(event, result)) return 1;     // 0 = success , otherwise return 1
    }

    return 0;
}