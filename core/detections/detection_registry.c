#include "detector.h"

// Reverse shell detection external function
// located at: reverse_shell/reverse_shell_detector.c
extern int detect_reverse_shell(
    struct ke_suspicious_event *event,  // for get header type
    struct ke_detection_result *result    // store result of detection
);

/*
* 
*   This is the list of detectors kernel eye used.
*/
ke_detector detectors[] = {
    {.name = "reverse_shell", .detect = detect_reverse_shell}
};

// for iterate, we should know the detector count
int detector_count = sizeof(detectors) / sizeof(detectors[0]);