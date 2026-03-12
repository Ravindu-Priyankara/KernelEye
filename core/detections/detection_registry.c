#include "detector.h"

// Reverse shell detection external function
// located at: reverse_shell/reverse_shell_detector.c
extern int detect_reverse_shell(
    struct ke_reverse_shell_event *event,  // for get header type
    struct ke_detection_result *result    // store result of detection
);

/*
*   In the future, this should be improved. 
*   Reason:
*       1. The event handler passes data to every detector, and it eats performance.
*/
ke_detector detectors[] = {
    {.name = "reverse_shell", .detect = detect_reverse_shell}
};

// for iterate, we should know the detector count
int detector_count = sizeof(detectors) / sizeof(detectors[0]);