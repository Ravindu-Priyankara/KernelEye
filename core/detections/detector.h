#pragma once

#include "../common/common_structs.h"
#include "detection_results.h"

// This struct is used for store detection functions
typedef struct ke_detector{
    // for detector name
    const char *name;

    // function pointer for hold funtion name
    int (*detect)(
        // arg1 = event header 
        // arg2 = detection result
        struct ke_event_header *event,
        struct detection_results *result
    );
} ke_detector;