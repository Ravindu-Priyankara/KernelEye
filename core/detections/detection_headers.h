#pragma once

// detection engine
int run_detections(
    struct ke_event_header *event,
    struct ke_detection_result *result
);