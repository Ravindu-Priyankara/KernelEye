#pragma once

// Used for hold detection results
struct ke_detection_result {
    int detection_id;
    int score;
    int severity;
    bool detected;
};

// detection types
enum ke_detection_id {
    KE_DET_CONNECT_WITH_EXECVE = 0,
    KE_DET_REVERSE_SHELL,
};

// detection severity
enum ke_severity {
    KE_SEV_INFO = 1,
    KE_SEV_WARNING,
    KE_SEV_CRITICAL
};