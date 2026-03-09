#pragma once

// reverse shell detectors
struct ke_detection_result *reverse_shell_time_correlation(__u64 execve_ts, __u64 net_ts);
struct ke_detection_result *reverse_shell_filename_correlation(const char *filename, struct ke_detection_result *result);