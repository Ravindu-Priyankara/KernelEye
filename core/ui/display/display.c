#include <stdio.h>
#include "display.h"
#include "../../detections/detection_results.h"
#include "../../common/common_structs.h"

void ke_display_init(void)
{
    printf("=====================================================================\n");
    printf(" KernelEye Live Threat Monitor\n");
    printf("=====================================================================\n");

    printf("\033[36m%-8s %-8s %-10s %-20s %-10s\033[0m\n",
           "PID",
           "TYPE",
           "SEVERITY",
           "DETECTION",
           "SCORE");

    printf("---------------------------------------------------------------------\n");

    fflush(stdout);
}

const char *ke_event_type_str(int type)
{
    switch(type)
    {
        case KE_EVENT_EXECVE:
            return "EXECVE";

        case KE_EVENT_CONNECT:
            return "CONNECT";

        case KE_EVENT_REVERSE_SHELL:
            return "REVSH";

        default:
            return "UNKNOWN";
    }
}

const char *ke_severity_str(int severity)
{
    switch(severity)
    {
        case KE_SEV_INFO:
            return "INFO";

        case KE_SEV_WARNING:
            return "WARNING";

        case KE_SEV_CRITICAL:
            return "CRITICAL";

        default:
            return "UNKNOWN";
    }
}

const char *ke_detection_str(int id)
{
    switch(id)
    {
        case KE_DET_CONNECT_WITH_EXECVE:
            return "CONNECT+EXECVE";

        case KE_DET_REVERSE_SHELL:
            return "REVERSE_SHELL";

        default:
            return "UNKNOWN";
    }
}

void ke_display_event(
    int pid,
    int type,
    int severity,
    int detection_id,
    int score
)
{
    const char *type_str = ke_event_type_str(type);
    const char *sev_str  = ke_severity_str(severity);
    const char *det_str  = ke_detection_str(detection_id);

    printf("%-8d %-10s %-10s %-20s %-10d\n",
           pid,
           type_str,
           sev_str,
           det_str,
           score);

    fflush(stdout);
}

void ke_print_stats(struct stats *s)
{
    if(!s) return;

    printf("\n---------------------------------------------------------------------\n");

    printf("Events:%d | ReverseShells:%d | Alerts:%d | Blocks:%d\n",
           s->events,
           s->reverse_shells,
           s->alerts,
           s->blocks);

    fflush(stdout);
}