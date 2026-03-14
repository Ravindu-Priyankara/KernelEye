#include <stdio.h>
#include "display.h"
#include "../../detections/detection_results.h"
#include "../../common/common_structs.h"
#include "../color.h"

void ke_display_init(void)
{
    printf(COLOR_BRIGHT_WHITE"                     KernelEye Live Threat Monitor\n"COLOR_RESET);
    printf(COLOR_BRIGHT_CYAN"=====================================================================\n"COLOR_RESET);

    printf(COLOR_BRIGHT_YELLOW"%-8s %-10s %-10s %-20s %-10s\n"COLOR_RESET,
           "PID",
           "TYPE",
           "SEVERITY",
           "DETECTION",
           "SCORE");

    printf(COLOR_BRIGHT_BLACK"---------------------------------------------------------------------\n"COLOR_RESET);

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

    const char *color;

    switch(severity)
    {
        case KE_SEV_INFO:
            color = COLOR_BRIGHT_WHITE;
            break;

        case KE_SEV_WARNING:
            color = COLOR_BRIGHT_YELLOW;
            break;

        case KE_SEV_CRITICAL:
            color = COLOR_BRIGHT_RED;
            break;

        default:
            color = COLOR_RESET;
    }

    printf("%-8d %-10s %s%-10s%s %-20s %-10d\n",
           pid,
           type_str,
           color,
           sev_str,
           COLOR_RESET,
           det_str,
           score);

    fflush(stdout);
}

void ke_print_stats(struct stats *s)
{
    if(!s) return;
    printf(COLOR_BRIGHT_YELLOW"                            SYSTEM STATUS"COLOR_RESET);
    printf("\n---------------------------------------------------------------------\n");
    printf("Events: %s%-5d%s | ReverseShells: %s%-5d%s | Alerts: %s%-5d%s | Blocks: %s%-5d%s\n",
           COLOR_GREEN, s->events, COLOR_RESET,
           COLOR_YELLOW, s->reverse_shells, COLOR_RESET,
           COLOR_RED, s->alerts, COLOR_RESET,
           COLOR_RED, s->blocks, COLOR_RESET);
    fflush(stdout);
}