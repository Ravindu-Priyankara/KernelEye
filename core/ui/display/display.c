#include <stdio.h>
#include "display.h"
#include "../../common/common_structs.h"
#include "../color.h"

// Initialize the console UI for KernelEye
void ke_display_init(void)
{
    printf(COLOR_BRIGHT_WHITE"                     KernelEye Live Threat Monitor\n"COLOR_RESET);
    printf(COLOR_BRIGHT_CYAN"=====================================================================\n"COLOR_RESET);

    printf(COLOR_BRIGHT_YELLOW"%-8s %-10s %-15s %-10s\n"COLOR_RESET,
           "PID",
           "TYPE",
           "SEVERITY",
           "FLAGS"
        );

    printf(COLOR_BRIGHT_BLACK"---------------------------------------------------------------------\n"COLOR_RESET);

    fflush(stdout);
}

// Convert numeric event type to string
const char *ke_event_type_str(int type)
{
    switch(type)
    {
        case KE_EVENT_REVERSE_SHELL:
            return "REVSH";

        default:
            return "UNKNOWN";
    }
}

// Convert severity level to string
const char *ke_severity_str(int severity)
{
    switch(severity)
    {
        case STAGE_BEHAVIORAL:
            return "WARNING";

        case STAGE_HIGH_RISK:
            return "HIGH_RISK";

        case STAGE_CONFIRMED:
            return "CRITICAL";

        default:
            return "UNKNOWN";
    }
}
// Display a single event in the UI
void ke_display_event(
    int pid,
    int type,
    int severity,
    uint64_t flags
)
{
    const char *type_str = ke_event_type_str(type);
    const char *sev_str  = ke_severity_str(severity);

    const char *color;

    switch(severity)
    {
        case STAGE_BEHAVIORAL:
            color = COLOR_BRIGHT_WHITE;
            break;

        case STAGE_HIGH_RISK:
            color = COLOR_BRIGHT_YELLOW;
            break;

        case STAGE_CONFIRMED:
            color = COLOR_RED;
            break;

        default:
            color = COLOR_RESET;
    }

    printf("%-8d %-10s %s%-15s%s 0x%llx\n",
           pid,
           type_str,
           color,
           sev_str,
           COLOR_RESET,
           (unsigned long long)flags
        );

    fflush(stdout);
}

// Print overall system statistics
void ke_print_stats(struct stats *s)
{
    if(!s) return;
    printf("\n---------------------------------------------------------------------\n");
    printf(COLOR_BRIGHT_YELLOW"                     SYSTEM STATUS"COLOR_RESET);
    printf("\n---------------------------------------------------------------------\n");
    printf("Events: %s%-5d%s | ReverseShells: %s%-5d%s | Alerts: %s%-5d%s | Blocks: %s%-5d%s\n",
           COLOR_GREEN, s->events, COLOR_RESET,
           COLOR_YELLOW, s->reverse_shells, COLOR_RESET,
           COLOR_RED, s->alerts, COLOR_RESET,
           COLOR_RED, s->blocks, COLOR_RESET);
    printf("\n---------------------------------------------------------------------\n");
    fflush(stdout);
}