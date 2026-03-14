#include <stdio.h>
#include "display.h"

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

void ke_display_event(
    int pid,
    const char *type,
    const char *severity,
    const char *detection,
    int score
)
{
    printf("%-8d %-8s %-10s %-20s %-10d\n",
           pid,
           type,
           severity,
           detection,
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