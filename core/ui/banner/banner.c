#include <stdio.h>
#include "banner.h"
#include "../color.h"

void ke_print_banner(void) {

printf("\n");

printf(COLOR_CYAN
    "██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██╗         ███████╗██╗   ██╗███████╗\n"
    "██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║         ██╔════╝╚██╗ ██╔╝██╔════╝\n"
    "█████╔╝ █████╗  ██████╔╝██╔██╗ ██║█████╗  ██║         █████╗   ╚████╔╝ █████╗  \n"
    "██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██║         ██╔══╝    ╚██╔╝  ██╔══╝  \n"
    "██║  ██╗███████╗██║  ██║██║ ╚████║███████╗███████╗    ███████╗   ██║   ███████╗\n"
    "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝\n\n"
    COLOR_RESET);

}

void ke_description(void){
    printf("\n");

    printf(COLOR_BRIGHT_CYAN "=====================================================================\n" COLOR_RESET);
    printf(COLOR_BRIGHT_GREEN "                     KernelEye v%s\n" COLOR_RESET, KE_VERSION);
    printf(COLOR_BRIGHT_CYAN "=====================================================================\n" COLOR_RESET);

    printf(COLOR_BRIGHT_WHITE "  Kernel-Level Threat Detection & Behavioral Monitoring\n\n" COLOR_RESET);

    printf(COLOR_BRIGHT_CYAN "  eBPF Telemetry  " COLOR_RESET);
    printf(COLOR_BRIGHT_BLACK "| " COLOR_RESET);
    printf(COLOR_BRIGHT_CYAN "Syscall Correlation  " COLOR_RESET);
    printf(COLOR_BRIGHT_BLACK "| " COLOR_RESET);
    printf(COLOR_BRIGHT_CYAN "Real-Time Alerts\n\n" COLOR_RESET);

    printf(COLOR_BRIGHT_YELLOW "  Observe the Kernel. Detect the Threat.\n" COLOR_RESET);

    printf(COLOR_BRIGHT_BLACK "-------------------------------------------------------------------\n" COLOR_RESET);

    printf(COLOR_BRIGHT_WHITE "  Author   : " COLOR_RESET COLOR_BRIGHT_GREEN "Ravindu Priyankara\n" COLOR_RESET);
    printf(COLOR_BRIGHT_WHITE "  Project  : " COLOR_RESET COLOR_BRIGHT_GREEN "KernelEye Security Research\n" COLOR_RESET);

    printf(COLOR_BRIGHT_CYAN "=====================================================================\n" COLOR_RESET);
}