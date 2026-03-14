#include <stdio.h>
#include "banner.h"

void ke_print_banner(void) {

printf("\n");

printf("██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██╗         ███████╗██╗   ██╗███████╗\n");
printf("██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║         ██╔════╝╚██╗ ██╔╝██╔════╝\n");
printf("█████╔╝ █████╗  ██████╔╝██╔██╗ ██║█████╗  ██║         █████╗   ╚████╔╝ █████╗  \n");
printf("██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██║         ██╔══╝    ╚██╔╝  ██╔══╝  \n");
printf("██║  ██╗███████╗██║  ██║██║ ╚████║███████╗███████╗    ███████╗   ██║   ███████╗\n");
printf("╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝\n\n");

}

void ke_description(void){
    printf("KernelEye v%s\n", KE_VERSION);
    printf("Kernel-Level Threat Detection & Behavioral Monitoring\n\n");

    printf("eBPF Telemetry  •  Syscall Correlation  •  Real-Time Alerts\n\n");

    printf("Observe the Kernel. Detect the Threat.\n\n");

    printf("Author : Ravindu Priyankara\n");
    printf("Research Project\n\n");
}


void ke_display_init(void)
{
    printf("\033[2J"); // clear screen
    printf("\033[H");  // move cursor to top

    printf("=====================================================================\n");
    printf(" KernelEye Live Threat Monitor\n");
    printf("=====================================================================\n");

    printf("%-8s %-8s %-10s %-20s %-10s\n",
           "PID",
           "TYPE",
           "SEVERITY",
           "DETECTION",
           "SCORE");

    printf("---------------------------------------------------------------------\n");

    fflush(stdout);
}