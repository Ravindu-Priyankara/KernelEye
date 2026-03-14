#include <stdio.h>
#include "banner_header.h"

void ke_print_banner(void) {

printf("\n");

printf("██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██╗         ███████╗██╗   ██╗███████╗\n");
printf("██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║         ██╔════╝╚██╗ ██╔╝██╔════╝\n");
printf("█████╔╝ █████╗  ██████╔╝██╔██╗ ██║█████╗  ██║         █████╗   ╚████╔╝ █████╗  \n");
printf("██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██║         ██╔══╝    ╚██╔╝  ██╔══╝  \n");
printf("██║  ██╗███████╗██║  ██║██║ ╚████║███████╗███████╗    ███████╗   ██║   ███████╗\n");
printf("╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝\n\n");

printf("KernelEye v%s\n", KE_VERSION);
printf("Kernel-Level Threat Detection & Behavioral Monitoring\n\n");

printf("eBPF Telemetry  •  Syscall Correlation  •  Real-Time Alerts\n\n");

printf("Observe the Kernel. Detect the Threat.\n\n");

printf("Author : Ravindu Priyankara\n");
printf("Research Project\n\n");

}

void 