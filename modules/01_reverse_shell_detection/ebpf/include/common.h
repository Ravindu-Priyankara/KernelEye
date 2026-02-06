
#pragma once    // stop duplication (preprocessor directives)

//Macros 

/*
*   These macros help to identify program types. (event.type)
*/
#define EVT_SOCKET 1    
#define EVT_CONNECT 2
#define EVT_DUP2 3
#define EVT_EXECVE 4

/*
*   These macros used for `execve syscall` have argv data sizes defined.
*/
#define MAX_ARGS 3
#define ARG_LEN 64

/*
*   These macros are used for IPv4 or IPv6 identification.
*/
#define AF_INET 2
#define AF_INET6 10