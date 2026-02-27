#pragma once

#include "../common/common_headers.h"
#include "common_helpers.h"
#include "../common/common_sockets.h"
#include "../common/common_status.h"
#include "../common/common_validation.h"

/*
*   This helper's main task is identify the socket family type and return it to the requester.
*   Argivements:   general sockaddr struct
*   Return: socket family type
*/
static int __always_inline get_socket_family(const struct sockaddr *sa){
    //prevent null data
    if(validate_not_null(sa) != ERR_SUCCESS) return ERR_FAILURE;

    // Take socket family snapshot
    __u16 family = sa->sa_family;

    // For identify IPV4 and IPV6 socket family types
    switch(family){
        case AF_INET: return FAMILY_IPV4; 
        case AF_INET6: return FAMILY_IPV6;
        default: return FAMILY_UNKNOWN; // other families
    }

}

/*
*   This helper function is used to pass socket details to the correct functions. According to the socket family
*   Argivements
*       1. family type(AF_INET, AF_INET6)
*       2. pointer to the general sockaddr
*       3. struct for hold socket details
*   
*   Return 0 / -1 {0 = success, -1 = failure}
*/
static int __always_inline parse_socket_address(const int family, const void *usr_ptr, struct ke_sockaddr *event){
    // This validation helps to prevent NULL data.
    if(validate_not_null_int(family) != ERR_SUCCESS) return ERR_FAILURE;
    if(validate_not_null_duel(usr_ptr, event) != ERR_SUCCESS) return ERR_FAILURE;

    switch(family){
        case FAMILY_IPV4:{  // IPV4 block
            return parse_ipv4(usr_ptr, event);  // pass data to the ipv4 data extraction function
        }
        case FAMILY_IPV6:{
            return parse_ipv6(usr_ptr, event);  // pass data to the ipv6 data extraction function
        }
        default: ERR_FAILURE;   // Other socket categories
    }
}

/*
*   This helper function used to extract ipv4 data
*   Argivements:
*       1. pointer to the general sockaddr
*       2. struct for hold socket data
*
*   Return 0 / -1 {0 = Success, -1 = failure}
*/
static int __always_inline parse_ipv4(const void *usr_ptr, struct ke_sockaddr *event){
    // This validation helps to prevent NULL data.
    if(validate_not_null_duel(usr_ptr, event) != ERR_SUCCESS) return ERR_FAILURE;

    /*  This struct helps to extract ipv4
    *       1. ip address
    *       2. port number
    */
    struct sockaddr_in sin = {};

    // copy data from user pointer (ctx->args[1])
    if(bpf_probe_read_user(&sin, sizeof(sin), usr_ptr) < 0) return ERR_FAILURE;

    // fill the ipv4 event data
    event->family = FAMILY_IPV4;
    event->ipv4 = sin.sin_addr.s_addr;
    event->port = bpf_ntohs(sin.sin_port);

    return ERR_SUCCESS;
}

/*
*   This helper function used to extract ipv6 data
*   Argivements:
*       1. pointer to the general sockaddr
*       2. struct for hold socket data
*
*   Return 0 / -1 {0 = Success, -1 = failure}
*/
static int __always_inline parse_ipv6(const void *usr_ptr, struct ke_sockaddr *event){
    // This validation helps to prevent NULL data.
    if(validate_not_null_duel(usr_ptr, event) != ERR_SUCCESS) return ERR_FAILURE;
    
    /*  This struct helps to extract ipv6
    *       1. ip address
    *       2. port number
    */
    struct sockaddr_in6 sin6 = {};

    //copy data to sockaddr_in6 from user pointer (ctx->args[1])
    if(bpf_probe_read_user(&sin6, sizeof(sin6), usr_ptr) < 0) return ERR_FAILURE;

    // copy the ipv6 address to our struct
    __builtin_memcpy(event->tpv6, &sin6.sin6_addr, 16);

    // fill other ipv6 data
    event->family = FAMILY_IPV6;
    event->port = bpf_ntohs(sin6.sin6_port);

    return ERR_SUCCESS;

}