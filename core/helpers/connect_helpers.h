#pragma once

#include "../common/common_headers.h"

// We focused socket family types
typedef enum {
    FAMILY_UNKNOWN = 0, // for other categories
    FAMILY_IPV4,    // for ipv4
    FAMILY_IPV6     // for ipv6
} socket_category;

/*
*   This helper's main task is identify the socket family type and return it to the requester.
*/
static int __always_inline get_socket_family(const struct sockaddr *sa){
    if(!sa) return FAMILY_UNKNOWN; 

    // Take socket family snapshot
    __u16 family = sa->sa_family;

    // For identify IPV4 and IPV6 socket family types
    switch(family){
        case AF_INET: return FAMILY_IPV4; 
        case AF_INET6: return FAMILY_IPV6;
        default: return FAMILY_UNKNOWN;
    }

}

// Protect socket type reordering
_Static_assert(FAMILY_UNKNOWN == 0, "Default socket family changed!");
_Static_assert(FAMILY_IPV4 == 1, "IPV4 socket family changed!");
_Static_assert(FAMILY_IPV6 == 2, "IPV6 socket family changed!");