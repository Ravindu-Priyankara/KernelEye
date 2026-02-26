#pragma once

#include "../common/common_headers.h"
#include "common_helpers.h"
#include "../common/common_sockets.h"

/*
*   This helper's main task is identify the socket family type and return it to the requester.
*   Agrivements:   general sockaddr struct
*   Return: socket family type
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

static int __always_inline parse_socket_data(const int family, const void *user_ptr,
     void *map, const void *key, __u64 flags){
    
    struct sockaddr_in sin = {};    // This holds the IPV4 socket details
    struct sockaddr_in6 sin6 = {};  // This holds the IPV6 socket details 

    switch(family){
        case FAMILY_IPV4:{
            // copy socket details to IPV4 struct
            if(bpf_probe_read_user(&sin, sizeof(sin), user_ptr) < 0){
                return 0;
            }
            extract_ipv4_data(sin, net_ts, map, key, flags);

        }
    }
}

static int __always_inline extract_ipv4_data(const struct sockaddr_in sin, __u64 net_ts, void *map, const void *key, __u64 flags){
    int ret;
    __u32 addr = sin.sin_addr.s_addr;
    __u16 port = bpf_ntohs(sin.sin_port);
    ret = update_hash_map_element(map, key, &addr, flags);
}

// Protect socket type reordering
_Static_assert(FAMILY_UNKNOWN == 0, "Default socket family changed!");
_Static_assert(FAMILY_IPV4 == 1, "IPV4 socket family changed!");
_Static_assert(FAMILY_IPV6 == 2, "IPV6 socket family changed!");