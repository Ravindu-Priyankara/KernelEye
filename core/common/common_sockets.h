#pragma once

#include "common_headers.h"

// This vertion focus on AF_INET AND AF_INET6 only
typedef enum {
    FAMILY_UNKNOWN = 0, // other varients
    FAMILY_IPV4,    // for AF_INET
    FAMILY_IPV6,    // for AF_INET6
} socket_category;



// Protect socket type reordering
_Static_assert(FAMILY_UNKNOWN == 0, "Default socket family changed!");
_Static_assert(FAMILY_IPV4 == 1, "IPV4 socket family changed!");
_Static_assert(FAMILY_IPV6 == 2, "IPV6 socket family changed!");