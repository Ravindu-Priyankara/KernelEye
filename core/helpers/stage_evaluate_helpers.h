static inline __u8 evaluate_stage(__u32 flags)
{
    // will be add more
    if ((flags & CONNECT_SEEN) && (flags & DUP2_SEEN) && (flags & FD_REDERECTS_SEEN) && (flags & SOCKET_MATCH_SEEN))
        return STAGE_HIGH_RISK;

    return STAGE_NORMAL;
}