
#define LOOPBACK_IPV4 0x0100007F  // 127.0.0.1 in little endian
#define HIGH_PORT_MIN 1024
#define EPHEMERAL_PORT_MIN 49152

// for check is that private ip
static __always_inline int is_private_ipv4(__u32 ip){

    // extract bytes from left
    __u8 a1 = ip & 0xFF; 
    __u8 a2 = (ip >> 8) & 0xFF;
    /*__u8 a3 = (ip >> 16) & 0xFF;
    __u8 a4 = (ip >> 24) & 0xFF;*/

    /*
    * Target public ipv4 ranges
    *   - 10.0.0.0/8
    *   - 192.168.0.0/16
    *   - 172.16.0.0/12
    */

    // 10.0.0.0/8
    if(a1 == 10) return 1;

    // 192.168.0.0/16
    if(a1 == 192 && a2 == 168) return 1;

    // 172.16.0.0/12
    if(a1 == 172 && (a2 >= 16 && a2 <= 31)) return 1;

    return 0;
}

// check is that suspicious port
static __always_inline int is_suspicious_port(__u16 port){
    if (port == 4444 || port == 1337 ||
        port == 9001 || port == 5555
    )return 1;

    return 0;
}

// high port{huge false positives}
static __always_inline int is_high_port(__u16 port)
{
    return port > HIGH_PORT_MIN;
}

// best with score > 30
static __always_inline int is_ephemeral_port(__u16 port)
{
    return port >= EPHEMERAL_PORT_MIN;
}