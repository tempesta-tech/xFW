#ifndef TRACE_XDP_H
#define TRACE_XDP_H


struct event {
    char dev[16];

    __u32 ifindex;

    __u32 pkt_type;
    __u32 skb_iif;

    __u32 mark;
    __u32 priority;

    __u16 protocol;
    __u16 mac_len;

    __u16 mac_header;
    __u16 network_header;
    __u16 transport_header;

    __u32 len;
    __u32 data_len;
    __u64 data;

    unsigned char bytes[64];
};



#endif