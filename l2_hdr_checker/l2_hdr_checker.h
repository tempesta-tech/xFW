#ifndef TRACE_XDP_H
#define TRACE_XDP_H

#define BYTES_CNT 64

struct event {
	unsigned char bytes[BYTES_CNT];
	char dev[16];
	__u32 len;
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
};

#endif