#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "trace_xdp.h"


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");



SEC("kprobe/bpf_prog_run_generic_xdp")
int BPF_KPROBE(trace_xdp, struct sk_buff *skb)
{
    struct event *e;
    struct net_device *dev;
    void *data;


    if (!skb)
        return 0;


    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
        return 0;


    __builtin_memset(e, 0, sizeof(*e));


    dev = BPF_CORE_READ(skb, dev);


    if (dev) {
        BPF_CORE_READ_STR_INTO(
            &e->dev,
            dev,
            name
        );

        e->ifindex =
            BPF_CORE_READ(dev, ifindex);
    }


/*
     * pkt_type is bitfield:
     *
     * __u8 pkt_type:3;
     *
     * поэтому читаем целый byte
     */
    __u8 pkt;

    BPF_CORE_READ_INTO(
        &pkt,
        skb,
        __pkt_type_offset
    );

    e->pkt_type = pkt & 0x7;


    e->skb_iif =
        BPF_CORE_READ(skb, skb_iif);


    e->mark =
        BPF_CORE_READ(skb, mark);


    e->priority =
        BPF_CORE_READ(skb, priority);


    e->protocol =
        BPF_CORE_READ(skb, protocol);


    e->mac_len =
        BPF_CORE_READ(skb, mac_len);


    e->mac_header =
        BPF_CORE_READ(skb, mac_header);


    e->network_header =
        BPF_CORE_READ(skb, network_header);


    e->transport_header =
        BPF_CORE_READ(skb, transport_header);


    e->len =
        BPF_CORE_READ(skb, len);


    e->data_len =
        BPF_CORE_READ(skb, data_len);



    data = BPF_CORE_READ(skb, data);

    if (data) {
        bpf_probe_read_kernel(
            e->bytes,
            sizeof(e->bytes),
            data
        );
    }



    bpf_ringbuf_submit(e, 0);

    return 0;
}