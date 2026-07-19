#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>

#include "trace_xdp.skel.h"
#include "trace_xdp.h"



static volatile sig_atomic_t stop;


static void sig_handler(int sig)
{
    stop = 1;
}



static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;


    printf(
        "dev=%s ifindex=%u type=%u proto=0x%x "
        "iif=%u mark=0x%x prio=%u "
        "mac_len=%u "
        "mac=%u net=%u trans=%u "
        "len=%u\n",
        e->dev,
        e->ifindex,
        e->pkt_type,
        ntohs(e->protocol),
        e->skb_iif,
        e->mark,
        e->priority,
        e->mac_len,
        e->mac_header,
        e->network_header,
        e->transport_header,
        e->len
    );


    printf("bytes:");

    for (int i = 0; i < 32; i++)
        printf(" %02x", e->bytes[i]);

    printf("\n\n");


    return 0;
}



int main()
{
    struct trace_xdp_bpf *skel;
    struct ring_buffer *rb;
    int err;



    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);



    libbpf_set_strict_mode(
        LIBBPF_STRICT_ALL
    );



    skel =
        trace_xdp_bpf__open_and_load();


    if (!skel) {
        fprintf(stderr,
            "failed open/load\n");
        return 1;
    }



    err =
        trace_xdp_bpf__attach(skel);


    if (err) {
        fprintf(stderr,
            "attach failed %d\n",
            err);

        goto cleanup;
    }



    rb =
        ring_buffer__new(
            bpf_map__fd(skel->maps.events),
            handle_event,
            NULL,
            NULL
        );


    if (!rb) {
        fprintf(stderr,
            "ringbuf failed\n");

        goto cleanup;
    }



    printf("running...\n");



    while (!stop) {

        err =
            ring_buffer__poll(
                rb,
                100
            );


        if (err < 0)
            break;
    }



    ring_buffer__free(rb);



cleanup:

    trace_xdp_bpf__destroy(skel);

    return 0;
}