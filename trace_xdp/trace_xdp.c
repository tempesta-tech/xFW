#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /*
     * Только открыть объект, без загрузки в ядро
     */
    skel = trace_xdp_bpf__open();

    if (!skel) {
        fprintf(stderr, "failed open\n");
        return 1;
    }


    /*
     * Забираем уже существующую map от xdp-loader
     */
    int skip_fd = bpf_obj_get(
        "/sys/fs/bpf/tc/globals/xdp_should_skip"
    );

    if (skip_fd < 0) {
        perror("bpf_obj_get xdp_should_skip");
        goto cleanup;
    }


    /*
     * Говорим skeleton использовать существующую map,
     * а не создавать новую
     */
    err = bpf_map__reuse_fd(
        skel->maps.xdp_should_skip,
        skip_fd
    );

    if (err) {
        fprintf(stderr,
            "reuse map failed: %d\n",
            err);
        goto cleanup;
    }


    /*
     * Теперь загружаем BPF объект
     */
    err = trace_xdp_bpf__load(skel);

    if (err) {
        fprintf(stderr,
            "load failed: %d\n",
            err);
        goto cleanup;
    }


    err = trace_xdp_bpf__attach(skel);

    if (err) {
        fprintf(stderr,
            "attach failed %d\n",
            err);
        goto cleanup;
    }


    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(stderr, "ringbuf failed\n");
        goto cleanup;
    }


    printf("running...\n");


    while (!stop) {
        err = ring_buffer__poll(rb, 100);

        if (err < 0)
            break;
    }


    ring_buffer__free(rb);


cleanup:
    trace_xdp_bpf__destroy(skel);

    return 0;
}
