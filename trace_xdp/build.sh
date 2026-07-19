bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -O2 -g -target bpf \
      -D__TARGET_ARCH_x86 \
      -c trace_xdp.bpf.c \
      -o trace_xdp.bpf.o

bpftool gen skeleton trace_xdp.bpf.o > trace_xdp.skel.h
clang -O2 trace_xdp.c \
      -lbpf -lelf -lz \
      -o trace_xdp