bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -O2 -g -target bpf \
      -D__TARGET_ARCH_x86 \
      -c l2_hdr_checker.bpf.c \
      -o l2_hdr_checker.bpf.o

bpftool gen skeleton l2_hdr_checker.bpf.o > l2_hdr_checker.skel.h
clang -O2 l2_hdr_checker.c \
      -lbpf -lelf -lz \
      -o l2_hdr_checker