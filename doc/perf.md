# Performance Evaluation Guide

The main performance page is at our [wiki](https://tempesta-tech.com/tempesta-escudo/knowledge-base/Performance/)
and here are more details and gotchas about specific configurations and tests.

## Common servers setup

Disable CPU mitigations, which makes no sense on a single-user machines, on both machines:
add `spectre_v2=off ibrs=off` to `GRUB_CMDLINE_LINUX_DEFAULT`.

### Mellanox drivers

> These steps could should be repeated on SUT and Generator machines.

1. [Download](https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/) latest OFED
drivers:
* MLNX_OFED_LINUX-24.01-0.3.3.1-ubuntu23.10-x86_64 for Ubuntu 23.10.
* For Ubuntu 24.04 (direct link just for convenience):
```
wget http://content.mellanox.com/ofed/MLNX_OFED-24.07-0.6.1.0/MLNX_OFED_LINUX-24.07-0.6.1.0-ubuntu24.04-x86_64.tgz
tar zxvf MLNX_OFED_LINUX-24.07-0.6.1.0-ubuntu24.04-x86_64.tgz
cd MLNX_OFED_LINUX-24.07-0.6.1.0-ubuntu24.04-x86_64.tgz
```

2. Install drivers with  appropriate options and packages required for them:
```
sudo apt install -y libnl-route-3-dev make gcc libnuma1 debhelper dkms chrpath quilt libltdl-dev libc6-dev libnl-3-dev lsb-base autotools-dev autoconf automake swig m4 graphviz
sudo ./mlnxofedinstall --with-mft --with-mstflint --dpdk --upstream-libs
sudo /etc/init.d/openibd restart
```

> It's OK to see the error message after installation:
```
The firmware for this device is not distributed inside Mellanox driver: 98:00.0 (PSID: DEL0000000027)
To obtain firmware for this device, please contact your HW vendor.

Failed to update Firmware.
See /tmp/MLNX_OFED_LINUX.17127.logs/fw_update.log
```

## Install TRex on Generator

1. TRex has issues with modern compilers, so we need to install GCC 10
```
sudo apt install -y gcc-10 g++-10
```

> Alternatively you can build TRex in a Docker container (see [instructions](https://github.com/cisco-system-traffic-generator/trex-core))

2. Download latest TRex version from [Github](https://github.com/cisco-system-traffic-generator/trex-core)
(only the master branch contains fix for ConnectX-6, which is not included in latest release version!):
```
mkdir /trex && cd /trex # specify you own folder, but not /root
git clone https://github.com/cisco-system-traffic-generator/trex-core.git && cd trex-core
```

3. Start driver:
```
sudo mlxfwreset -d mlx5_0 --yes r
```

4. Build TRex and install its dependencies:
```
sudo apt install zlib1g-dev
cd linux_dpdk
CC=gcc-10 CXX=g++-10 ./b configure
CC=gcc-10 CXX=g++-10 ./b build
```

## Run xFW on SUT

0. Install xFW by a custom path:
```
PREFIX=/root/ak/escudo_install/ make install
```

1. [Start xFW](/Basic-Administration/#run-amp-stop) and load configuration. It's
   useful to run xFW from a local (`main`) build:
```
ESCUDO_PATH=~/ak/escudo_install/ TFW_CFG_FILE=~/ak/xfw.json ~/ak/escudo_install/bin/xfwctl --start
ESCUDO_PATH=~/ak/escudo_install/ TFW_CFG_FILE=~/ak/xfw.json ~/ak/escudo_install/bin/xfwctl --status
```

2. Load rules, e.g.
```
./bin/tfw push -c ../src_150k_wl.conf
```

3. Assign additional IP addresses (required at least for TCP SYN cookies testing)
   and run TCP listening daemons (required for registering listening sockets)
   on the addresses with [run_servers.sh](https://github.com/tempesta-tech/xFW/blob/main/t/trex/run_servers.sh):
```
./run_servers.sh
```

4. Run [irq.sh](https://github.com/tempesta-tech/xFW/blob/main/t/trex/irq.sh):
```
./irq.sh
```


## Configure Generator

1. (Optional) change MTU. TRex optimizes throughput via big frames, but we need normal traffic to
emulate real workloads:
```
git diff
diff --git a/scripts/dpdk_setup_ports.py b/scripts/dpdk_setup_ports.py
index bc7003de2..646c15909 100755
--- a/scripts/dpdk_setup_ports.py
+++ b/scripts/dpdk_setup_ports.py
@@ -489,7 +489,8 @@ Other network devices
             out=out.decode(errors='replace');

     def set_max_mtu_mlx_device(self,dev_id):
-        mtu=9*1024+22
+#        mtu=9*1024+22
+        mtu=1500
         dev_mtu=self.get_mtu_mlx (dev_id);
         if (dev_mtu>0) and (dev_mtu!=mtu):
             self.set_mtu_mlx(dev_id,mtu);
```

2. Determine NIC ports' PCI IDs:
```
lspci |grep 'ConnectX-6 Dx'
98:00.0 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
98:00.1 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
```

3. Copy TRex config amd adjust NIC ports in it if necessary:
```
cp ~/xFW/t/trex/trex_cfg.yaml /etc
```

> Dummy interfaces allow to use both ports for sending packets, and non of them for receiving.

4. If you have Python > 3.11 (Ubuntu 24):

Ubuntu 24 is shipped with Python 3.12, so TRex doesn't work out of the box due to legacy Scapy
module and you need to install Python 3.11:
```
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update && sudo apt install python3.11 python3.11-venv
```

Then create venv in `trex-core/scripts` directory:
```
cd /trex/trex-core/scripts
python3.11 -m venv venv
source ./venv/bin/activate
python --version # ensure 3.11
```

Now you can run TRex Python scripts (`./t-rex-64`, `./trex-console`, `./trex-cfg` etc.). But
`sudo` doesn't work with `venv`, so use `sudo -i` before venv activation.

Install dependencies inside venv:
```
venv/bin/python venv/bin/pip install cffi
```

You can remove `venv` just removing the directory:
```
rm -rf venv
```

5. Prepare TRex:
```
cd /trex/trex-core/scripts
sudo -i
source ./venv/bin/activate
./trex-cfg
apt install -y dpdk
dpdk-hugepages.py --setup 2G
```

TODO: address 2G hugepages - it seems boot setup is more efficient

> Reboot the server if you see error message like:
```
ETHDEV: Cannot allocate ethdev shared data
mlx5_net: can not allocate rte ethdev
mlx5_net: probe of PCI device 0000:98:00.0 aborted after encountering an error: Cannot allocate memory
mlx5_common: Failed to load driver mlx5_eth
EAL: Requested device 0000:98:00.0 cannot be used
ETHDEV: Cannot allocate ethdev shared data
mlx5_net: can not allocate rte ethdev
mlx5_net: probe of PCI device 0000:98:00.1 aborted after encountering an error: Cannot allocate memory
mlx5_common: Failed to load driver mlx5_eth
EAL: Requested device 0000:98:00.1 cannot be used
```


## Monitoring

Check NIC receive buffer overflow with:
```
ethtool -S <dev> | grep rx_out_of_buffer
```
High non-zero values mean that CPU (XDP prog) is not in time to process all ingress
packets.

For traffic performance statistics use `bmon` or `dstat`, e.g.
```
bmon -p 'enp202s0f*'
```
```
dstat --cpu-adv --net -N enp202s0f1np1 -N enp202s0f0np0 --net-packets --sys --bits --time --int -I RES
```

Also `htop` is good to observe CPU utilization.


## Profiling

Standard `bpftool` shipped with Ubuntu 24 LTS doesn't have JIT disassembly and
profiling (skeletons) support, so you need to build it from source code:
```
git clone --depth 1 --branch v6.8 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-6.8
cd linux-6.8/tools/bpf/bpftool
make -j"$(nproc)"
# ./bpftool --version
bpftool v7.4.0
using libbpf v1.4
features: llvm, skeletons
```

You should see 'llvm' and 'skeletons' in the features list (for the standard bpftool
it is empty).

Also standard `perf` doesn't have BPF annotation support, so you need to build it
from sources as well:
```
apt install -y build-essential flex bison pkg-config libelf-dev libdw-dev \
  libunwind-dev libslang2-dev libperl-dev python3-dev libzstd-dev libcap-dev \
  libnuma-dev binutils-dev libbabeltrace-dev libtraceevent-dev libtracefs-dev
cd linux-6.8/tools/perf/
make clean
make -j"$(nproc)" BUILD_NONDISTRO=1 WERROR=0
```
Check that all the requested options are 'on':
```
./perf version --build-options | grep -Ei 'bfd|opcode|disassembler|libelf|dwarf|bpf'
                 dwarf: [ on  ]  # HAVE_DWARF_SUPPORT
    dwarf_getlocations: [ on  ]  # HAVE_DWARF_GETLOCATIONS_SUPPORT
                libbfd: [ on  ]  # HAVE_LIBBFD_SUPPORT
                libelf: [ on  ]  # HAVE_LIBELF_SUPPORT
    libdw-dwarf-unwind: [ on  ]  # HAVE_DWARF_SUPPORT
                   bpf: [ on  ]  # HAVE_LIBBPF_SUPPORT
               libpfm4: [ on  ]  # HAVE_LIBPFM
         bpf_skeletons: [ on  ]  # HAVE_BPF_SKEL
```

Get program ID with ('199' is used hereafter):
```
bpftool prog show | grep -A2 xfw_xdp
```

Collect x86-64 and eBPF disassembly with C code references for mapping samples to interpret profiling results:
```
./bpftool prog dump jited id 199 linum opcodes > /tmp/xfw.jit
./bpftool prog dump xlated id 199 linum opcodes > /tmp/xfw.bpf
```

Run workload and start profiling:
```
./bpftool prog profile id 199 duration 60 cycles instructions llc_misses dtlb_misses

        1172580977 run_cnt
     1261619554721 cycles
     3280698993346 instructions        #     2.60 insns per cycle
         227773681 llc_misses          #    69.43 LLC misses per million insns
          96098822 dtlb_misses         #    29.29 dtlb misses per million insns
```
which means:
1. duration:              60 sec
2. run rate:              1,172,580,977 / 60 = 19.54 Mpps
3. cycles per run:        1,261,619,554,721 / 1,172,580,977 ≈ 1076 cycles/packet
4. instructions per run:  3,280,698,993,346 / 1,172,580,977 ≈ 2798 insns/packet
5. LLC misses per run:    227,773,681 / 1,172,580,977 ≈ 0.194
6. DTLB misses per run:   96,098,822 / 1,172,580,977 ≈ 0.082

You can get annotated assembly code with:
```
linux-6.8/tools/perf/perf record -a -g -e cycles:k -c 100000 -m 1024 -- sleep 60
linux-6.8/tools/perf/perf annotate --stdio --symbol=bpf_prog_0798899db6da08a4_xfw_xdp
```

The most of our code has `__always_inline` for functions, so we can get a
analytics-friendly call stacks and can use annotated assembly only at the moment.


## The Baseline

We have dual 100Gbps port NIC.

For a TCP SYN segment we have 74 bytes for Ethernet, IPv4 and TCP headers - this is
what xFW accounts as a packet length. Meantime, there are also FCS, Preamble + SFD
and nter-frame gap, which add about 24 bytes of overhead resulting to 98 bytes on
wire. I.e. the theoretical peak for the adapter is about 255Mpps, but
[NVIDIA announced](https://www.nvidia.com/content/dam/en-zz/Solutions/Data-Center/documents/nvidia-connectx-6-dx-en-hpe-datasheet.pdf)
215Mpps.

To estimate performance baselines for the current setup we created the
[xdp_baseline](https://github.com/tempesta-tech/xFW/blob/main/t/trex/xdp_baseline.c) program -
a minimal XDP module to run TRex load against to.

For TRex we use `-c 23` since it rejects larger values with:
```
src/trex_global.h:913 assert(size<=MAX_PKT_ALIGN_BUF_9K);
```

> Note non-zero `Total_queue_full` values. This is generally not recommended, but for
> DDoS stress testing this is acceptable since TRex still reports actual wired
> traffic.


## ICMP flood

> We separately generate ICMP traffic and TCP/UDP flood traffic. It doesn't have much sense other
than to save some time. TCP/UDP config was written before and we don't have much time to fully
rewrite it from stateful to stateless mode.

This test generates ICMPv6 traffic only.

1. Copy `trex/perf/icmpv6_fix_cs.py` to `trex-core/scripts` directory:
```
scp icmpv6_fix_cs.py gen:/trex/trex-core/scripts
```

> We use slightly modified TRex script for ICMPv6 flood generation.

2. In one window run:
```
./t-rex-64 -i -c 23
```

3. In another window run:
```
./trex-console
```

4. Inside TRex console run:
```
start -f icmpv6_fix_cs.py -m 122000000
```

You should see something like this at TRex info panel:
```
-Per port stats table
      ports |               0 |               2
 -----------------------------------------------------------------------------------------
   opackets |      1704026304 |      1700013447
     obytes |    139730156928 |    139401102654
   ipackets |            8689 |               5
     ibytes |          817218 |             922
    ierrors |               0 |               0
    oerrors |               0 |               0
      Tx Bw |      64.66 Gbps |      64.32 Gbps

-Global stats enabled
 Cpu Utilization : 67.4  %  8.3 Gb/core
 Platform_factor : 1.0
 Total-Tx        :     128.97 Gbps
 Total-Rx        :     405.98 Kbps
 Total-PPS       :     196.61 Mpps
 Total-CPS       :       0.00  cps

 Expected-PPS    :       0.00  pps
 Expected-CPS    :       0.00  cps
 Expected-BPS    :       0.00  bps

 Active-flows    :        0  Clients :        0   Socket-util : 0.0000 %
 Open-flows      :        0  Servers :        0   Socket :        0 Socket/Clients :  -nan
 Total_queue_full : 376921385
 drop-rate       :     128.97 Gbps
 current time    : 81.5 sec
 test duration   : 0.0 sec
```
* Workload is 129 Gbps and 196 Mpps.
* No `ierrors` and `oerrors`.

On SUT server in `bmon` or `ifconfig` we see that amount of traffic passed to kernel is about zero
(we rate limit it, don't drop) and CPU load is adequate (less than 35% on any core).


## TCP & UDP flood

This test generates UDP traffic (packet length 1514 bytes) and various types of TCP flood traffic
(length 54 bytes):
* ACK flood
* FIN flood
* NULL flood
* RST flood
* SYN flood
* SYN-ACK flood
* URG flood
* XMAS flood (FIN-PUSH-URG)

> Currently the test doesn't support IPv6, IPv4 only.

1. Next steps are for Generator: copy `traffic/` and `tcpudp.yaml` to `trex-core/scripts`:
```
scp -r traffic/ tcpudp.yaml gen:/trex/trex-core/scripts
```

2. Run test (directly, without `./trex-console`):
```
./t-rex-64 --ipv6 -f tcpudp.yaml -m 650 -c 23
```


## TCP SYN flood

Use [run_servers.sh](https://github.com/tempesta-tech/xFW/blob/main/t/trex/run_servers.sh) to assign
enough IP addresses on both the NIC ports and run a Python TCP server on each of
them.

[syncookies.conf](https://github.com/tempesta-tech/xFW/blob/main/t/trex/syncookies.conf) is the
xFW configuration and [syn_flood.yaml](https://github.com/tempesta-tech/xFW/blob/main/t/trex/syn_flood.yaml)
is the TRex generation configuration.


## Latency

We use TRex for [latency testing](https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_measuring_jitter_latency).
In this test we generate a small DDoS-like workload in parallel with ICMP echo probes:
```
./t-rex-64 -f syn_flood_lat.yaml -m 1000 -c 23 -l 1 --l-pkt-mode 1 -d 60
```

It's hard to make TRex to correctly use both the interfase for ICMP probbing, so we
use single socket traffic profile
[syn_flood_lat.yaml](https://github.com/tempesta-tech/xFW/blob/main/t/trex/syn_flood_lat.yamla)
and [TRex config](https://github.com/tempesta-tech/xFW/blob/main/t/trex/trex_lat_cfg.yaml)
