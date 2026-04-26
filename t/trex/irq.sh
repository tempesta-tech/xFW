#!/usr/bin/env bash
set -euo pipefail

# PCI IDs for the two ports of ConnectX-6 Dx EN
PORT0_PCI="0000:ca:00.0"
PORT1_PCI="0000:ca:00.1"

# The NIC is attached to the 2nd Gold 6348 processor with 28 cores and 56 threads.
# This processor has odd `processor` numbers in /proc/cpuinfo and first threads go
# first and their siblings are in the 2nd half 57-111.
PORT0_CPUS=(1 5 9 13 17 21 25 29 33 37 41 45 49 53)
PORT1_CPUS=(3 7 11 15 19 23 27 31 35 39 43 47 51 55)

get_irqs() {
    local pci="$1"
    awk -v pci="$pci" '
        match($0, /^[[:space:]]*([0-9]+):.*[[:space:]](mlx5_comp[0-9]+)@pci:([^[:space:]]+)$/, m) {
            if (m[3] == pci)
                print m[1], m[2], $0
        }
    ' /proc/interrupts | sort -k2,2V
}

cpu_to_mask() {
    perl -e '
        my $cpu = shift;
        my @m = (0,0,0,0); # enough for CPUs up to 127
        $m[int($cpu/32)] = 1 << ($cpu % 32);
        pop @m while @m > 1 && $m[-1] == 0;
        print join(",", map { sprintf("%08x", $_) } reverse @m), "\n";
    ' "$1"
}

# Enable Linux syncookies
sysctl -w net.ipv4.tcp_syncookies=2

# The NIC is attached to the 2nd processor package. Each of the processors has 28
# cores (56 hyperthreads). So use 14 cores for each of the NIC ports.
ethtool -L enp202s0f1np1 combined 14
ethtool -L enp202s0f0np0 combined 14

mapfile -t PORT0_IRQS < <(get_irqs "$PORT0_PCI" | awk 'NR<=14 {print $1}')
mapfile -t PORT1_IRQS < <(get_irqs "$PORT1_PCI" | awk 'NR<=14 {print $1}')

echo "Port $PORT0_PCI queue[0] and queue[13]:"
get_irqs "$PORT0_PCI" | awk 'NR==1 || NR==14 {print $3}'
echo

echo "Port $PORT1_PCI queue[0] and queue[13]:"
get_irqs "$PORT1_PCI" | awk 'NR==1 || NR==14 {print $3}'
echo

if [ "${#PORT0_IRQS[@]}" -ne 14 ] || [ "${#PORT1_IRQS[@]}" -ne 14 ]; then
    echo "Did not find exactly 14 mlx5_comp IRQs per port" >&2
    exit 1
fi

echo "Assigning $PORT0_PCI..."
for n in $(seq 0 13); do
    irq="${PORT0_IRQS[$n]}"
    cpu="${PORT0_CPUS[$n]}"
    mask="$(cpu_to_mask "$cpu")"
    echo "$mask" > "/proc/irq/$irq/smp_affinity"
    echo "irq $irq -> cpu $cpu -> $(cat /proc/irq/$irq/smp_affinity)"
done
echo

echo "Assigning $PORT1_PCI..."
for n in $(seq 0 13); do
    irq="${PORT1_IRQS[$n]}"
    cpu="${PORT1_CPUS[$n]}"
    mask="$(cpu_to_mask "$cpu")"
    echo "$mask" > "/proc/irq/$irq/smp_affinity"
    echo "irq $irq -> cpu $cpu -> $(cat /proc/irq/$irq/smp_affinity)"
done
