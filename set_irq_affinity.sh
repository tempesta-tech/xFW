#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Pin network device IRQ groups to physical cores.
#
# Run as root with one or two network interface names; extra names are ignored.
#
# IRQs are assigned to separate physical cores on the device's NUMA node, using
# only one hardware thread per core. Two devices on the same node split its
# cores between their CPU pools. If the node has an odd number of physical
# cores, the second device's CPU pool contains the extra core. Devices on
# different nodes each have all physical cores on their own node available.
# A device without a known NUMA node uses all physical cores. If both devices
# lack a known node, they split all physical cores equally, with any extra core
# assigned to the second device's CPU pool. For a mixed pair, the known device
# uses its local node and the unknown device uses all cores; their pools may
# overlap. The number of CPUs actually assigned IRQ groups is limited to the
# NIC's configured queue count; remaining CPUs are unused by this script.
#
# The configured queue count is the sum of RX, TX, and Combined channels
# reported by ethtool -l; Other channels are excluded. The script fails if this
# count exceeds the device's allowed CPU count. It assigns at most one IRQ group
# per CPU and leaves excess IRQ groups unchanged.
#
# IRQ discovery uses the PCI address reported by ethtool and excludes IRQ names
# containing "async". For virtio_net devices, only handlers named
# virtioN-input.Q or virtioN-output.Q are selected, and each matching input/output
# queue pair is pinned to the same CPU.
#
# irqbalance must be stopped or configured to leave these IRQs alone so that it
# does not override the affinity settings.

set -euo pipefail

usage()
{
	printf 'Usage: %s iface_name [iface_name]\n' "$0"
}

error()
{
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

get_device_numa_node()
{
	local device="$1" node node_file

	node_file="/sys/class/net/$device/device/numa_node"
	if [[ ! -r $node_file ]]; then
		# A PCI-backed virtio net device exposes NUMA locality on its parent.
		node_file="/sys/class/net/$device/device/../numa_node"
	fi
	if [[ -r $node_file ]] && read -r node < "$node_file" &&
	   [[ $node =~ ^[0-9]+$ ]]; then
		printf '%s\n' "$node"
	else
		printf '%s\n' -1
	fi
}

get_cpu_sets()
{
	local core_data node_cores core_count cpu_scope i j start end
	local -a devices=("$@") nodes cores cpu_sets

	for i in "${!devices[@]}"; do
		nodes[$i]=$(get_device_numa_node "${devices[$i]}") || exit 1
	done

	# Select the first online CPU of each physical core, excluding SMT siblings.
	# Core IDs can repeat across sockets; CPU IDs need not be contiguous.
	core_data=$(lscpu --online --parse=CPU,CORE,SOCKET,NODE | awk -F, '
		/^#/ { next }
		NF != 4 || $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ ||
			$3 !~ /^[0-9]+$/ { exit 1 }
		{
			if ($4 == "" || $4 == "-" || $4 == "-1")
				$4 = -1
			else if ($4 !~ /^[0-9]+$/)
				exit 1
			key = $4 ":" $3 ":" $2
			if (!(key in cpus)) {
				keys[++count] = key
				cpus[key] = $1 " " $4
			}
		}
		END {
			for (i = 1; i <= count; i++)
				print cpus[keys[i]]
		}') || error "Cannot determine online CPU topology using lscpu."
	[[ -n $core_data ]] || error "No online physical cores found."

	for i in "${!devices[@]}"; do
		cpu_scope="NUMA node ${nodes[$i]}"
		if [[ ${nodes[$i]} == -1 ]]; then
			cpu_scope="all NUMA nodes (device node unknown)"
		fi
		node_cores=$(awk -v node="${nodes[$i]}" 'node == -1 || $2 == node { print $1 }' <<< "$core_data")
		[[ -n $node_cores ]] ||
			error "No online physical cores on $cpu_scope for '${devices[$i]}'."
		mapfile -t cores <<< "$node_cores"
		core_count=${#cores[@]}
		start=0
		end=$core_count
		if (( ${#devices[@]} == 2 )) && [[ ${nodes[0]} == "${nodes[1]}" ]]; then
			(( core_count >= 2 )) ||
				error "Two devices sharing $cpu_scope require at least two online physical cores."

			if (( i == 0 )); then
				end=$((core_count / 2))
			else
				start=$((core_count / 2))
			fi
		fi
		cpu_sets[$i]=""
		for ((j = start; j < end; j++)); do
			cpu_sets[$i]+="${cpu_sets[$i]:+,}${cores[$j]}"
		done
		printf '%s: %s, allowed CPUs: %s\n' \
			"${devices[$i]}" "$cpu_scope" "${cpu_sets[$i]}" >&2
	done
	printf '%s\n' "${cpu_sets[@]}"
}

cpu_mask()
{
	local cpu="$1" word

	# Kernel CPU masks list 32-bit hexadecimal words, highest word first.
	printf '%08x' "$((1 << (cpu % 32)))"
	for ((word = cpu / 32; word > 0; word--)); do
		printf ',00000000'
	done
	printf '\n'
}

get_queue_count()
{
	ethtool -l "$1" | awk '
		/^Current hardware settings:/ { current = 1; next }
		current && $1 ~ /^(RX|TX|Combined):$/ {
			fields++
			if ($2 == "n/a")
				next
			if ($2 !~ /^[0-9]+$/) {
				invalid = 1
				next
			}
			count += $2
		}
		END {
			if (!current || fields != 3 || invalid)
				exit 1
			printf "%.0f\n", count
		}'
}

get_physical_irqs()
{
	local pci_dev="$1"

	# Each IRQ is its own affinity group.
	grep -F -- "$pci_dev" /proc/interrupts | grep -vF -- async |
		awk '$1 ~ /^[0-9]+:$/ { sub(/:$/, "", $1); print $1, $1 }'
}

get_virtio_irqs()
{
	local pci_dev="$1" queue_count="$2"

	# Return only configured input/output queues, pairing them by group name.
	grep -F -- "$pci_dev" /proc/interrupts | grep -vF -- async |
		awk -v queues="$queue_count" '
			$1 ~ /^[0-9]+:$/ {
				if ($NF !~ /^virtio[0-9]+-(input|output)\.[0-9]+$/)
					next
				queue = $NF
				sub(/^.*\./, "", queue)
				if (queue + 0 >= queues)
					next
				sub(/:$/, "", $1)
				group = $NF
				sub(/-(input|output)/, "", group)
				print $1, group
			}'
}

get_irqs()
{
	local info="$1" driver="$2" queue_count="$3" pci_dev

	pci_dev=$(awk '$1 == "bus-info:" { print $2 }' <<< "$info")
	[[ -n $pci_dev ]] || return 1
	if [[ $driver == virtio_net ]]; then
		get_virtio_irqs "$pci_dev" "$queue_count"
	else
		get_physical_irqs "$pci_dev"
	fi
}

validate_irqs()
{
	local device="$1" queue_count="$2" irq_data="$3"
	local entry irq group
	local -a irq_list
	local -A found_groups=()

	mapfile -t irq_list <<< "$irq_data"
	for entry in "${irq_list[@]}"; do
		read -r irq group <<< "$entry"
		# A virtio input/output pair counts as one queue group.
		found_groups[$group]=1
		[[ -w /proc/irq/$irq/smp_affinity ]] ||
			error "Cannot write IRQ $irq affinity for '$device'; run as root."
	done
	(( ${#found_groups[@]} >= queue_count )) ||
		error "Device '$device': $queue_count configured queues, but only ${#found_groups[@]} IRQ groups found. No affinities were changed."
}

# Write the same CPU mask to one IRQ, or to all IRQs of a virtio queue pair.
set_irq_affinity()
{
	local device="$1" cpu="$2" irq mask
	shift 2

	mask=$(cpu_mask "$cpu")
	for irq in "$@"; do
		if ! printf '%s\n' "$mask" > "/proc/irq/$irq/smp_affinity"; then
			error "Cannot set IRQ $irq affinity, earlier IRQs may already be changed."
		fi
		printf '%s: IRQ %s -> CPU %s (mask %s)\n' \
			"$device" "$irq" "$cpu" "$mask"
	done
}

set_physical_affinity()
{
	local device="$1" queue_count="$2" irq_data="$3" cpu_set="$4"
	local cpu_index irq group
	local -a cpus irq_list

	IFS=, read -r -a cpus <<< "$cpu_set"
	mapfile -t irq_list <<< "$irq_data"
	for ((cpu_index = 0; cpu_index < queue_count; cpu_index++)); do
		read -r irq group <<< "${irq_list[$cpu_index]}"
		set_irq_affinity "$device" "${cpus[$cpu_index]}" "$irq"
	done
}

set_virtio_affinity()
{
	local device="$1" queue_count="$2" irq_data="$3" cpu_set="$4"
	local entry irq group index cpu_index
	local -a cpus irq_list groups=()
	local -A group_index=()

	IFS=, read -r -a cpus <<< "$cpu_set"
	mapfile -t irq_list <<< "$irq_data"
	# Collect input/output IRQs together, preserving first-seen queue order.
	for entry in "${irq_list[@]}"; do
		read -r irq group <<< "$entry"
		index=${group_index[$group]:-}
		if [[ -z $index ]]; then
			index=${#groups[@]}
			group_index[$group]=$index
			groups+=("$irq")
		else
			groups[$index]+=" $irq"
		fi
	done
	for ((cpu_index = 0; cpu_index < queue_count; cpu_index++)); do
		read -r -a irq_list <<< "${groups[$cpu_index]}"
		set_irq_affinity "$device" "${cpus[$cpu_index]}" "${irq_list[@]}"
	done
}

if (( $# == 1 )) && [[ $1 == -h || $1 == --help ]]; then
	usage
	exit 0
fi
if (( $# < 1 )); then
	usage >&2
	exit 1
fi
set -- "${@:1:2}"
if (( $# == 2 )) && [[ $1 == "$2" ]]; then
	error "Specify two different devices."
fi
for device in "$@"; do
	[[ -n $device && $device != . && $device != .. &&
	   $device != */* && -d /sys/class/net/$device ]] ||
		error "Network device '$device' does not exist."
done

cpu_sets_data=$(get_cpu_sets "$@") || exit 1
mapfile -t cpu_sets <<< "$cpu_sets_data"

devices=("$@")
device_irqs=()
device_queue_counts=()
device_drivers=()

# Check both devices before writing anything.
for i in "${!devices[@]}"; do
	device=${devices[$i]}
	IFS=, read -r -a cpus <<< "${cpu_sets[$i]}"
	queue_count=$(get_queue_count "$device") ||
		error "Cannot determine configured queue count for '$device' using ethtool -l."
	(( queue_count <= ${#cpus[@]} )) ||
		error "Device '$device' has $queue_count configured queue groups, more than its ${#cpus[@]} allowed CPUs."
	device_queue_counts+=("$queue_count")

	info=$(ethtool -i "$device") || error "Cannot read driver information for '$device'."
	driver=$(awk '$1 == "driver:" { print $2 }' <<< "$info")
	device_drivers+=("$driver")
	irqs=$(get_irqs "$info" "$driver" "$queue_count" | sort -nu) ||
		error "Cannot discover IRQs for '$device'."
	[[ -n $irqs ]] || error "No IRQs found for '$device'."
	validate_irqs "$device" "$queue_count" "$irqs"
	device_irqs+=("$irqs")
done

for i in "${!devices[@]}"; do
	if [[ ${device_drivers[$i]} == virtio_net ]]; then
		set_virtio_affinity "${devices[$i]}" "${device_queue_counts[$i]}" \
			"${device_irqs[$i]}" "${cpu_sets[$i]}"
	else
		set_physical_affinity "${devices[$i]}" "${device_queue_counts[$i]}" \
			"${device_irqs[$i]}" "${cpu_sets[$i]}"
	fi
done
