#!/usr/bin/env bash
#
# Tempesta xFW gateway SYN-proxy lifecycle helpers, sourced by xfwctl.
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

declare -r synproxy_state_dir="/run/tempesta/xfw/synproxy"
declare -r synproxy_prepared="$synproxy_state_dir/prepared.json"
declare synproxy_lock_fd=""

synproxy_lock()
{
	local path="/run/tempesta/xfw/synproxy.lock"
	[[ ! -L /run/tempesta && ! -L /run/tempesta/xfw
	   && ! -L "$synproxy_state_dir" && ! -L "$path" ]] || return 1
	install -d -o root -g root -m 0755 /run/tempesta /run/tempesta/xfw || return 1
	install -d -o root -g root -m 0700 "$synproxy_state_dir" || return 1
	[[ ! -e "$path" || -f "$path" ]] || return 1
	(umask 077; : >> "$path") || return 1
	[[ $(stat -c %u "$path") == 0 ]] || return 1
	chmod 0600 "$path" || return 1
	exec {synproxy_lock_fd}>"$path" || return 1
	if ! flock -x -w 10 "$synproxy_lock_fd"; then
		exec {synproxy_lock_fd}>&-
		synproxy_lock_fd=""
		return 1
	fi
}

synproxy_unlock()
{
	if [[ -n "$synproxy_lock_fd" ]]; then
		exec {synproxy_lock_fd}>&-
		synproxy_lock_fd=""
	fi
}

synproxy_requirements()
{
	local command option value
	for command in nft flock modprobe jq; do
		command -v "$command" >/dev/null || {
			echo "ERROR: SYN proxy requires $command" >&2
			return 1
		}
	done
	[[ -x /usr/sbin/nft ]] || {
		echo "ERROR: SYN proxy requires /usr/sbin/nft for the manager" >&2
		return 1
	}
	if [[ -r "$kconfig_file" ]]; then
		for option in NF_CONNTRACK NF_TABLES NF_TABLES_INET NF_TABLES_IPV6 NFT_CT NFT_SYNPROXY IPV6; do
			value=$(sed -n "s/^CONFIG_${option}=//p" "$kconfig_file")
			[[ "$value" == y || "$value" == m ]] || {
				echo "ERROR: SYN proxy requires CONFIG_$option" >&2
				return 1
			}
		done
		if [[ $(sed -n 's/^CONFIG_NF_CONNTRACK=//p' "$kconfig_file") == m ]]; then
			if ! grep -q '^CONFIG_DEBUG_INFO_BTF_MODULES=y$' "$kconfig_file"; then
				echo "ERROR: modular conntrack requires module BTF for SYN proxy" >&2
				return 1
			fi
		fi
	fi
}

synproxy_owned_table()
{
	local owner="$1"
	[[ "$owner" =~ ^[0-9a-f]{16,128}$ ]] || return 1
	nft -j list table inet xfw_synproxy 2>/dev/null |
		jq -e --arg owner "xfw-synproxy:$owner" \
		'any(.nftables[]; .table.comment? == $owner)' >/dev/null
}

# Return 0 for an existing table, 1 for absence, and 2 for an inspection error.
synproxy_table_exists()
{
	local tables result
	tables=$(nft -j list tables) || return 2
	jq -e 'any(.nftables[]; .table.family? == "inet" and
		.table.name? == "xfw_synproxy")' <<< "$tables" >/dev/null
	result=$?
	[[ "$result" == 0 || "$result" == 1 ]] || return 2
	return "$result"
}

synproxy_validate_prepared()
{
	[[ -f "$synproxy_prepared" && ! -L "$synproxy_prepared"
	   && $(stat -c %u "$synproxy_prepared") == 0
	   && $(stat -c %a "$synproxy_prepared") == 600 ]] || return 1
	jq -e --arg boot "$(cat /proc/sys/kernel/random/boot_id)" \
		--argjson ns "$(stat -Lc %i /proc/self/ns/net)" '
		.version == 1 and .boot_id == $boot and .netns_inode == $ns and
		(.owner | type == "string" and test("^[0-9a-f]{16,128}$")) and
		(.active | type == "boolean") and (.old_loose == 0 or .old_loose == 1) and
		(.ifindexes | type == "array" and length > 0 and
		 all(.[]; type == "number" and . > 0 and . == floor))
	' "$synproxy_prepared" >/dev/null
}

synproxy_interfaces()
{
	local dev index roots="" links
	for dev in $devs; do
		index=$(cat "/sys/class/net/$dev/ifindex") || return 1
		[[ "$index" =~ ^[0-9]+$ ]] || return 1
		roots+="${roots:+,}$index"
	done
	[[ -n "$roots" ]] || return 1
	links=$(ip -j -d link show) || return 1
	jq -c --argjson roots "[$roots]" '
		. as $links |
		def descendants($ids):
			([$links[] | select(.linkinfo.info_kind? == "vlan") |
			  select(.link_index as $parent | $ids | index($parent)) |
			  .ifindex] + $ids | unique) as $all |
			if ($all | length) == ($ids | length) then $all
			else descendants($all) end;
		descendants($roots | unique)
	' <<< "$links"
}

synproxy_write_prepared()
{
	local owner="$1" old_loose="$2" interfaces="$3" active="$4" temporary
	temporary=$(mktemp "$synproxy_state_dir/prepared.XXXXXX") || return 1
	if ! jq -n --arg owner "$owner" --arg boot_id "$(cat /proc/sys/kernel/random/boot_id)" \
		--argjson netns_inode "$(stat -Lc %i /proc/self/ns/net)" \
		--argjson ifindexes "$interfaces" --argjson old_loose "$old_loose" \
		--argjson active "$active" \
		'{version: 1, owner: $owner, boot_id: $boot_id, netns_inode: $netns_inode,
		  ifindexes: $ifindexes, old_loose: $old_loose, active: $active}' > "$temporary"; then
		rm -f "$temporary"
		return 1
	fi
	chmod 0600 "$temporary" && mv -f "$temporary" "$synproxy_prepared"
}

synproxy_prepare()
{
	local owner="" old_loose interfaces rc=0 new_table=0 previous=0 table_status
	local previous_loose previous_interfaces previous_active
	synproxy_requirements || return 1
	modprobe nf_conntrack && modprobe nft_ct && modprobe nft_synproxy || return 1
	synproxy_lock || return 1
	if [[ -e "$synproxy_prepared" || -L "$synproxy_prepared" ]]; then
		if ! synproxy_validate_prepared; then
			synproxy_unlock
			return 1
		fi
		previous=1
		owner=$(jq -er '.owner' "$synproxy_prepared") || rc=1
		previous_loose=$(jq -er '.old_loose' "$synproxy_prepared") || rc=1
		previous_interfaces=$(jq -c '.ifindexes' "$synproxy_prepared") || rc=1
		previous_active=$(jq -r '.active' "$synproxy_prepared") || rc=1
		if [[ $rc != 0 ]]; then synproxy_unlock; return 1; fi
	fi
	synproxy_table_exists
	table_status=$?
	if [[ "$table_status" == 0 ]]; then
		if ! synproxy_owned_table "$owner"; then
			echo "ERROR: refusing to modify an unowned xfw_synproxy nft table" >&2
			synproxy_unlock
			return 1
		fi
		if ! nft list synproxy inet xfw_synproxy handoff >/dev/null 2>&1; then
			echo "ERROR: owned SYN-proxy translation anchor is missing" >&2
			synproxy_unlock
			return 1
		fi
	elif [[ "$table_status" == 1 ]]; then
		new_table=1
		if [[ -z "$owner" ]]; then
			owner=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
		fi
	else
		synproxy_unlock
		return 1
	fi
	[[ "$owner" =~ ^[0-9a-f]{16,128}$ ]] || { synproxy_unlock; return 1; }
	interfaces=$(synproxy_interfaces) || { synproxy_unlock; return 1; }
	old_loose=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_loose) || rc=1
	if [[ "$previous" == 1 && "$previous_active" == true ]]; then
		old_loose="$previous_loose"
	fi
	[[ "$old_loose" == 0 || "$old_loose" == 1 ]] || rc=1
	if [[ $rc == 0 ]]; then
		synproxy_write_prepared "$owner" "$old_loose" "$interfaces" true || rc=1
	fi
	if [[ $rc == 0 && "$new_table" == 1 ]]; then
		nft -f - <<EOF
create table inet xfw_synproxy { comment "xfw-synproxy:$owner"; }
add synproxy inet xfw_synproxy handoff { mss 536; wscale 7; timestamp sack-perm; }
EOF
		rc=$?
	fi
	if [[ $rc == 0 ]]; then
		sysctl -q -w net.netfilter.nf_conntrack_tcp_loose=0 || rc=1
	fi
	if [[ $rc != 0 && -e "$synproxy_prepared" ]]; then
		if [[ "$previous_active" != true && "$old_loose" == 1
		   && $(cat /proc/sys/net/netfilter/nf_conntrack_tcp_loose) == 0 ]]; then
			if ! sysctl -q -w net.netfilter.nf_conntrack_tcp_loose=1; then
				echo "ERROR: SYN-proxy preparation rollback requires recovery" >&2
				synproxy_unlock
				return 1
			fi
		fi
		if [[ "$previous" == 1 ]]; then
			synproxy_write_prepared "$owner" "$previous_loose" \
				"$previous_interfaces" "$previous_active" || true
		else
			synproxy_write_prepared "$owner" "$old_loose" "$interfaces" false || true
		fi
	fi
	synproxy_unlock
	return "$rc"
}

# Called after datapath detachment with the lifecycle lock held.
synproxy_release()
{
	local owner old_loose interfaces name batch="" rc=0 table_status table
	[[ -e "$synproxy_prepared" || -L "$synproxy_prepared" ]] || return 0
	synproxy_validate_prepared || return 1
	owner=$(jq -er '.owner' "$synproxy_prepared") || return 1
	synproxy_table_exists
	table_status=$?
	if [[ "$table_status" == 0 ]]; then
		synproxy_owned_table "$owner" || return 1
		table=$(nft -j list table inet xfw_synproxy) || return 1
		jq -e '.nftables | type == "array"' <<< "$table" >/dev/null || return 1
		for name in scope4 scope6 ports4 ports6 ingress; do
			if jq -e --arg name "$name" 'any(.nftables[]; .set.name? == $name)' \
				<<< "$table" >/dev/null; then
				batch+="flush set inet xfw_synproxy $name"$'\n'
			fi
		done
	elif [[ "$table_status" != 1 ]]; then
		return 1
	fi
	if [[ -n "$batch" ]]; then nft -f - <<< "$batch" || return 1; fi
	old_loose=$(jq -er '.old_loose' "$synproxy_prepared") || return 1
	interfaces=$(jq -c '.ifindexes' "$synproxy_prepared") || return 1
	[[ "$old_loose" == 0 || "$old_loose" == 1 ]] || return 1
	if jq -e '.active == true' "$synproxy_prepared" >/dev/null \
	   && [[ $(cat /proc/sys/net/netfilter/nf_conntrack_tcp_loose) == 0 ]]; then
		sysctl -q -w "net.netfilter.nf_conntrack_tcp_loose=$old_loose" || rc=1
	fi
	if [[ $rc == 0 ]]; then
		rm -f "$synproxy_state_dir/state.json" "$synproxy_state_dir/pending.json" \
			"$synproxy_state_dir/state.json.tmp" "$synproxy_state_dir/pending.json.tmp" || rc=1
		synproxy_write_prepared "$owner" "$old_loose" "$interfaces" false || rc=1
	fi
	# Keep the owned table and dormant object: live flows need its core hooks.
	return "$rc"
}

synproxy_status()
{
	[[ -e "$synproxy_prepared" ]] || return 0
	if jq -e '.active == true' "$synproxy_prepared" >/dev/null; then
		echo -e "SYN proxy:\t\t\tprepared (runtime rules select protection)"
	else
		echo -e "SYN proxy:\t\t\tdisabled; translation hooks retained"
	fi
}
