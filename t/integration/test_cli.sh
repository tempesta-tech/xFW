#!/bin/bash
#
#	Tempesta CLI test
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

test_path=$(dirname ${0})
bin_path="$test_path/../BUILD/bin"
cli="$bin_path/tfw"

# Debugging options
args=-d

# Run CLI with a full configuration file
$cli $args -c $test_path/cli_test.conf

# Run CLI with a command line TL program
$cli $args --tl "\
	ip6.dst == 2001:0db8:85a3:0000:0000:8a2e:0370:7334 && tcp.dst == 80 -> http_chain;\
	req.user_agent =~ /firefox/i && client.addr == 1.1.1.1 -> block"
