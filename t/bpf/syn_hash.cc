#include <gtest/gtest.h>
#include <xxhash.h>

extern "C" {
#include "../../bpf/syn_hash.h"
}

TEST(Xxh64SynHash, IPv4GoldenVector)
{
	XfwIpv4SynTuple tuple = {
		.src_ip = 0x01020304,
		.dst_ip = 0x05060708,
		.seq = 0x11223344,
		.sport = 12345,
		.dport = 443,
	};
	auto hash = syn_xxh64_ipv4(&tuple, 0);
	auto ref_hash = XXH64(&tuple, sizeof(tuple), 0);

	ASSERT_EQ(hash, ref_hash);
}

TEST(Xxh64SynHash, IPv6GoldenVector)
{
	XfwIpv6SynTuple tuple = {
		.src_ip = {
			0x20, 0x01, 0x0d, 0xb8,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 1
		},
		.dst_ip = {
			0x20, 0x01, 0x0d, 0xb8,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 2
		},
		.seq = 0x11223344,
		.sport = 12345,
		.dport = 443,
	};
	auto hash = syn_xxh64_ipv6(&tuple, 0);
	auto ref_hash = XXH64(&tuple, sizeof(tuple), 0);

	ASSERT_EQ(hash, ref_hash);
}
