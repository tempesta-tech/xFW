#include <benchmark/benchmark.h>
#include <random>
#include <cstdint>
#include <climits>

using namespace std;

extern "C" {
#include "jhash.h"
#include <linux/limits.h>
}

#define OBJ_COUNT_MAX 100000

struct XfwIpv4SynTuple {
	uint32_t	src_ip;
	uint32_t	dst_ip;
	uint32_t	seq;
	uint16_t	sport;
	uint16_t	dport;
};

struct XfwIpv6SynTuple {
	uint8_t		src_ip[16];
	uint8_t		dst_ip[16];
	uint32_t	seq;
	uint16_t	sport;
	uint16_t	dport;
};

static XfwIpv4SynTuple syn_jhash_ip4[OBJ_COUNT_MAX];
static XfwIpv6SynTuple syn_jhash_ip6[OBJ_COUNT_MAX];

static void
BM_syn_jhash_ip4(benchmark::State& state)
{
	unsigned int idx = 0;
	random_device rd;
	mt19937 gen(rd());
	uniform_int_distribution<uint32_t> distrib_ip(1, UINT_MAX);
	uniform_int_distribution<uint32_t> distrib_port(1, 65535);
	uniform_int_distribution<uint32_t> distrib(1, UINT_MAX);
	uint64_t val = distrib(gen);

	static_assert(sizeof(XfwIpv4SynTuple) == 16);

	for (unsigned int i = 0; i < OBJ_COUNT_MAX; i++) {
		syn_jhash_ip4[i].src_ip = distrib_ip(gen);
		syn_jhash_ip4[i].dst_ip = distrib_ip(gen);
		syn_jhash_ip4[i].seq = distrib(gen);
		syn_jhash_ip4[i].sport = distrib_port(gen);
		syn_jhash_ip4[i].dport = distrib_port(gen);
	}

	for (auto _ : state) {
		idx++;
		idx %= OBJ_COUNT_MAX;
		uint64_t hash = jhash(&syn_jhash_ip4[idx],
				      sizeof(XfwIpv4SynTuple), val);
		benchmark::DoNotOptimize(hash);
	}
}
BENCHMARK(BM_syn_jhash_ip4);

static void
BM_syn_jhash_ip6(benchmark::State& state)
{
	unsigned int idx = 0;
	random_device rd;
	mt19937 gen(rd());
	uniform_int_distribution<uint8_t> distrib_ip(1, UINT8_MAX);
	uniform_int_distribution<uint32_t> distrib_port(1, 65535);
	uniform_int_distribution<uint32_t> distrib(1, UINT_MAX);
	uint64_t val = distrib(gen);

	static_assert(sizeof(XfwIpv6SynTuple) == 40);

	for (unsigned int i = 0; i < OBJ_COUNT_MAX; i++) {
		for (int j = 0; j < 16; j++) {
			syn_jhash_ip6[i].src_ip[j] = distrib_ip(gen);
			syn_jhash_ip6[i].dst_ip[j] = distrib_ip(gen);
		}
		syn_jhash_ip6[i].seq = distrib(gen);
		syn_jhash_ip6[i].sport = distrib_port(gen);
		syn_jhash_ip6[i].dport = distrib_port(gen);
	}

	for (auto _ : state) {
		idx++;
		idx %= OBJ_COUNT_MAX;
		uint64_t hash = jhash(&syn_jhash_ip6[idx],
				      sizeof(XfwIpv6SynTuple), val);
		benchmark::DoNotOptimize(hash);
	}
}
BENCHMARK(BM_syn_jhash_ip6);

BENCHMARK_MAIN();
