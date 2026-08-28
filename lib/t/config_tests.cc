/**
 *	Tempesta Client library private definitions
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <cstring>
#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>

#include "../../lib/cli/config_defaults.hh"
#include "../../lib/proto/bitset_helper.hh"
#include "../../lib/proto/serialize.hh"
#include "../../lib/cli/tcl_private.hh"

const std::string max_tfw = "tfw {srv_group static{ {server 192.168.1.1}}}";
const std::string max_tfw_out = "tfw{srv_group static{ {server 192.168.1.1}}}";

const std::string max_tl = "tl {\nsome\nprogram\nhere\n}";
const std::string max_xfw = "xfw {"
	"tcp_syncookies passive_timer=1 flood_timer=5;"
	"tcp_syn_drop hash_salt=12345 time_min=500 max_delay=3000 retry_count=3 block_timeout=0;"
	"tcp_anomaly_filter; tcp_auth_filter/del;"
	"ratelimit=my_ratelimit pps=300 bps=1024;"
	"icmp ip6 : ratelimit=my_ratelimit { 13, 30 }"
	"dst=dst_name ip4.tcp: ratelimit=my_ratelimit {\n255.255.255.255:64,\n127.0.0.1/2\n}"
	"src=my_add/add ip4.tcp {127.0.0.1}"
	"src=my_del/del ip4.tcp {127.0.0.2}"
	"src=my_replace/replace ip4.tcp {127.0.0.3}"
	"src=ports_0 ip4.tcp {:443, :50-52}"
	"src=ports_1 ip4.tcp { :5000-5002 :4000-4005}"
	"src=ports_2 ip4.tcp { :6000 - 6002 :7000-7005}"
	"dns_filter;"
"}";

const size_t XFW_OPT_BYTES =
	((TempestaRPC::XFWOpt_MAX - TempestaRPC::XFWOpt_MIN + 1) + 7) / 8;

bool equal(const char* a, const char* b, std::size_t len)
{
	return std::memcmp(a, b, len) == 0;
}

/**
 * You can call program with "-v" or "--verbose" to get all debug output.
 */
int main(int argc, char **argv)
{
	for (int i = 1; i < argc; ++i) {
		if (std::string(argv[i]) == "--verbose"
		    || std::string(argv[i]) == "-v") {
			tcl_debug(true);
		}
	}

	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

//Empty line as an input -> Ok.
TEST(ParsesFullConfig, AcceptEmptyConfig)
{
	std::string prog;
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_EQ(conf->tfw_conf_len, 0);
	ASSERT_EQ(conf->tl_prog_txt_len, 0);
	ASSERT_TRUE(conf->prvt);
	ASSERT_EQ(conf->prvt->tl_prog.size(), 0);
	ASSERT_TRUE(!conf->prvt->xfw_conf.has_value());
}

//Correct configuration as an input -> Ok.
TEST(ParsesFullConfig, HandlesMaximumData)
{
	const std::string prog = max_tl + max_tfw + max_xfw;

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_EQ(conf->tfw_conf_len, max_tfw_out.size());
	ASSERT_TRUE(equal(max_tfw_out.c_str(), conf->tfw_conf, conf->tfw_conf_len));
	ASSERT_EQ(conf->tl_prog_txt_len, max_tl.size());
	ASSERT_TRUE(equal(max_tl.c_str(), conf->tl_prog_txt, conf->tl_prog_txt_len));

	ASSERT_TRUE(conf->prvt);
	//TODO: has to be filled with compiled TL
	ASSERT_EQ(conf->prvt->tl_prog.size(), 0);

	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf.value().syncookie_.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf.value().syncookie_.value().flood_timer_sec_, 5);
	ASSERT_EQ(conf->prvt->xfw_conf.value().syncookie_.value().passive_timer_sec_, 1);

	auto &tcp_syn_drop = conf->prvt->xfw_conf.value().tcp_syn_drop_;
	ASSERT_TRUE(tcp_syn_drop.has_value());
	ASSERT_EQ(tcp_syn_drop->hash_salt_, 12345);
	ASSERT_EQ(tcp_syn_drop->time_min_ms_, 500);
	ASSERT_EQ(tcp_syn_drop->max_delay_ms_, 3000);
	ASSERT_EQ(tcp_syn_drop->retry_count_, 3);
	ASSERT_EQ(tcp_syn_drop->block_timeout_ms_, 0);

	auto &cflags = conf->prvt->xfw_conf.value().flags_;
	ASSERT_FALSE(cflags.test(XfwConf::Opt::TCP_AUTH_FILTER_ON));
	ASSERT_TRUE(cflags.test(XfwConf::Opt::TCP_AUTH_FILTER_OFF));
	ASSERT_FALSE(cflags.test(XfwConf::Opt::TCP_ANOMALY_FILTER_OFF));

	ASSERT_EQ(conf->prvt->xfw_conf.value().net_rules_.size(), 7);
	auto &rule = conf->prvt->xfw_conf.value().net_rules_[0];
	ASSERT_EQ(rule.alias_, "dst_name");
	ASSERT_EQ(rule.ratelimit_, "my_ratelimit");
	ASSERT_EQ(rule.net6s_.size(), 0);
	ASSERT_EQ(rule.net4s_.size(), 2);
	ASSERT_EQ(rule.net4s_[0].port_, 64);
	ASSERT_EQ(rule.net4s_[0].prefix_, 32);
	ASSERT_EQ(rule.net4s_[0].addr_[0], 0xff);
	ASSERT_EQ(rule.net4s_[0].addr_[1], 0xff);
	ASSERT_EQ(rule.net4s_[0].addr_[2], 0xff);
	ASSERT_EQ(rule.net4s_[0].addr_[3], 0xff);
	ASSERT_EQ(rule.net4s_[1].port_, 0);
	ASSERT_EQ(rule.net4s_[1].prefix_, 2);
	ASSERT_EQ(rule.net4s_[1].addr_[0], 0x7F);
	ASSERT_EQ(rule.net4s_[1].addr_[1], 0x00);
	ASSERT_EQ(rule.net4s_[1].addr_[2], 0x00);
	ASSERT_EQ(rule.net4s_[1].addr_[3], 0x01);

	ASSERT_EQ(rule.nets_.size(), 0);

	auto &rflags = rule.flags_;
	ASSERT_FALSE(rflags.test(NetRule::Attr::IPV6));
	ASSERT_TRUE(rflags.test(NetRule::Attr::TCP));
	ASSERT_FALSE(rflags.test(NetRule::Attr::SRC));
	ASSERT_TRUE(rflags.test(NetRule::Attr::ALLOW));

	ASSERT_EQ(conf->prvt->xfw_conf.value().icmp_rules_.size(), 1);
	const auto &icmp = conf->prvt->xfw_conf.value().icmp_rules_[0];
	ASSERT_EQ(icmp.ratelimit_, "my_ratelimit");
	ASSERT_EQ(icmp.alias_, "ip6");
	ASSERT_EQ(icmp.types_.size(), 2);
	ASSERT_EQ(icmp.types_[0], 13);
	ASSERT_EQ(icmp.types_[1], 30);
	auto &iflags = icmp.flags_;
	ASSERT_TRUE(iflags.test(IcmpRule::Attr::IPV6));
	ASSERT_TRUE(iflags.test(IcmpRule::Attr::ALLOW));
	ASSERT_TRUE(iflags.test(IcmpRule::Attr::REPLACE));
}

//Correct configuration as an input -> Ok.
TEST(ParsesXfwConfig, HandlesIpAsIsoCodeInSrc)
{
	const std::string prog = "xfw {"
		"src ip4.udp {uk}"
	"}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);

	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_FALSE(conf->prvt->xfw_conf.value().syncookie_.has_value());

	auto &cflags = conf->prvt->xfw_conf.value().flags_;
	ASSERT_FALSE(cflags.test(XfwConf::Opt::TCP_AUTH_FILTER_ON));

	ASSERT_EQ(conf->prvt->xfw_conf.value().net_rules_.size(), 1);
	auto &rule = conf->prvt->xfw_conf.value().net_rules_[0];
	ASSERT_EQ(rule.ratelimit_, "");
	ASSERT_EQ(rule.net6s_.size(), 0);
	ASSERT_EQ(rule.net4s_.size(), 0);
	ASSERT_EQ(rule.nets_.size(), 1);
	ASSERT_TRUE(equal("uk", rule.nets_[0].code_str_, 2));
	ASSERT_EQ(rule.nets_[0].port_, 0);

	auto &rflags = rule.flags_;
	ASSERT_FALSE(rflags.test(NetRule::Attr::IPV6));
	ASSERT_FALSE(rflags.test(NetRule::Attr::TCP));
	ASSERT_TRUE(rflags.test(NetRule::Attr::SRC));
}

//Unknown section "tfwa" in the Root -> Fail.
TEST(RejectsXfwConfig, WithUnknownRootSection)
{
	std::string prog = "tfwa { srv_group static { server 192.168.1.1:8080}}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Two "tfw" sectons in the Root -> Fail.
TEST(RejectsXfwConfig, TwoXfwSection)
{
	std::string prog = max_tfw + max_tfw;
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Unknown required protocol type -> Fail.
TEST(RejectsXfwConfig, MissingProtocolInSrc)
{
	std::string prog = "xfw{src{127.0.0.1}}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Unknown attribute in section src, typo -> Fail.
TEST(RejectsXfwConfig, WithUnknownAttribute)
{
	std::string prog = "xfw{src tcp.ip4{127.0.0.1}}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

class RejectsXfwConfigWithPortWithTwoDashes
	: public ::testing::TestWithParam<std::string>
{
};

TEST_P(RejectsXfwConfigWithPortWithTwoDashes, InvalidPortRange)
{
	using namespace std::literals;

	const std::string& ports = GetParam();
	std::string prog = "xfw{dst tcp.ip4 : block {"s + ports + "}}";

	std::unique_ptr<TlProgConf> conf(
		tcl_parse_full_conf(prog.c_str(), prog.length())
	);

	ASSERT_TRUE(!conf);
}


INSTANTIATE_TEST_SUITE_P(
	AllSpacingVariants,
	RejectsXfwConfigWithPortWithTwoDashes,
	::testing::Values(
		":2000-2003-2005",
		":2000 -2003-2005",
		":2000- 2003-2005",
		":2000 - 2003-2005",
		":2000-2003 -2005",
		":2000 -2003 -2005",
		":2000- 2003 -2005",
		":2000 - 2003 -2005",

		":2000-2003- 2005",
		":2000 -2003- 2005",
		":2000- 2003- 2005",
		":2000 - 2003- 2005",
		":2000-2003 - 2005",
		":2000 -2003 - 2005",
		":2000- 2003 - 2005",
		":2000 - 2003 - 2005"
	)
);

//Mask and port in one rule -> Fail.
TEST(RejectsXfwConfig, WithMaskAndPort)
{
	std::string prog = "xfw{dst tcp.ip4 : block {127.0.0.1/30:2000}}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Null port at ip address -> Fail.
TEST(RejectsXfwConfig, NullPortIsInvalidInDst)
{
	std::string prog = "xfw{dst ip4.tcp {127.0.0.1:0}}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

// IPv6 mask inside brackets -> Fail.
TEST(RejectsXfwConfig, IPv6MaskInsideBracketsInSrc)
{
	std::string prog = "xfw { src ip6.tcp { [2001:0db8:85a3:0000:0000:8a2e:0370:7334/60]:80 } }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

// IPv6 mask outside brackets -> Fail.
TEST(RejectsXfwConfig, IPv6MaskOutsideBracketsInSrc)
{
	std::string prog = "xfw { src ip6.tcp { [2001:0db8:85a3:0000:0000:8a2e:0370:7334]/60 } }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

// IPv6 mask outside brackets -> Fail.
TEST(RejectsXfwConfig, IPv6MaskAndPortOutsideBracketsInSrc)
{
	std::string prog = "xfw { src ip6.tcp { [2001:0db8:85a3:0000:0000:8a2e:0370:7334]/60:80 } }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

// IPv6 mask after port with address inside brackets -> Fail.
TEST(RejectsXfwConfig, IPv6MaskAfterPortInSrc)
{
	std::string prog = "xfw { src ip6.tcp { [2001:0db8:85a3:0000:0000:8a2e:0370:7334]:80/60 } }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

// IPv6 with one more word -> Fail.
TEST(RejectsXfwConfig, IPv6TooManyWordsInSrc)
{
	std::string prog = "xfw { src ip6.tcp { 2001:0db8:85a3:0000:0000:8a2e:0370:7334:80 } }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

// Two src sections with the same alias -> Fail.
TEST(RejectsXfwConfig, DuplicateAliasInSrc)
{
	std::string prog = "xfw{ "
				"src=my_list ip4.tcp { 127.0.0.1} "
				"src=my_list ip4.tcp { 127.10.0.1} }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

TEST(RejectsIcmpRule, BadIcmpType)
{
	const std::string prog = "xfw {icmp ip6 : allow { -13, 30 }}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

TEST(ParsesIcmpRule, EmptyIcmpTypes)
{
	const std::string prog = "xfw {icmp ip6: allow {}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
}

TEST(ParsesXfwConfig, WithDeleteTcpSyncookies)
{
	const std::string prog = "xfw{tcp_syncookies/del;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::TCP_SYNCOOKIE_FILTER_OFF));
	ASSERT_FALSE(conf->prvt->xfw_conf->syncookie_.has_value());
}

TEST(ParsesXfwConfig, TcpSyncookiesDefaultValues)
{
	std::string prog = "xfw {"
		"tcp_syncookies passive_timer=3;"
	"}";

	std::unique_ptr<TlProgConf> conf1(tcl_parse_full_conf(prog.c_str(),
							     prog.length()));

	ASSERT_TRUE(conf1);
	ASSERT_TRUE(conf1->prvt);
	ASSERT_TRUE(conf1->prvt->xfw_conf.has_value());

	auto &syncookie = conf1->prvt->xfw_conf->syncookie_;

	ASSERT_TRUE(syncookie.has_value());
	ASSERT_EQ(syncookie->passive_timer_sec_, 3);
	ASSERT_EQ(syncookie->flood_timer_sec_, DEFAULT_FLOOD_TIMER_SEC);

	prog = "xfw {"
		"tcp_syncookies flood_timer=3;"
	"}";

	std::unique_ptr<TlProgConf> conf2(tcl_parse_full_conf(prog.c_str(),
							      prog.length()));
	ASSERT_TRUE(conf2);
	ASSERT_TRUE(conf2->prvt);
	ASSERT_TRUE(conf2->prvt->xfw_conf.has_value());

	syncookie = conf2->prvt->xfw_conf->syncookie_;

	ASSERT_TRUE(syncookie.has_value());
	ASSERT_EQ(syncookie->passive_timer_sec_, DEFAULT_PASSIVE_TIMER_SEC);
	ASSERT_EQ(syncookie->flood_timer_sec_, 3);
}

TEST(ParsesXfwConfig, WithDeleteTcpSynDrop)
{
	const std::string prog = "xfw{tcp_syn_drop/del;}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::TCP_SYN_DROP_FILTER_OFF));
	ASSERT_FALSE(conf->prvt->xfw_conf->tcp_syn_drop_.has_value());
}

TEST(ParsesXfwConfig, TcpSynDropUsesDefaultValues)
{
	const std::string prog = "xfw {"
		"tcp_syn_drop hash_salt=12345 retry_count=3;"
	"}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));

	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());

	const auto &tcp_syn_drop =
		conf->prvt->xfw_conf->tcp_syn_drop_;

	ASSERT_TRUE(tcp_syn_drop.has_value());
	EXPECT_EQ(tcp_syn_drop->hash_salt_, 12345);
	EXPECT_EQ(tcp_syn_drop->time_min_ms_, TCP_SYN_DROP_DEFAULT_MIN_DELAY_MS);
	EXPECT_EQ(tcp_syn_drop->max_delay_ms_, TCP_SYN_DROP_DEFAULT_MAX_DELAY_MS);
	EXPECT_EQ(tcp_syn_drop->retry_count_, 3);

	/*
	 * Zero means unlimited blocking until the corresponding
	 * LRU map entry is evicted.
	 */
	EXPECT_EQ(tcp_syn_drop->block_timeout_ms_,
		  TCP_SYN_DROP_DEFAULT_BLOCK_TIMEOUT_MS);
}

TEST(ParsesXfwConfig, TcpSynDropAcceptsEqualWindowBounds)
{
	const std::string prog = "xfw {"
		"tcp_syn_drop hash_salt=1 time_min=500 max_delay=500 retry_count=1;"
	"}";

	std::unique_ptr<TlProgConf> conf(
		tcl_parse_full_conf(prog.c_str(), prog.length())
	);

	ASSERT_TRUE(conf);

	const auto &tcp_syn_drop =
		conf->prvt->xfw_conf->tcp_syn_drop_;

	ASSERT_TRUE(tcp_syn_drop.has_value());
	EXPECT_EQ(tcp_syn_drop->time_min_ms_, 500);
	EXPECT_EQ(tcp_syn_drop->max_delay_ms_, 500);
}

class RejectsInvalidTcpSynDrop
	: public ::testing::TestWithParam<std::string>
{
};

TEST_P(RejectsInvalidTcpSynDrop, InvalidConfiguration)
{
	const std::string prog = "xfw { tcp_syn_drop " + GetParam() + "; }";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));

	ASSERT_FALSE(conf);
}

INSTANTIATE_TEST_SUITE_P(
	InvalidValues,
	RejectsInvalidTcpSynDrop,
	::testing::Values(
		/*
		 * hash_salt and retry_count do not have defaults and
		 * therefore must be specified explicitly.
		 */
		"retry_count=3",
		"hash_salt=12345",
		/*
		 * retry_count defines how many retransmitted SYNs may
		 * pass before the tuple is blocked.
		 */
		"hash_salt=12345 retry_count=0",
		/*
		 * The valid retransmission window is:
		 *
		 * stored_time + time_min <= now
		 *     <= stored_time + max_delay
		 *
		 * Therefore, time_min must not exceed max_delay.
		 */
		"hash_salt=12345 time_min=3001 "
			"max_delay=3000 retry_count=3",
		/* Unknown attributes must be rejected. */
		"hash_salt=12345 retry_count=3 unknown=1",
		/* Invalid edit operations must be rejected. */
		"/add hash_salt=12345 retry_count=3",
		"/replace hash_salt=12345 retry_count=3",
		/* `max_delay` can't be equal to zero. */
		"hash_salt=12345 retry_count=3 time_min=0 max_delay=0"
	)
);

TEST(ParsesXfwConfig, WithEvaluationModeOn)
{
	const std::string prog = "xfw{evaluation_mode;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::EVALUATION_MODE_ON));
}

TEST(ParsesXfwConfig, WithEvaluationModeOff)
{
	const std::string prog = "xfw{evaluation_mode/del;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::EVALUATION_MODE_OFF));
	ASSERT_FALSE(conf->prvt->xfw_conf->syncookie_.has_value());
}

//Serialize full config and check data after deserialization
TEST(SerializesConfig, WithMaximumData)
{
	using namespace TempestaRPC;
	const std::string prog = max_tl + max_tfw + max_xfw;

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);

	flatbuffers::grpc::Message<TempestaRPC::Request> request =
		build_set_config_request(*conf);

	//deserialize
	auto req = request.GetRoot();
	ASSERT_TRUE(req);
	ASSERT_EQ(req->proto_ver(), ProtoVersion);
	ASSERT_EQ(req->records()->size(), 3);

	ASSERT_EQ(req->records()->Get(0)->type(), ReqRecType_RRT_TL_OBJ);
	auto tl_prog = req->records()->Get(0)->data_as_tl_prog();
	ASSERT_TRUE(tl_prog);
	ASSERT_EQ(tl_prog->text()->size(), max_tl.size());
	ASSERT_EQ(max_tl.size(), tl_prog->text()->size());
	ASSERT_TRUE(std::equal(max_tl.begin(), max_tl.end(), tl_prog->text()->begin()));

	ASSERT_EQ(req->records()->Get(1)->type(), ReqRecType_RRT_TFW_CFG);
	auto tfw_cfg = req->records()->Get(1)->data_as_tfw_cfg();
	ASSERT_TRUE(tfw_cfg);
	ASSERT_EQ(tfw_cfg->text()->size(), max_tfw_out.size());
	ASSERT_EQ(max_tfw_out.size(), tfw_cfg->text()->size());
	ASSERT_TRUE(std::equal(max_tfw_out.begin(),
			       max_tfw_out.end(),
			       tfw_cfg->text()->begin()));

	ASSERT_EQ(req->records()->Get(2)->type(), ReqRecType_RRT_XFW_CFG);
	auto xfw_cfg = req->records()->Get(2)->data_as_xfw_cfg();
	ASSERT_TRUE(xfw_cfg);
	ASSERT_TRUE(xfw_cfg->syncookie());
	ASSERT_EQ(xfw_cfg->syncookie()->passive_timer(), 1);
	ASSERT_EQ(xfw_cfg->syncookie()->flood_timer(), 5);
	ASSERT_TRUE(xfw_cfg->tcp_syn_drop());
	ASSERT_EQ(xfw_cfg->tcp_syn_drop()->hash_salt(), 12345);
	ASSERT_EQ(xfw_cfg->tcp_syn_drop()->time_min(), 500);
	ASSERT_EQ(xfw_cfg->tcp_syn_drop()->max_delay(), 3000);
	ASSERT_EQ(xfw_cfg->tcp_syn_drop()->retry_count(), 3);
	ASSERT_EQ(xfw_cfg->tcp_syn_drop()->block_timeout(), 0);
	ASSERT_EQ(xfw_cfg->net_rules()->size(), 7);
	
	ASSERT_TRUE(xfw_cfg->flags());
	ASSERT_EQ(xfw_cfg->flags()->size(), XFW_OPT_BYTES);

	BitSet<XFWOpt, XFWOpt::XFWOpt_MAX> cflags;
	ASSERT_TRUE(bitset_deserialize(*xfw_cfg->flags(), cflags));

	ASSERT_FALSE(cflags.test(XFWOpt::XFWOpt_TCP_AUTH_FILTER_ON));
	ASSERT_TRUE(cflags.test(XFWOpt::XFWOpt_TCP_AUTH_FILTER_OFF));
	ASSERT_FALSE(cflags.test(XFWOpt::XFWOpt_TCP_SYNCOOKIE_FILTER_OFF));
	ASSERT_FALSE(cflags.test(XFWOpt::XFWOpt_TCP_SYN_DROP_FILTER_OFF));
	ASSERT_FALSE(cflags.test(XFWOpt::XFWOpt_TCP_ANOMALY_FILTER_OFF));
	ASSERT_TRUE(cflags.test(XFWOpt::XFWOpt_DNS_FILTER_ON));
	ASSERT_FALSE(cflags.test(XFWOpt::XFWOpt_DNS_FILTER_OFF));

	auto rule = xfw_cfg->net_rules()->Get(0);

	ASSERT_TRUE(!!rule->alias());
	ASSERT_EQ(rule->alias()->str(), "dst_name");
	ASSERT_TRUE(!!rule->ratelimit());
	ASSERT_EQ(rule->ratelimit()->str(), "my_ratelimit");
	ASSERT_TRUE(!rule->net6s());
	ASSERT_TRUE(rule->net4s());
	ASSERT_EQ(rule->net4s()->size(), 2);
	ASSERT_EQ(rule->net4s()->Get(0)->port(), 64);
	ASSERT_EQ(rule->net4s()->Get(0)->prefix(), 32);
	ASSERT_EQ(rule->net4s()->Get(0)->addr()->Get(0), 0xff);
	ASSERT_EQ(rule->net4s()->Get(0)->addr()->Get(1), 0xff);
	ASSERT_EQ(rule->net4s()->Get(0)->addr()->Get(2), 0xff);
	ASSERT_EQ(rule->net4s()->Get(0)->addr()->Get(3), 0xff);
	ASSERT_EQ(rule->net4s()->Get(1)->port(), 0);
	ASSERT_EQ(rule->net4s()->Get(1)->prefix(), 2);
	ASSERT_EQ(rule->net4s()->Get(1)->addr()->Get(0), 0x7F);
	ASSERT_EQ(rule->net4s()->Get(1)->addr()->Get(1), 0x00);
	ASSERT_EQ(rule->net4s()->Get(1)->addr()->Get(2), 0x00);
	ASSERT_EQ(rule->net4s()->Get(1)->addr()->Get(3), 0x01);

	ASSERT_TRUE(!rule->nets());
	ASSERT_TRUE(!rule->ports());

	auto rule_ports_0 = xfw_cfg->net_rules()->Get(4);
	ASSERT_TRUE(!!rule_ports_0->alias());
	ASSERT_EQ(rule_ports_0->alias()->str(), "ports_0");
	ASSERT_TRUE(rule_ports_0->ports());
	ASSERT_EQ(rule_ports_0->ports()->size(), 2);
	ASSERT_EQ(rule_ports_0->ports()->Get(0)->port(), 443);
	ASSERT_EQ(rule_ports_0->ports()->Get(0)->port_end(), 0);
	ASSERT_EQ(rule_ports_0->ports()->Get(1)->port(), 50);
	ASSERT_EQ(rule_ports_0->ports()->Get(1)->port_end(), 52);

	auto rule_ports_1 = xfw_cfg->net_rules()->Get(5);
	ASSERT_TRUE(!!rule_ports_1->alias());
	ASSERT_EQ(rule_ports_1->alias()->str(), "ports_1");
	ASSERT_TRUE(rule_ports_1->ports());
	ASSERT_EQ(rule_ports_1->ports()->size(), 2);
	ASSERT_EQ(rule_ports_1->ports()->Get(0)->port(), 5000);
	ASSERT_EQ(rule_ports_1->ports()->Get(0)->port_end(), 5002);
	ASSERT_EQ(rule_ports_1->ports()->Get(1)->port(), 4000);
	ASSERT_EQ(rule_ports_1->ports()->Get(1)->port_end(), 4005);

	auto rule_ports_2 = xfw_cfg->net_rules()->Get(6);
	ASSERT_TRUE(!!rule_ports_2->alias());
	ASSERT_EQ(rule_ports_2->alias()->str(), "ports_2");
	ASSERT_TRUE(rule_ports_2->ports());
	ASSERT_TRUE(rule_ports_2->ports()->size() == 2);
	ASSERT_EQ(rule_ports_2->ports()->Get(0)->port(), 6000);
	ASSERT_EQ(rule_ports_2->ports()->Get(0)->port_end(), 6002);
	ASSERT_EQ(rule_ports_2->ports()->Get(1)->port(), 7000);
	ASSERT_EQ(rule_ports_2->ports()->Get(1)->port_end(), 7005);

	ASSERT_TRUE(!!rule->flags());
	BitSet<NetRuleOpt, NetRuleOpt::NetRuleOpt_MAX> rflags;
	ASSERT_TRUE(bitset_deserialize(*rule->flags(), rflags));
	ASSERT_FALSE(rflags.test(NetRuleOpt::NetRuleOpt_IPV6));
	ASSERT_TRUE(rflags.test(NetRuleOpt::NetRuleOpt_TCP));
	ASSERT_FALSE(rflags.test(NetRuleOpt::NetRuleOpt_SRC));

	//we want only check add/delete/replace flags
	auto add_rule = xfw_cfg->net_rules()->Get(1);
	ASSERT_TRUE(!!add_rule);
	ASSERT_TRUE(!!add_rule->flags());
	BitSet<NetRuleOpt, NetRuleOpt::NetRuleOpt_MAX> add_flags;
	ASSERT_TRUE(bitset_deserialize(*add_rule->flags(), add_flags));
	ASSERT_FALSE(add_flags.test(NetRuleOpt::NetRuleOpt_REPLACE));
	ASSERT_FALSE(add_flags.test(NetRuleOpt::NetRuleOpt_DELETE));

	auto del_rule = xfw_cfg->net_rules()->Get(2);
	ASSERT_TRUE(!!del_rule);
	ASSERT_TRUE(!!del_rule->flags());
	BitSet<NetRuleOpt, NetRuleOpt::NetRuleOpt_MAX> del_flags;
	ASSERT_TRUE(bitset_deserialize(*del_rule->flags(), del_flags));
	ASSERT_FALSE(del_flags.test(NetRuleOpt::NetRuleOpt_REPLACE));
	ASSERT_TRUE(del_flags.test(NetRuleOpt::NetRuleOpt_DELETE));

	auto repl_rule = xfw_cfg->net_rules()->Get(3);
	ASSERT_TRUE(!!repl_rule);
	ASSERT_TRUE(!!repl_rule->flags());
	BitSet<NetRuleOpt, NetRuleOpt::NetRuleOpt_MAX> repl_flags;
	ASSERT_TRUE(bitset_deserialize(*repl_rule->flags(), repl_flags));
	ASSERT_TRUE(repl_flags.test(NetRuleOpt::NetRuleOpt_REPLACE));
	ASSERT_FALSE(repl_flags.test(NetRuleOpt::NetRuleOpt_DELETE));

	auto port_rule = xfw_cfg->net_rules()->Get(4);
	ASSERT_TRUE(!port_rule->net6s());
	ASSERT_TRUE(!port_rule->net4s());
	ASSERT_TRUE(!port_rule->nets());
	ASSERT_TRUE(port_rule->ports());
	ASSERT_EQ(port_rule->ports()->size(), 2);
	ASSERT_EQ(port_rule->ports()->Get(0)->port(), 443);
	ASSERT_EQ(port_rule->ports()->Get(0)->port_end(), 0);
	ASSERT_EQ(port_rule->ports()->Get(1)->port(), 50);
	ASSERT_EQ(port_rule->ports()->Get(1)->port_end(), 52);

	//check icmp
	ASSERT_TRUE(xfw_cfg->icmp_rules());

	ASSERT_EQ(xfw_cfg->icmp_rules()->size(), 1);
	ASSERT_TRUE(!!xfw_cfg->icmp_rules()->Get(0));
	auto cfg = xfw_cfg->icmp_rules()->Get(0);
	ASSERT_TRUE(!!cfg->ratelimit());
	ASSERT_EQ(cfg->alias()->str(), "ip6");
	ASSERT_EQ(cfg->ratelimit()->str(), "my_ratelimit");
	ASSERT_EQ(cfg->types()->size(), 2);
	ASSERT_EQ(cfg->types()->Get(0), 13);
	ASSERT_EQ(cfg->types()->Get(1), 30);

	ASSERT_TRUE(!!cfg->flags());
	BitSet<IcmpRuleOpt, IcmpRuleOpt::IcmpRuleOpt_MAX> iflags;
	ASSERT_TRUE(bitset_deserialize(*cfg->flags(), iflags));
	ASSERT_TRUE(iflags.test(IcmpRuleOpt::IcmpRuleOpt_IPV6));
	ASSERT_TRUE(iflags.test(IcmpRuleOpt::IcmpRuleOpt_ALLOW));
	ASSERT_TRUE(iflags.test(IcmpRuleOpt::IcmpRuleOpt_REPLACE));
}