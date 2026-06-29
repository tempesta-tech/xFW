#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>

#include "../../lib/proto/bitset_helper.hh"
#include "../../lib/proto/serialize.hh"
#include "../../lib/cli/tcl_private.hh"

const size_t XFW_OPT_BYTES =
	((TempestaRPC::XFWOpt_MAX - TempestaRPC::XFWOpt_MIN + 1) + 7) / 8;

//Correct format of default section -> Ok.
TEST(ParsesXfwConfig, AllRulesInDefaultSection)
{
	//We have the same order as in enum to simplify check
	const std::string prog ="xfw{defaults{"
				"src_ip ip4.tcp: allow; "
				"src_ip ip6.tcp: allow;"
				"src_ip ip4.udp: allow; "
				"src_ip ip6.udp: allow;"
				"src_port ip4.tcp: allow; "
				"src_port ip6.tcp: allow;"
				"src_port ip4.udp: allow; "
				"src_port ip6.udp: allow;"
				"dst ip4.tcp: allow;"
				"dst ip6.tcp: allow; "
				"dst ip4.udp: allow;"
				"dst ip6.udp: allow; "
				"icmp ip4: allow;"
				"icmp ip6: allow;"
			"}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->defaults_.size(), DefaultIndex::XFW_DEFAULT_MAX);

	for (uint8_t i = 0; i < static_cast<uint8_t>(DefaultIndex::XFW_DEFAULT_MAX); ++i) {
		auto &rule = conf->prvt->xfw_conf->defaults_[i];
		ASSERT_EQ(rule.allow_, true);
		ASSERT_TRUE(rule.ratelimit_.empty());
		ASSERT_TRUE(rule.flags_.test(static_cast<DefaultIndex>(i)));
	}
}

//Correct format of default section -> Ok.
TEST(ParsesXfwConfig, DefaultSectionWithoutProtoTypeWithoutTransportType)
{
	//We have the same order as in enum to simplify check
	const std::string prog ="xfw{defaults{"
				"src_ip: block; "
			"}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->defaults_.size(), 1);

	auto &rule = conf->prvt->xfw_conf->defaults_[0];
	ASSERT_EQ(rule.allow_, false);
	ASSERT_TRUE(rule.ratelimit_.empty());
	ASSERT_TRUE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP4));
	ASSERT_TRUE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP6));
	ASSERT_TRUE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP4));
	ASSERT_TRUE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP6));

	//other flags are null
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_PORT_TCP_IP4));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_PORT_TCP_IP6));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_PORT_UDP_IP4));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_PORT_UDP_IP6));

	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_DST_TCP_IP4));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_DST_TCP_IP6));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_DST_UDP_IP4));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_DST_UDP_IP6));

	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_ICMP_IP4));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_ICMP_IP6));
}

//Correct format of default section -> Ok.
TEST(ParsesXfwConfig, DefaultSectionWithIp4WithoutTransportProtocol)
{
	//We have the same order as in enum to simplify check
	const std::string prog ="xfw{defaults{"
				"src_ip ip4: ratelimit = myRatelimit; "
			"}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->defaults_.size(), 1);

	auto &rule = conf->prvt->xfw_conf->defaults_[0];
	ASSERT_EQ(rule.allow_, true);
	ASSERT_FALSE(rule.ratelimit_.empty());
	ASSERT_EQ(rule.ratelimit_, "myRatelimit");
	ASSERT_TRUE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP4));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP6));
	ASSERT_TRUE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP4));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP6));
}

//Conflict of rules is not allowed -> Fail.
TEST(RejectXfwConfig, DefaultSectionWhenSecondRuleIncludeFirst)
{
	const std::string prog ="xfw{defaults{"
				"src_ip ip4.tcp: allow; "
				"src_ip : allow;"
			"}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Conflict of rules is not allowed -> Fail.
TEST(RejectXfwConfig, DefaultSectionWhenFirstRuleIncludeSecond)
{
	const std::string prog ="xfw{defaults{"
				"src_ip : allow;"
				"src_ip ip6.udp: allow; "
			"}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Unknown words in section -> Fail.
TEST(RejectXfwConfig, DefaultSectionWithUnknownName)
{
	const std::string prog ="xfw{defaults{"
				"src_prt : allow;"
			"}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Correct format of default section -> Ok.
TEST(ParsesXfwConfig, DefaultSectionWithIp6WithoutTransportProtocol)
{
	//We have the same order as in enum to simplify check
	const std::string prog ="xfw{defaults{"
				"src_ip ip6: ratelimit = myRatelimit; "
			"}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->defaults_.size(), 1);

	auto &rule = conf->prvt->xfw_conf->defaults_[0];
	ASSERT_EQ(rule.allow_, true);
	ASSERT_FALSE(rule.ratelimit_.empty());
	ASSERT_EQ(rule.ratelimit_, "myRatelimit");
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP4));
	ASSERT_TRUE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_TCP_IP6));
	ASSERT_FALSE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP4));
	ASSERT_TRUE(rule.flags_.test(DefaultIndex::XFW_DEFAULT_SRC_IP_UDP_IP6));
}

TEST(SerializesConfig, WithDefaultsOnly)
{
	using namespace TempestaRPC;

	//We have the same order as in enum to simplify check
	const std::string prog ="xfw{defaults{"
				"src_ip ip4.tcp: block; "
				"src_ip ip6.tcp: block;"
				"src_ip ip4.udp: block; "
				"src_ip ip6.udp: block;"
				"src_port ip4.tcp: block; "
				"src_port ip6.tcp: block;"
				"src_port ip4.udp: block; "
				"src_port ip6.udp: block;"
				"dst ip4.tcp: block;"
				"dst ip6.tcp: block; "
				"dst ip4.udp: block;"
				"dst ip6.udp: block; "
				"icmp ip4: block;"
				"icmp ip6: block;"
			"}}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);

	flatbuffers::grpc::Message<TempestaRPC::Request> request =
		build_set_config_request(*conf);

	//deserialize
	auto req = request.GetRoot();
	ASSERT_TRUE(req);
	ASSERT_EQ(req->proto_ver(), ProtoVersion);
	ASSERT_EQ(req->records()->size(), 1);

	ASSERT_EQ(req->records()->Get(0)->type(), ReqRecType_RRT_XFW_CFG);
	auto xfw_cfg = req->records()->Get(0)->data_as_xfw_cfg();
	ASSERT_TRUE(xfw_cfg);
	ASSERT_EQ(xfw_cfg->flags()->size(), XFW_OPT_BYTES);
	ASSERT_EQ(xfw_cfg->defaults()->size(), DefaultIndex::XFW_DEFAULT_MAX);

	for (uint8_t i = 0; i < static_cast<uint8_t>(DefaultIndex::XFW_DEFAULT_MAX); ++i) {
		auto rule = xfw_cfg->defaults()->Get(i);

		ASSERT_TRUE(rule->flags());
		BitSet<DefaultIndex, XFW_DEFAULT_MAX> cflags;
		ASSERT_TRUE(bitset_deserialize(*rule->flags(), cflags));

		ASSERT_EQ(rule->allow(), false);
		ASSERT_TRUE(!rule->ratelimit());
		ASSERT_TRUE(cflags.test(static_cast<DefaultIndex>(i)))
			<< "Failed on i:" << i << ":"<< cflags;
	}
}