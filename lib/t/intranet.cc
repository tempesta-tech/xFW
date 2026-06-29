#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>

#include "../../lib/proto/bitset_helper.hh"
#include "../../lib/proto/serialize.hh"
#include "../../lib/cli/tcl_private.hh"

//Remove alias without a name -> Fail.
//Explanation: We have to know which net we have to remove.
TEST(RejectsXfwConfig, RemoveNetWithoutAlias)
{
	std::string prog = "xfw{net/del;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_FALSE(conf);
}

//Correct format of net section -> Ok.
TEST(ParsesXfwConfig, OneNet)
{
	std::string prog = "xfw{"
			   "net ip4 {127.0.0.1, 127.0.0.0/8}"
			   "}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->net_rules_.size(), 1);

	auto &rule = conf->prvt->xfw_conf->net_rules_[0];
	ASSERT_EQ(rule.alias_, "ip4");
	ASSERT_TRUE(rule.ratelimit_.empty());
	ASSERT_EQ(rule.net6s_.size(), 0);
	ASSERT_EQ(rule.net4s_.size(), 2);
	ASSERT_EQ(rule.net4s_[0].port_, 0);
	ASSERT_EQ(rule.net4s_[0].prefix_, 32);
	ASSERT_EQ(rule.net4s_[0].addr_[0], 0x7F);
	ASSERT_EQ(rule.net4s_[0].addr_[1], 0x00);
	ASSERT_EQ(rule.net4s_[0].addr_[2], 0x00);
	ASSERT_EQ(rule.net4s_[0].addr_[3], 0x01);
	ASSERT_EQ(rule.net4s_[1].port_, 0);
	ASSERT_EQ(rule.net4s_[1].prefix_, 8);
	ASSERT_EQ(rule.net4s_[1].addr_[0], 0x7F);
	ASSERT_EQ(rule.net4s_[1].addr_[1], 0x00);
	ASSERT_EQ(rule.net4s_[1].addr_[2], 0x00);
	ASSERT_EQ(rule.net4s_[1].addr_[3], 0x00);
	ASSERT_EQ(rule.nets_.size(), 0);
	ASSERT_EQ(rule.ports_.size(), 0);
	auto &rflags = rule.flags_;
	ASSERT_TRUE(rflags.test(NetRule::Attr::PROTECTED_NET));
	ASSERT_FALSE(rflags.test(NetRule::Attr::IPV6));
	ASSERT_FALSE(rflags.test(NetRule::Attr::TCP));
	ASSERT_FALSE(rflags.test(NetRule::Attr::SRC));
}

//Correct format of net section -> Ok.
TEST(ParsesXfwConfig, TwoNetsWithoutAlias)
{
	std::string prog = "xfw{"
			   "net ip4 {127.0.0.1, 127.0.0.0/8}"
			   "net ip6 {3001:db8:85a3::8a2e:370:7334/120}"
			   "}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->net_rules_.size(), 2);

	auto &rule = conf->prvt->xfw_conf->net_rules_[0];
	ASSERT_EQ(rule.alias_, "ip4");
	ASSERT_TRUE(rule.ratelimit_.empty());
	ASSERT_EQ(rule.net6s_.size(), 0);
	ASSERT_EQ(rule.nets_.size(), 0);
	ASSERT_EQ(rule.ports_.size(), 0);
	ASSERT_EQ(rule.net4s_.size(), 2);
	ASSERT_EQ(rule.net4s_[0].port_, 0);
	ASSERT_EQ(rule.net4s_[0].prefix_, 32);
	ASSERT_EQ(rule.net4s_[0].addr_[0], 0x7F);
	ASSERT_EQ(rule.net4s_[0].addr_[1], 0x00);
	ASSERT_EQ(rule.net4s_[0].addr_[2], 0x00);
	ASSERT_EQ(rule.net4s_[0].addr_[3], 0x01);
	ASSERT_EQ(rule.net4s_[1].port_, 0);
	ASSERT_EQ(rule.net4s_[1].prefix_, 8);
	ASSERT_EQ(rule.net4s_[1].addr_[0], 0x7F);
	ASSERT_EQ(rule.net4s_[1].addr_[1], 0x00);
	ASSERT_EQ(rule.net4s_[1].addr_[2], 0x00);
	ASSERT_EQ(rule.net4s_[1].addr_[3], 0x00);

	auto &rflags = rule.flags_;
	ASSERT_TRUE(rflags.test(NetRule::Attr::PROTECTED_NET));
	ASSERT_FALSE(rflags.test(NetRule::Attr::IPV6));
	ASSERT_FALSE(rflags.test(NetRule::Attr::TCP));
	ASSERT_FALSE(rflags.test(NetRule::Attr::SRC));


	auto &rule2 = conf->prvt->xfw_conf->net_rules_[1];
	ASSERT_EQ(rule2.alias_, "ip6");
	ASSERT_TRUE(rule2.ratelimit_.empty());
	ASSERT_EQ(rule2.net4s_.size(), 0);
	ASSERT_EQ(rule2.nets_.size(), 0);
	ASSERT_EQ(rule2.ports_.size(), 0);
	ASSERT_EQ(rule2.net6s_.size(), 1);
	ASSERT_EQ(rule2.net6s_[0].addr_[0], 0x30);
	ASSERT_EQ(rule2.net6s_[0].addr_[1], 0x01);
	ASSERT_EQ(rule2.net6s_[0].addr_[2], 0x0d);
	ASSERT_EQ(rule2.net6s_[0].addr_[3], 0xb8);
	ASSERT_EQ(rule2.net6s_[0].addr_[4], 0x85);
	ASSERT_EQ(rule2.net6s_[0].addr_[5], 0xa3);
	ASSERT_EQ(rule2.net6s_[0].addr_[6], 0x00);
	ASSERT_EQ(rule2.net6s_[0].addr_[7], 0x00);
	ASSERT_EQ(rule2.net6s_[0].addr_[8], 0x00);
	ASSERT_EQ(rule2.net6s_[0].addr_[9], 0x00);
	ASSERT_EQ(rule2.net6s_[0].addr_[10], 0x8a);
	ASSERT_EQ(rule2.net6s_[0].addr_[11], 0x2e);
	ASSERT_EQ(rule2.net6s_[0].addr_[12], 0x03);
	ASSERT_EQ(rule2.net6s_[0].addr_[13], 0x70);
	ASSERT_EQ(rule2.net6s_[0].addr_[14], 0x73);
	ASSERT_EQ(rule2.net6s_[0].addr_[15], 0x34);
	ASSERT_EQ(rule2.net6s_[0].port_, 0);
	ASSERT_EQ(rule2.net6s_[0].prefix_, 120);

	auto &r2flags = rule2.flags_;
	ASSERT_TRUE(r2flags.test(NetRule::Attr::PROTECTED_NET));
	ASSERT_TRUE(r2flags.test(NetRule::Attr::IPV6));
	ASSERT_FALSE(r2flags.test(NetRule::Attr::TCP));
	ASSERT_FALSE(r2flags.test(NetRule::Attr::SRC));
}

//Remove alias with default name ip4. -> Ok.
TEST(ParsesXfwConfig, RemoveNetWithAlias)
{
	std::string prog = "xfw{net=ip4/del;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	const auto &rules = conf->prvt->xfw_conf->net_rules_;
	ASSERT_EQ(rules.size(), 1);
	ASSERT_EQ(rules[0].alias_, "ip4");
	ASSERT_TRUE(rules[0].flags_.test(NetRule::Attr::DELETE));
	ASSERT_TRUE(rules[0].flags_.test(NetRule::Attr::PROTECTED_NET));
}

TEST(SerializesConfig, WithNetOnly)
{
	using namespace TempestaRPC;

	std::string prog = "xfw{ "
			   "net ip4 {127.0.0.1, 127.0.0.0/8}"
			   "net=my_name ip6 {3001:db8:85a3::8a2e:370:7334/120}"
			   "net=ip6/del;"
			   " }";

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
	ASSERT_TRUE(xfw_cfg->net_rules());
	ASSERT_EQ(xfw_cfg->net_rules()->size(), 3);

	BitSet<NetRuleOpt, NetRuleOpt::NetRuleOpt_MAX> flags;
	auto rule = xfw_cfg->net_rules()->Get(0);
	ASSERT_TRUE(rule);
	ASSERT_TRUE(rule->alias());
	ASSERT_EQ(rule->alias()->str(), "ip4");
	ASSERT_TRUE(rule->flags());
	ASSERT_TRUE(rule->net4s());
	ASSERT_EQ(rule->net4s()->size(), 2);
	ASSERT_EQ(rule->net4s()->Get(0)->port(), 0);
	ASSERT_EQ(rule->net4s()->Get(0)->prefix(), 32);
	ASSERT_EQ(rule->net4s()->Get(0)->addr()->Get(0), 0x7F);
	ASSERT_EQ(rule->net4s()->Get(0)->addr()->Get(1), 0x00);
	ASSERT_EQ(rule->net4s()->Get(0)->addr()->Get(2), 0x00);
	ASSERT_EQ(rule->net4s()->Get(0)->addr()->Get(3), 0x01);
	ASSERT_EQ(rule->net4s()->Get(1)->port(), 0);
	ASSERT_EQ(rule->net4s()->Get(1)->prefix(), 8);
	ASSERT_EQ(rule->net4s()->Get(1)->addr()->Get(0), 0x7F);
	ASSERT_EQ(rule->net4s()->Get(1)->addr()->Get(1), 0x00);
	ASSERT_EQ(rule->net4s()->Get(1)->addr()->Get(2), 0x00);
	ASSERT_EQ(rule->net4s()->Get(1)->addr()->Get(3), 0x00);

	ASSERT_TRUE(!!rule->flags());
	ASSERT_TRUE(bitset_deserialize(*rule->flags(), flags));
	ASSERT_FALSE(flags.test(NetRuleOpt::NetRuleOpt_DELETE));
	ASSERT_TRUE(flags.test(NetRuleOpt::NetRuleOpt_PROTECTED_NET));
	ASSERT_FALSE(flags.test(NetRuleOpt::NetRuleOpt_IPV6));

	rule = xfw_cfg->net_rules()->Get(1);
	ASSERT_TRUE(rule);
	ASSERT_TRUE(rule->alias());
	ASSERT_EQ(rule->alias()->str(), "my_name");
	ASSERT_TRUE(rule->flags());
	ASSERT_TRUE(rule->net6s());
	ASSERT_EQ(rule->net6s()->size(), 1);
	ASSERT_EQ(rule->net6s()->Get(0)->port(), 0);
	ASSERT_EQ(rule->net6s()->Get(0)->prefix(), 120);
	ASSERT_TRUE(rule->net6s()->Get(0)->addr());
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->size(), 16);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(0), 0x30);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(1), 0x01);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(2), 0x0d);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(3), 0xb8);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(4), 0x85);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(5), 0xa3);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(6), 0x00);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(7), 0x00);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(8), 0x00);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(9), 0x00);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(10), 0x8a);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(11), 0x2e);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(12), 0x03);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(13), 0x70);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(14), 0x73);
	ASSERT_EQ(rule->net6s()->Get(0)->addr()->Get(15), 0x34);
	
	ASSERT_TRUE(!!rule->flags());
	ASSERT_TRUE(bitset_deserialize(*rule->flags(), flags));
	ASSERT_FALSE(flags.test(NetRuleOpt::NetRuleOpt_DELETE));
	ASSERT_TRUE(flags.test(NetRuleOpt::NetRuleOpt_PROTECTED_NET));

	rule = xfw_cfg->net_rules()->Get(2);
	ASSERT_TRUE(rule);
	ASSERT_TRUE(rule->alias());
	ASSERT_EQ(rule->alias()->str(), "ip6");
	ASSERT_TRUE(rule->flags());
	ASSERT_TRUE(bitset_deserialize(*rule->flags(), flags));
	ASSERT_TRUE(flags.test(NetRuleOpt::NetRuleOpt_DELETE));
	ASSERT_TRUE(flags.test(NetRuleOpt::NetRuleOpt_PROTECTED_NET));
}
