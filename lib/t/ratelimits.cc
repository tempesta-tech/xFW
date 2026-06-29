#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>

#include "../../lib/proto/bitset_helper.hh"
#include "../../lib/proto/serialize.hh"
#include "../../lib/cli/tcl_private.hh"

//Incorrect format for pps -> Fail.
TEST(RejectsXfwConfig, NonNumericPpsValueInRatelimit)
{
	std::string prog = "xfw{ratelimit=rl1 pps=empty bps=10;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Too big number for pps -> Fail.
TEST(RejectsXfwConfig, WithPpsValueTooLargeInRatelimit)
{
	std::string prog = "xfw{ratelimit pps=2345876475756674848576563675 bps=4000;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Incorrect format for bps -> Fail.
TEST(RejectsXfwConfig, NonNumericBpsValueInRatelimit)
{
	std::string prog = "xfw{ratelimit=rl2 pps=10 bps=;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Ratelimit's name is missing -> Fail.
TEST(RejectsXfwConfig, EmptyRatelimitName)
{
	std::string prog = "xfw{ratelimit pps=10 bps=20;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Both of 'pbs' and 'bbs' are missing -> Fail.
TEST(RejectsXfwConfig, RatelimitWithoutData)
{
	std::string prog = "xfw{ratelimit=my_ratelimit;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Two ratelimit rules with the same name -> Fail
TEST(RejectsXfwConfig, WithRepeatedRatelimitName)
{
	std::string prog = "xfw{ratelimit=my_ratelimit/del;"
			   "ratelimit=my_ratelimit pps=10 bps=20;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

//Correct format of ratelimit section -> Ok.
TEST(ParsesXfwConfig, WithFullRatelimit)
{
	std::string prog = "xfw{ratelimit=my_ratelimit pps=10 bps=20;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	const auto &ratelimits = conf->prvt->xfw_conf->ratelimits_;
	ASSERT_EQ(ratelimits.size(), 1);
	ASSERT_EQ(ratelimits[0].alias_, "my_ratelimit");
	ASSERT_EQ(ratelimits[0].pps_, 10);
	ASSERT_EQ(ratelimits[0].bps_, 20);
	ASSERT_FALSE(ratelimits[0].flags_.test(Ratelimit::Attr::DELETE));
}

//Correct format of ratelimit section -> Ok.
TEST(ParsesXfwConfig, WithRemoveRatelimit)
{
	std::string prog = "xfw{ratelimit=my_ratelimit/del;}";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	const auto &ratelimits = conf->prvt->xfw_conf->ratelimits_;
	ASSERT_EQ(ratelimits.size(), 1);
	ASSERT_EQ(ratelimits[0].alias_, "my_ratelimit");
	ASSERT_TRUE(ratelimits[0].flags_.test(Ratelimit::Attr::DELETE));
}

TEST(SerializesConfig, WithRatelimitsOnly)
{
	using namespace TempestaRPC;

	std::string prog = "xfw{ "
			   "ratelimit=my_ratelimit/del;"
			   "ratelimit=my_ratelimit2 pps=18446744073709551614 bps=18446744073709551615;"
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
	ASSERT_TRUE(xfw_cfg->ratelimits());
	ASSERT_EQ(xfw_cfg->ratelimits()->size(), 2);

	auto rule = xfw_cfg->ratelimits()->Get(0);
	ASSERT_TRUE(rule);
	ASSERT_TRUE(rule->alias());
	ASSERT_EQ(rule->alias()->str(), "my_ratelimit");
	ASSERT_TRUE(rule->flags());
	BitSet<RatelimitOpt, RatelimitOpt::RatelimitOpt_MAX> flags;
	ASSERT_TRUE(bitset_deserialize(*rule->flags(), flags));
	ASSERT_TRUE(flags.test(RatelimitOpt::RatelimitOpt_DELETE));

	rule = xfw_cfg->ratelimits()->Get(1);
	ASSERT_TRUE(rule);
	ASSERT_TRUE(rule->alias());
	ASSERT_EQ(rule->alias()->str(), "my_ratelimit2");
	ASSERT_TRUE(rule->flags());
	ASSERT_TRUE(bitset_deserialize(*rule->flags(), flags));
	ASSERT_FALSE(flags.test(RatelimitOpt::RatelimitOpt_DELETE));
	ASSERT_EQ(rule->pps(), 0xFFFFFFFFFFFFFFFE);
	ASSERT_EQ(rule->bps(), 0xFFFFFFFFFFFFFFFF);
}