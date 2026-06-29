#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>

#include "../../lib/proto/bitset_helper.hh"
#include "../../lib/proto/serialize.hh"
#include "../../lib/cli/tcl_private.hh"

const size_t XFW_OPT_BYTES =
	((TempestaRPC::XFWOpt_MAX - TempestaRPC::XFWOpt_MIN + 1) + 7) / 8;

TEST(ParsesXfwConfig, WithTypeInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags syn : ratelimit=my_ratelimit;"
			   "tcp_flags rst :ratelimit=my_ratelimit2;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_.size(), 2);
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_[0].flag_, TcpFlags::FlagType::SYN);
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_[0].ratelimit_, "my_ratelimit");
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_[1].flag_, TcpFlags::FlagType::RST);
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_[1].ratelimit_, "my_ratelimit2");
}

TEST(ParsesXfwConfig, WithoutTypeInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags : ratelimit=my_ratelimit;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_.size(), 1);
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_[0].flag_, TcpFlags::FlagType::ALL);
}

TEST(ParsesXfwConfig, WithoutExtraSpacesInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags rst:ratelimit=my_ratelimit;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_.size(), 1);
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_[0].flag_, TcpFlags::FlagType::RST);
}

TEST(ParsesXfwConfig, WithDeleteSynInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags/del syn;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::TCP_SYN_FLAGS_FILTER_OFF));
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_.size(), 0);
}

TEST(ParsesXfwConfig, WithDeleteRstInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags/del rst;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::TCP_RST_FLAGS_FILTER_OFF));
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_.size(), 0);
}

TEST(ParsesXfwConfig, WithDeleteAllInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags/del;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::TCP_RST_FLAGS_FILTER_OFF));
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::TCP_SYN_FLAGS_FILTER_OFF));
	ASSERT_EQ(conf->prvt->xfw_conf->tcp_flags_.size(), 0);
}

// Two rules for 'syn' flag -> Fail.
// Explanation: missing flag means 'all' flags.
TEST(RejectXfwConfig, WithConflictRuleInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags syn :ratelimit=my_ratelimit;"
			   "tcp_flags :ratelimit=my_ratelimit2;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

// Action /add in tcp_flags -> Fail.
// Explanation: only /del is allowed.
TEST(RejectXfwConfig, WithUnknownActionInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags/add syn :ratelimit=my_ratelimit;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

// Missed ratelimit in tcp_flags -> Fail.
// Explanation: ratelimit is required field for tcp_flags.
TEST(RejectXfwConfig, WithoutRatelimitInTcpFlags)
{
	std::string prog = "xfw{ "
			   "tcp_flags syn;"
			   " }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

TEST(SerializesConfig, WithTcpFlagsOnly)
{
	using namespace TempestaRPC;

	std::string prog = "xfw{ "
			   "tcp_flags syn :ratelimit=my_ratelimit;"
			   "tcp_flags/del rst;"
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
	ASSERT_TRUE(xfw_cfg->flags());
	ASSERT_EQ(xfw_cfg->flags()->size(), XFW_OPT_BYTES);
	ASSERT_EQ(xfw_cfg->tcp_flags()->size(), 1);

	BitSet<XFWOpt, XFWOpt::XFWOpt_MAX> cflags;
	ASSERT_TRUE(bitset_deserialize(*xfw_cfg->flags(), cflags));
	ASSERT_TRUE(cflags.test(XFWOpt::XFWOpt_TCP_RST_FLAGS_FILTER_OFF));
	ASSERT_FALSE(cflags.test(XFWOpt::XFWOpt_TCP_SYN_FLAGS_FILTER_OFF));

	auto rule = xfw_cfg->tcp_flags()->Get(0);
	ASSERT_EQ(rule->flag(), TcpFlagType::TcpFlagType_SYN);
	ASSERT_TRUE(rule->ratelimit());
	ASSERT_EQ(rule->ratelimit()->str(), "my_ratelimit");
}