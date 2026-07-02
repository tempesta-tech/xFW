#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>

#include "../../lib/proto/bitset_helper.hh"
#include "../../lib/proto/serialize.hh"
#include "../../lib/cli/tcl_private.hh"

TEST(RejectsXfwConfig, WithUnsupportedProtocol)
{
	std::string prog = "xfw{ip_proto {2} }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

TEST(ParsesXfwConfig, WithAllSupportedProtocols)
{
	std::string prog = "xfw{ip_proto {1, 6, 17, 47, 58} }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->ip_proto_.has_value());

	const auto &protocols = conf->prvt->xfw_conf->ip_proto_->protocols_;
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_ICMP));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_GRE));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_TCP));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_UDP));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_ICMPV6));
}

TEST(ParsesXfwConfig, WithIpProtoDeletion)
{
	std::string prog = "xfw{ip_proto/del; }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->flags_.test(XfwConf::Opt::IP_PROTO_FILTER_OFF));
	ASSERT_TRUE(!conf->prvt->xfw_conf->ip_proto_);
}

TEST(SerializesConfig, WithIpProtoOnly)
{
	using namespace TempestaRPC;

	std::string prog = "xfw{ ip_proto {1, 6, 17, 47, 58} }";

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
	ASSERT_TRUE(xfw_cfg->ip_proto());
	ASSERT_TRUE(xfw_cfg->ip_proto()->protocols());

	BitSet<XfwSupportedProtocols, XFW_SUPPORTED_PROTOCOL_MAX> protocols;
	ASSERT_TRUE(bitset_deserialize(*xfw_cfg->ip_proto()->protocols(), protocols));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_ICMP));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_GRE));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_TCP));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_UDP));
	ASSERT_TRUE(protocols.test(XfwSupportedProtocols::XFW_L4_PROTO_ICMPV6));
}

TEST(SerializesConfig, WithoutIpProto)
{
	using namespace TempestaRPC;

	std::string prog = "xfw{ }";

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
	ASSERT_FALSE(xfw_cfg->ip_proto());
}