#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>

#include "../../lib/proto/bitset_helper.hh"
#include "../../lib/proto/serialize.hh"
#include "../../lib/cli/tcl_private.hh"

TEST(RejectsXfwConfig, WithUnsupportedProtocolPositive)
{
	std::string prog = "xfw{ip_proto {256} }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

TEST(RejectsXfwConfig, WithUnsupportedProtocolNegative)
{
	std::string prog = "xfw{ip_proto {-1} }";
	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(!conf);
}

TEST(ParsesXfwConfig, WithAllSupportedProtocols)
{
	std::string prog = "xfw{ip_proto {"
		"1, 2, 3, 4, 5, 6, 7, 8, 9, 10,"
		"11, 12, 13, 14, 15, 16, 17, 18, 19, 20,"
		"21, 22, 23, 24, 25, 26, 27, 28, 29, 30,"
		"41, 42, 43, 44, 45, 46, 47, 48, 49, 50,"
		"51, 52, 53, 54, 55, 56, 57, 58, 59, 60,"
		"61, 62, 63, 64, 65, 66, 67, 68, 69, 70,"
		"81, 82, 83, 84, 85, 86, 87, 88, 89, 90,"
		"91, 92, 93, 94, 95, 96, 97, 98, 99, 100,"
		"101, 102, 103, 104, 105, 106, 107, 108, 109, 110,"
		"111, 112, 113, 114, 115, 116, 117, 118, 119, 120,"
		"121, 122, 123, 124, 125, 126, 127, 128, 129, 130,"
		"131, 132, 133, 134, 135, 136, 137, 138, 139, 140,"
		"141, 142, 143, 144, 145, 146, 147, 148, 149, 150,"
		"151, 152, 153, 154, 155, 156, 157, 158, 159, 160,"
		"161, 162, 163, 164, 165, 166, 167, 168, 169, 170,"
		"171, 172, 173, 174, 175, 176, 177, 178, 179, 180,"
		"181, 182, 183, 184, 185, 186, 187, 188, 189, 190,"
		"191, 192, 193, 194, 195, 196, 197, 198, 199, 200,"
		"201, 202, 203, 204, 205, 206, 207, 208, 209, 210,"
		"211, 212, 213, 214, 215, 216, 217, 218, 219, 220,"
		"221, 222, 223, 224, 225, 226, 227, 228, 229, 230,"
		"231, 232, 233, 234, 235, 236, 237, 238, 239, 240,"
		"241, 242, 243, 244, 245, 246, 247, 248, 249, 250,"
		"251, 252, 253, 254, 255"
	"} }";
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