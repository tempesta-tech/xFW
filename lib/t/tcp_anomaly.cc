#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>

#include "../../lib/proto/bitset_helper.hh"
#include "../../lib/proto/serialize.hh"
#include "../../lib/cli/tcl_private.hh"

std::string
flags_to_string(uint8_t bits)
{
	std::string result;

	auto append_flag_if_need = [&](const char* name, uint8_t mask) {
		if (bits & mask) {
			if (!result.empty())
				result += "+";
			result += name;
		}
	};

	if (bits == 0)
		return "0";

	append_flag_if_need("SYN", TcpControlBits::XFW_BIT_SYN);
	append_flag_if_need("ACK", TcpControlBits::XFW_BIT_ACK);
	append_flag_if_need("FIN", TcpControlBits::XFW_BIT_FIN);
	append_flag_if_need("RST", TcpControlBits::XFW_BIT_RST);
	append_flag_if_need("ECE", TcpControlBits::XFW_BIT_ECE);
	append_flag_if_need("URG", TcpControlBits::XFW_BIT_URG);
	append_flag_if_need("PSH", TcpControlBits::XFW_BIT_PSH);
	append_flag_if_need("CWR", TcpControlBits::XFW_BIT_CWR);

	return result;
}

std::string
build_bad_flags(const std::vector<uint8_t> &combos)
{
	std::string result;

	for (size_t i = 0; i < combos.size(); ++i)
	{
		if (i)
			result += ", ";
		result += flags_to_string(combos[i]);
	}

	return result;
}

//Check that without the tcp_anomaly_filter in config we setup nothing by default.
TEST(ParsesXfwConfig, WithoutTcpAnomalyFilter)
{
	const std::string prog ="xfw{}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_FALSE(conf->prvt->xfw_conf->tcp_anomaly_.has_value());
}

//Correct format of tcp_anomaly_filter -> Ok. All features are set in default values.
TEST(ParsesXfwConfig, WithShortTcpAnomalyFilter)
{
	const std::string prog ="xfw{tcp_anomaly_filter;}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->tcp_anomaly_.has_value());

	const auto &anomaly = conf->prvt->xfw_conf->tcp_anomaly_.value();
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_BAD_FLAGS));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO));
	ASSERT_FALSE(anomaly.bad_tcp_flags_.has_value());
	ASSERT_EQ(anomaly.seqno_value_, 0);
}

struct TcpFlagParam
{
	std::vector<uint8_t> combos;
};

class ParsesXfwConfigWithBadFlags: public ::testing::TestWithParam<TcpFlagParam> {};

INSTANTIATE_TEST_SUITE_P(
	,
	ParsesXfwConfigWithBadFlags,
	::testing::Values(
		TcpFlagParam{{TcpControlBits::XFW_BIT_NONE}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_FIN}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_SYN}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_RST}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_PSH}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_ACK}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_URG}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_ECE}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_CWR}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_ACK}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_FIN | TcpControlBits::XFW_BIT_RST}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_RST |
			      TcpControlBits::XFW_BIT_FIN | TcpControlBits::XFW_BIT_ACK |
			      TcpControlBits::XFW_BIT_ECE | TcpControlBits::XFW_BIT_URG |
			      TcpControlBits::XFW_BIT_PSH | TcpControlBits::XFW_BIT_CWR}},
		TcpFlagParam{{TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_ACK,
			      TcpControlBits::XFW_BIT_FIN | TcpControlBits::XFW_BIT_RST}}

	)
);

//Different tcp flags combinations in bad_flags -> Ok.
TEST_P(ParsesXfwConfigWithBadFlags, InTcpAnomalyFilter)
{
  	const auto &param = GetParam();
	const std::string prog = "xfw{tcp_anomaly_filter bad_flags(" + 
				  build_bad_flags(param.combos) + ");}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->tcp_anomaly_.has_value());

	const auto &anomaly = conf->prvt->xfw_conf->tcp_anomaly_.value();
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO));

	ASSERT_TRUE(anomaly.features_.test(TcpAnomalyFeature::XFW_BAD_FLAGS));
	ASSERT_TRUE(anomaly.bad_tcp_flags_.has_value());
	
	const auto &flags = anomaly.bad_tcp_flags_.value();
	for (auto combo : param.combos)
		ASSERT_TRUE(flags.test(static_cast<TcpControlBits>(combo)));
}

struct TcpWhitespaceParam
{
	const char* flags;
	std::vector<uint8_t> combos;
};

class ParsesXfwConfigWithWhitespacedBadFlags :
    public ::testing::TestWithParam<TcpWhitespaceParam> {};

INSTANTIATE_TEST_SUITE_P(
	,
	ParsesXfwConfigWithWhitespacedBadFlags,
	::testing::Values(
		TcpWhitespaceParam{
			"SYN+ACK,FIN+RST",
			{
				TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_ACK,
				TcpControlBits::XFW_BIT_FIN | TcpControlBits::XFW_BIT_RST
			}
		},
		TcpWhitespaceParam{
			"SYN + ACK,FIN + RST",
			{
				TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_ACK,
				TcpControlBits::XFW_BIT_FIN | TcpControlBits::XFW_BIT_RST
			}
		},
		TcpWhitespaceParam{
			"SYN+ACK , FIN+RST",
			{
				TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_ACK,
				TcpControlBits::XFW_BIT_FIN | TcpControlBits::XFW_BIT_RST
			}
		},
		TcpWhitespaceParam{
			" SYN  +  ACK  ,  FIN  +  RST ",
			{
				TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_ACK,
				TcpControlBits::XFW_BIT_FIN | TcpControlBits::XFW_BIT_RST
			}
		},
		TcpWhitespaceParam{
			"SYN, SYN + ACK + URG ,FIN  +  RST ",
			{
				TcpControlBits::XFW_BIT_SYN,
				TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_ACK
							| TcpControlBits::XFW_BIT_URG,
				TcpControlBits::XFW_BIT_FIN | TcpControlBits::XFW_BIT_RST
			},
		},
		TcpWhitespaceParam{
			"SYN + ACK,FIN",
			{
				TcpControlBits::XFW_BIT_SYN | TcpControlBits::XFW_BIT_ACK,
				TcpControlBits::XFW_BIT_FIN
			}
		}
	)
);

TEST_P(ParsesXfwConfigWithWhitespacedBadFlags, SpacesAroundOperators)
{
	const auto& param = GetParam();

	const std::string prog = std::string("xfw{tcp_anomaly_filter bad_flags(") +
					     param.flags + ");}";

	std::unique_ptr<TlProgConf> conf(
		tcl_parse_full_conf(prog.c_str(), prog.length()));

	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->tcp_anomaly_.has_value());

	const auto &anomaly = conf->prvt->xfw_conf->tcp_anomaly_.value();

	ASSERT_TRUE(anomaly.bad_tcp_flags_.has_value());

	const auto &flags = anomaly.bad_tcp_flags_.value();

	for (auto combo : param.combos)
		ASSERT_TRUE(flags.test(static_cast<TcpControlBits>(combo)));
}

//Just syn_without_opt in tcp_anomaly_filter -> Ok.
TEST(ParsesXfwConfig, WithNoOptionsInTcpAnomalyFilter)
{
	const std::string prog = "xfw{tcp_anomaly_filter syn_without_opt;}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->tcp_anomaly_.has_value());

	const auto &anomaly = conf->prvt->xfw_conf->tcp_anomaly_.value();
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD));
	ASSERT_TRUE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_BAD_FLAGS));
}

//Just syn_with_payload in tcp_anomaly_filter -> Ok.
TEST(ParsesXfwConfig, WithPayloadInTcpAnomalyFilter)
{
	const std::string prog = "xfw{tcp_anomaly_filter syn_with_payload;}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->tcp_anomaly_.has_value());

	const auto &anomaly = conf->prvt->xfw_conf->tcp_anomaly_.value();
	ASSERT_TRUE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_BAD_FLAGS));
}

//Just syn_with_seqno=0 in tcp_anomaly_filter -> Ok.
TEST(ParsesXfwConfig, WithNullSeqNumberInTcpAnomalyFilter)
{
	const std::string prog = "xfw{tcp_anomaly_filter syn_with_seqno=0;}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->tcp_anomaly_.has_value());

	const auto &anomaly = conf->prvt->xfw_conf->tcp_anomaly_.value();
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS));
	ASSERT_TRUE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO));
	ASSERT_EQ(anomaly.seqno_value_, 0);
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_BAD_FLAGS));
}

//Just syn_with_seqno=4294967295 in tcp_anomaly_filter -> Ok.
TEST(ParsesXfwConfig, WithHugeSeqNumberInTcpAnomalyFilter)
{
	const std::string prog = "xfw{tcp_anomaly_filter syn_with_seqno=4294967295;}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_TRUE(conf);
	ASSERT_TRUE(conf->prvt);
	ASSERT_TRUE(conf->prvt->xfw_conf.has_value());
	ASSERT_TRUE(conf->prvt->xfw_conf->tcp_anomaly_.has_value());

	const auto &anomaly = conf->prvt->xfw_conf->tcp_anomaly_.value();
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD));
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS));
	ASSERT_TRUE(anomaly.features_.test(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO));
	ASSERT_EQ(anomaly.seqno_value_, 4294967295);
	ASSERT_FALSE(anomaly.features_.test(TcpAnomalyFeature::XFW_BAD_FLAGS));
}

//Just syn_with_seqno=4294967296 > uint32_t in tcp_anomaly_filter -> Fail.
TEST(RejectsXfwConfig, WithIllegalSeqNumberInTcpAnomalyFilter)
{
	const std::string prog = "xfw{tcp_anomaly_filter syn_with_seqno=4294967296;}";

	std::unique_ptr<TlProgConf> conf(tcl_parse_full_conf(prog.c_str(), prog.length()));
	ASSERT_FALSE(conf);
}

TEST(SerializesConfig, WithTcpAnomalyFilterOnly)
{
	using namespace TempestaRPC;

	std::string prog = "xfw{ "
			   "tcp_anomaly_filter syn_with_seqno=1050 syn_with_payload "
			   "syn_without_opt bad_flags(SYN+ACK,SYN);"
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
	ASSERT_TRUE(xfw_cfg->tcp_anomaly());

	ASSERT_TRUE(xfw_cfg->tcp_anomaly()->bad_tcp_flags());
	BitSet<TcpControlBits, XFW_BIT_CONTROL_MAX> flags;
	ASSERT_TRUE(bitset_deserialize(*xfw_cfg->tcp_anomaly()->bad_tcp_flags(), flags));
	ASSERT_FALSE(flags.test(XFW_BIT_NONE));
	ASSERT_TRUE(flags.test(static_cast<TcpControlBits>(XFW_BIT_SYN|XFW_BIT_ACK)));
	ASSERT_TRUE(flags.test(XFW_BIT_SYN));
	ASSERT_FALSE(flags.test(static_cast<TcpControlBits>(XFW_BIT_SYN|XFW_BIT_RST)));
	ASSERT_FALSE(flags.test(XFW_BIT_RST));
	
	ASSERT_TRUE(xfw_cfg->tcp_anomaly()->features());

	BitSet<TcpAnomalyFeature, XFW_TCP_ANOMALY_FEATURE_MAX> features;
	ASSERT_TRUE(bitset_deserialize(*xfw_cfg->tcp_anomaly()->features(), features));
	ASSERT_TRUE(features.test(TcpAnomalyFeature::XFW_BAD_FLAGS));
	ASSERT_TRUE(features.test(TcpAnomalyFeature::XFW_SYN_WIHOUT_OPTIONS));
	ASSERT_TRUE(features.test(TcpAnomalyFeature::XFW_SYN_WITH_PAYLOAD));
	ASSERT_TRUE(features.test(TcpAnomalyFeature::XFW_SYN_WITH_SEQ_NO));

	ASSERT_EQ(xfw_cfg->tcp_anomaly()->seqno_value(), 1050);
}