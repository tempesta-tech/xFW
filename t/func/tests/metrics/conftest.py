# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later


import pytest

from framework.fabrics import client_fabric
from tests.metrics.utils import InvalidEthTypeRawClient
from tests.test_icmp import ICMP_BLOCKING_TYPES_STR


@pytest.fixture
async def xfw_blocked_by_tcp_flags_syn(xfw):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=1000;
            tcp_flags syn : ratelimit=test;
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_tcp_flags_rst(xfw):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=1000;
            tcp_flags rst : ratelimit=test;
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_icmp(xfw, ip_version):
    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ icmp: allow; }}
            icmp {ip_version}: block {{ {ICMP_BLOCKING_TYPES_STR} }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_icmp_ratelimit(xfw, ip_version):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=5000;
            defaults {{ icmp: allow; }}
            icmp {ip_version}: ratelimit=test {{ {ICMP_BLOCKING_TYPES_STR} }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_icmp_defaults(xfw):
    await xfw.rules_set(f"xfw {{ defaults {{ icmp: block; }} }}")


@pytest.fixture
async def xfw_blocked_by_icmp_defaults_ratelimit(xfw):
    await xfw.rules_set(f"""
        xfw {{
            ratelimit=test pps=0 bps=5000;
            defaults {{ icmp: ratelimit=test; }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_dst(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ dst : allow; }}
            dst {ip_version}.{protocol} : block {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_dst_ratelimit(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ dst : allow; }}
            ratelimit=test pps=0 bps=500;
            dst {ip_version}.{protocol} : ratelimit=test {{
                {server.ip_testing}:{server.port}
            }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_src_port(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ src_port : allow; }}
            src {ip_version}.{protocol} : block {{
                :{client.port}
            }}
        }}
        """)


@pytest.fixture
async def xfw_ratelimit_by_src_port(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=500;
            defaults {{ src_port : allow; }}
            src {ip_version}.{protocol} : ratelimit=test {{
                :{client.port}
            }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_src_port_defaults(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"xfw {{ defaults {{ src_port : block; }} }}")


@pytest.fixture
async def xfw_ratelimit_by_src_port_defaults(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=500;
            defaults {{ src_port : ratelimit=test; }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_src_ip(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ src_ip : allow; }}
            src {ip_version}.{protocol} : block {{
                {client.ip_testing}
            }}
        }}
        """)


@pytest.fixture
async def xfw_ratelimit_by_src_ip(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=500;
            defaults {{ src_ip : allow; }}
            src {ip_version}.{protocol} : ratelimit=test {{
                {client.ip_testing}
            }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_src_ip_defaults(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"xfw {{ defaults {{ src_ip : block; }} }}")


@pytest.fixture
async def xfw_ratelimit_by_src_ip_defaults(xfw, ip_version, protocol, client, server):
    await server.start()
    await client.start()

    await xfw.rules_set(f"""
        xfw {{ 
            ratelimit=test pps=0 bps=500;
            defaults {{ src_ip : ratelimit=test; }}
        }}
        """)


@pytest.fixture
async def xfw_blocked_by_tcp_anomaly_invalid_flags(xfw):
    await xfw.rules_set("xfw { tcp_anomaly_filter bad_flags(SYN+FIN); }")


@pytest.fixture
async def xfw_blocked_by_tcp_anomaly_invalid_syn_seq(xfw):
    await xfw.rules_set("xfw { tcp_anomaly_filter syn_with_seqno=0; }")


@pytest.fixture
async def xfw_blocked_by_tcp_anomaly_syn_without_options(xfw):
    await xfw.rules_set("xfw { tcp_anomaly_filter syn_without_opt; }")


@pytest.fixture
async def xfw_blocked_by_tcp_anomaly_syn_with_payload(xfw):
    await xfw.rules_set("xfw { tcp_anomaly_filter syn_with_payload; }")


@pytest.fixture
async def xfw_mtu(xfw):
    await xfw.set_mtu(4096)
    yield xfw
    await xfw.set_mtu()


@pytest.fixture
def xfw_setup(request):
    return request.getfixturevalue(request.param)


@pytest.fixture
async def invalid_l4_raw_client(config, logging_level):
    new_client = client_fabric(
        config=config,
        logging_level=logging_level,
        local_class=InvalidEthTypeRawClient,
        force_ip4=True,
    )
    yield new_client
    await new_client.stop()


@pytest.fixture
async def inverted_dns_server(dns_udp_client):
    dns_udp_client.port = 53
    dns_udp_client.remote_port = 50_000
    await dns_udp_client.start()
    yield dns_udp_client


@pytest.fixture
async def inverted_dns_server_mtu(inverted_dns_server):
    await inverted_dns_server.set_mtu(4096)
    yield inverted_dns_server
    await inverted_dns_server.set_mtu()


@pytest.fixture
async def inverted_dns_client(dns_udp_server, inverted_dns_server):
    await dns_udp_server.update_config(
        client_ip=inverted_dns_server.ip, client_port=inverted_dns_server.port, my_port=50_000
    )
    await dns_udp_server.set_mtu(4096)
    await dns_udp_server.start()
    yield dns_udp_server
