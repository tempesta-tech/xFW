# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from itertools import combinations

from framework.stateful import RegularKernelSocketNetworkStateful
from framework.asyn import TcpRawClient, TcpRawServer
from framework.xfw import XFW
from framework.utils import get_tcp_packet
from scapy.layers.inet import TCP


async def test_normal_connection(
        xfw: XFW,
        tcp_server: RegularKernelSocketNetworkStateful,
        tcp_raw_client: TcpRawClient,
        start_tcp_server_and_raw_clients
):
    await xfw.rules_set('xfw { tcp_anomaly_filter syn_without_opt'
                        ' syn_with_payload syn_with_seqno=0 bad_flags; }')

    assert await tcp_raw_client.handshake(get_tcp_packet(flag='S')) is True
    assert await tcp_raw_client.close_connection() is True


@pytest.mark.parametrize(
    'ok_packet, fail_packet, rules',
    [
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag='SF'),
            "xfw { tcp_anomaly_filter bad_flags(SYN+FIN); }",
            id='SF-flag',
        ),
        pytest.param(
            get_tcp_packet(flag='SA'),
            get_tcp_packet(flag='SFA'),
            "xfw { tcp_anomaly_filter bad_flags(SYN+FIN+ACK); }",
            id='SFA-flag',
        ),
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag=None),
            "xfw { tcp_anomaly_filter bad_flags(0); }",
            id='no-flags',
        ),
        pytest.param(
            get_tcp_packet(flag='A'),
            get_tcp_packet(flag='S'),
            "xfw { tcp_anomaly_filter bad_flags(SYN); }",
            id='syn-blocked',
        ),
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag='A'),
            "xfw { tcp_anomaly_filter bad_flags(ACK); }",
            id='ack-blocked',
        ),
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag='F'),
            "xfw { tcp_anomaly_filter bad_flags(FIN); }",
            id='fin-blocked',
        ),
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag='R'),
            "xfw { tcp_anomaly_filter bad_flags(RST); }",
            id='rst-blocked',
        ),
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag='P'),
            "xfw { tcp_anomaly_filter bad_flags(PSH); }",
            id='psh-blocked',
        ),
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag='U'),
            "xfw { tcp_anomaly_filter bad_flags(URG); }",
            id='urg-blocked',
        ),
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag='E'),
            "xfw { tcp_anomaly_filter bad_flags(ECE); }",
            id='ece-blocked',
        ),
        pytest.param(
            get_tcp_packet(flag='S'),
            get_tcp_packet(flag='C'),
            "xfw { tcp_anomaly_filter bad_flags(CWR); }",
            id='cwr-blocked',
        ),
        pytest.param(
            get_tcp_packet(flag='R'),
            get_tcp_packet(flag='S', payload=b'1'),
            "xfw { tcp_anomaly_filter syn_with_payload; }",
            id='SYN+payload'
        ),
        pytest.param(
            get_tcp_packet(flag='R'),
            get_tcp_packet(flag='SA', payload=b'1'),
            "xfw { tcp_anomaly_filter syn_with_payload; }",
            id='SYN-ACK+payload'
        ),
        pytest.param(
            get_tcp_packet(flag='R'),
            get_tcp_packet(flag='S',seq=0),
            "xfw { tcp_anomaly_filter syn_with_seqno=0; }",
            id='SYN+seq=0'
        ),
        pytest.param(
            get_tcp_packet(flag='R'),
            get_tcp_packet(flag='S', seq=100),
            "xfw { tcp_anomaly_filter syn_with_seqno=100; }",
            id='SYN+seq=100'
        ),
        pytest.param(
            get_tcp_packet(flag='R'),
            get_tcp_packet(flag='SA', seq=0),
            "xfw { tcp_anomaly_filter syn_with_seqno=0; }",
            id='SYN-ACK+seq=0'
        ),
        pytest.param(
            get_tcp_packet(flag='R'),
            get_tcp_packet(flag='S',options=[]),
            "xfw { tcp_anomaly_filter syn_without_opt; }",
            id='empty-options'
        )
    ],
)
async def test_block_invalid_packet(
        ok_packet: TCP,
        fail_packet: TCP,
        rules: str,
        xfw: XFW,
        tcp_raw_server: TcpRawServer,
        tcp_raw_client: TcpRawClient,
        start_tcp_raw_server_and_raw_clients,
):
    await xfw.rules_set(rules)

    await tcp_raw_client.send(fail_packet)
    response = await tcp_raw_server.receive_packet()
    assert response is None, f'Broken packet {fail_packet} is not blocked'

    await tcp_raw_client.send(ok_packet)
    response = await tcp_raw_server.receive_packet()
    assert response is not None, f'Ok packet {ok_packet} is blocked'


@pytest.mark.parametrize(
    'port_type',
    ['sport', 'dport'],
    ids=['src', 'dst']
)
async def test_zero_port_is_blocked(
        port_type: str,
        xfw: XFW,
        tcp_raw_server: TcpRawServer,
        tcp_raw_client: TcpRawClient,
        start_tcp_raw_server_and_raw_clients
):
    tcp_raw_client.auto_add_host = False

    packet = get_tcp_packet(flag='S')
    packet.sport = tcp_raw_client.port
    packet.dport = tcp_raw_server.port

    setattr(packet, port_type, 0)

    await xfw.rules_set('xfw { tcp_anomaly_filter syn_without_opt'
                        ' syn_with_payload syn_with_seqno=0 bad_flags; }')
    await tcp_raw_client.send(packet)

    response = await tcp_raw_server.receive_packet()
    assert response is None, f'Zero {port_type} port is not blocked'


@pytest.mark.parametrize(
    'rules, valid_flags',
    [
        pytest.param(
            'xfw { tcp_anomaly_filter; }',
            {
                "F", "S", "R", "P", "A", "U", "FP", "AF", "FU", "PS", "AS", "SU", "PR",
                "AR", "RU", "AP", "PU", "AU", "AFP", "FPU", "AFU", "APS", "PSU", "ASU",
                "APR", "PRU", "APU", "ARU", "APU", "AFPU", "APSU", "APRU"
            },
            id='default'
        ),
        pytest.param(
            'xfw { tcp_anomaly_filter bad_flags; }',
            {"S", "R", "P", "A", "U", "FP", "AF", "FU", "AS", "AR", "AP", "PU", "AU", "AFP", "AFU", "APU"},
            id='bad_flags'
        )
    ]
)
async def test_blocked_invalid_flags(
        rules: str,
        valid_flags: set[str],
        xfw: XFW,
        tcp_raw_server: TcpRawServer,
        tcp_raw_client: TcpRawClient,
        start_tcp_raw_server_and_raw_clients
):
    all_flags = ["F", "S", "R", "P", "A", "U"]
    possible_flags = []
    all_not_blocked = []

    for r in range(1, len(all_flags) + 1):
        possible_flags.extend(["".join(sorted(comb)) for comb in combinations(all_flags, r)])

    invalid_flags = [flags for flags in possible_flags if flags not in valid_flags]

    await xfw.rules_set(rules)

    for invalid_flag in invalid_flags:
        packet = get_tcp_packet(flag=invalid_flag)
        await tcp_raw_client.send(packet)

        response = await tcp_raw_server.receive_packet()

        if response is None:
            continue

        if str(packet.flags) != response:
            continue

        all_not_blocked.append(response)

    assert not all_not_blocked, f'Flags {all_not_blocked} are not blocked'


async def test_bad_flags_overriding(
        xfw: XFW,
        tcp_raw_server: TcpRawServer,
        tcp_raw_client: TcpRawClient,
        start_tcp_raw_server_and_raw_clients
):
    await xfw.rules_set('xfw { tcp_anomaly_filter bad_flags; }')

    default_blocking_packet = get_tcp_packet(flag='SP')
    await tcp_raw_client.send(default_blocking_packet)
    assert await tcp_raw_server.receive_packet() is None, \
        'The default bad packet is not blocked'

    await xfw.rules_set('xfw { tcp_anomaly_filter bad_flags(RST+PSH); }')

    await tcp_raw_client.send(default_blocking_packet)
    assert await tcp_raw_server.receive_packet() is not None, \
        'The default bad packet should not be blocked as default list of bad flags is override'


async def test_delete_filter(
        xfw: XFW,
        tcp_raw_server: TcpRawServer,
        tcp_raw_client: TcpRawClient,
        start_tcp_raw_server_and_raw_clients
):
    broken_packet = get_tcp_packet(flag='SF')
    await xfw.rules_set('xfw { tcp_anomaly_filter; }')

    await tcp_raw_client.send(broken_packet)
    response = await tcp_raw_server.receive_packet()
    assert response is None, f'Broken packet {broken_packet} is not blocked'

    await xfw.rules_patch('xfw { tcp_anomaly_filter/del; }')

    await tcp_raw_client.send(broken_packet)
    response = await tcp_raw_server.receive_packet()
    assert response is not None, f'Broken packet {broken_packet} is blocked again, but filter is deleted'