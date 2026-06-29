# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import os.path
import pytest
from datetime import datetime, timezone

from framework.asyn import UdpServer, UdpClient
from framework.clickhouse import ClickhouseClient
from framework.xfw import XFW
from framework.cmp import check_connection
from framework.utils import client_cloner


@pytest.mark.clickhouse
async def test_table_created_after_xfw_startup(
        xfw: XFW,
        clickhouse_client: ClickhouseClient
):
    await xfw.stop()
    await clickhouse_client.connect()

    await clickhouse_client.table_drop()
    assert await clickhouse_client.table_exists() is False

    await xfw.start()
    assert await clickhouse_client.table_exists() is True


@pytest.mark.clickhouse
async def test_log_file_created(xfw: XFW):
    await xfw.stop()

    if os.path.exists(xfw.tfw_logger_log_file):
        os.remove(xfw.tfw_logger_log_file)

    await xfw.start()
    assert os.path.exists(xfw.tfw_logger_log_file) is True

    with open(xfw.tfw_logger_log_file, 'r') as f:
        data = f.read()

    assert 'Starting Tempesta FW Logger' in data
    assert 'IncidentLogProcessor started. Timer interval' in data

    await xfw.stop()

    with open(xfw.tfw_logger_log_file, 'r') as f:
        data = f.read()

    assert 'Tempesta FW Logger stopped' in data
    assert 'PID file removed' in data


@pytest.mark.clickhouse
async def test_log_data_time_correctness(
        xfw: XFW,
        clickhouse_client: ClickhouseClient,
        ip_version: str,
        udp_client: UdpClient,
        udp_server: UdpServer,
):
    await udp_server.start()
    await udp_client.start()
    await clickhouse_client.connect()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ dst: allow; }} 
            dst {ip_version}.udp : block {{
                {udp_server.ip_testing}:{udp_server.port}
            }}
        }}
    """)

    time_before = datetime.now(tz=timezone.utc)

    assert await check_connection(udp_client, udp_server) is False, \
        'Request is not blocked'

    await clickhouse_client.wait_for_number_of_records(expected_records_n=1)
    time_after = datetime.now(tz=timezone.utc)

    db_records = await clickhouse_client.records_all()

    record = db_records[0]

    if record.timestamp.tzinfo is None:
        record.timestamp = record.timestamp.replace(tzinfo=timezone.utc)

    record_time = record.timestamp.astimezone(tz=timezone.utc)
    assert time_before <= record_time
    assert record_time <= time_after


@pytest.mark.clickhouse
async def test_log_data_counter_correctness(
        xfw: XFW,
        clickhouse_client: ClickhouseClient,
        ip_version: str,
        udp_server: UdpServer,
        udp_client: UdpClient,
):
    await udp_server.start()
    await udp_client.start()
    await clickhouse_client.connect()

    await xfw.rules_set(f"""
        xfw {{ 
            defaults {{ dst: allow; }} 
            dst {ip_version}.udp : block {{
                {udp_server.ip_testing}:{udp_server.port}
            }}
        }}
    """)

    await udp_client.send('0123456789')
    assert await udp_server.receive() is None

    await clickhouse_client.wait_for_number_of_records(expected_records_n=1)
    db_records = await clickhouse_client.records_all()

    packet_size = 52 if ip_version == "ip4" else 72 # packet size for UDP
    for record in db_records:
        assert record.reason == 128
        assert record.bytes == record.packets * packet_size
        assert record.dropped_events == 0


@pytest.mark.clickhouse
async def test_multiple_requests_logs(
        xfw: XFW,
        clickhouse_client: ClickhouseClient,
        udp_ip4_client: UdpClient,
        udp_ip4_server: UdpServer,
):
    await clickhouse_client.connect()
    await udp_ip4_server.start()

    clients = client_cloner(
        client=udp_ip4_client,
        amount=10
    )
    for client in clients:
        await client.start()

    await xfw.rules_set(
        f"""
        xfw {{ 
            defaults {{ dst: allow; }} 
            dst ip4.udp : block {{
                {udp_ip4_server.ip_testing}:{udp_ip4_server.port}
            }}
        }}
        """
    )

    results = await asyncio.gather(*[
        check_connection(client, udp_ip4_client)
        for client in clients
    ])

    assert not any(results)
    await clickhouse_client.wait_for_number_of_records(expected_records_n=10)
    records = await clickhouse_client.records_all()

    clients_ips = {client.ipv4 for client in clients}
    blocked_ips = {str(record.address.ipv4_mapped) for record in records}
    diff = clients_ips - blocked_ips
    assert diff == set(), f'Not all blocked clients where appeared in the db: {diff}'
