# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import hashlib
import os.path
import typing

import httpx
from contextlib import asynccontextmanager
from typing import Optional

from framework.stateful import State, NetworkStateful
from framework.utils import (
    run_cmd,
    retry_on_failure,
    RetryException,
)
from framework.remote import RemoteServer
from framework.clickhouse import ClickhouseClient


class XFW(NetworkStateful):
    def __init__(
            self,
            build_dir: str,
            *args,
            http_port: int = None,
            path_to_config: str = None,
            geolite2_db_path: str = None,
            server_iface: str = None,
            tfw_logger_config_file: str = None,
            xfw_logger_log_file: str = None,
            xfw_manager_log_file: str = None,
            tfw_logger_max_events: int = 1000,
            tfw_logger_max_wait_ms: int = 100,
            clickhouse_client: ClickhouseClient = None,
            devices_mode: typing.Literal['native', 'skb'] = 'skb',
            retry_daemon_start: bool = True,
            **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.build_dir = build_dir
        self.http_port = http_port
        self.path_to_config = path_to_config
        self.geolite2_db_path = geolite2_db_path
        self.server_iface = server_iface
        self.process = None
        self.rules_config_path = '/tmp/config'
        self.tfw_logger_max_events = tfw_logger_max_events
        self.tfw_logger_max_wait_ms = tfw_logger_max_wait_ms
        self.tfw_logger_config_file = tfw_logger_config_file
        self.tfw_logger_log_file = xfw_logger_log_file
        self.xfw_manager_log_file = xfw_manager_log_file
        self.clickhouse_client = clickhouse_client
        self.devices_mode = devices_mode
        self.retry_daemon_start = retry_daemon_start

        self.__config: Optional[str] = None

    @property
    def xfw_logger_config(self):
        conf = f"""
        {{
            "log_path": "{self.tfw_logger_log_file}",
            "xfw_events": {{
                "plugin_path": "{self.build_dir}/lib/incident_log.so",
                "host": "{self.clickhouse_client.host}",
                "port": {self.clickhouse_client.binary_port},
                "user": "{self.clickhouse_client.user}",
                "password": "{self.clickhouse_client.password}",
                "db_name": "{self.clickhouse_client.database}",
                "table_name": "{self.clickhouse_client.table}",
                "max_events": {self.tfw_logger_max_events},
                "max_wait_ms": {self.tfw_logger_max_wait_ms}
            }}
        }}
        """

        return conf

    @property
    def config(self):
        if self.__config:
            return self.__config

        daemon_args = f"--listen {self.ipv4} --port {self.port} --http-port {self.http_port}"

        if self.geolite2_db_path:
            daemon_args += f" --geoip {self.geolite2_db_path}"

        if self.xfw_manager_log_file:
            daemon_args += f" -L {self.xfw_manager_log_file}"

        conf = f"""
        {{
            "devices": "{self.network_interface}",
            "devices-mode": "{self.devices_mode}",
            "verbose": true,
            "mgr-args": "{daemon_args}"
        }}
        """

        return conf

    @config.setter
    def config(self, value):
        self.__config = value

    @property
    def path_to_executable(self) -> str:
        return self._with_tmp_config(f'{self.build_dir}/bin/xfwctl')

    async def status(self):
        code, stdout, stderr = await run_cmd(
            cmd=f'{self.path_to_executable} --status',
            logger=self.logger,
            wait_for_result=True,
            log_output=True
        )
        assert code == 0, f'Failed to get status (exit code: {code}): {stderr}\nStdout: {stdout}'

    @retry_on_failure(RetryException)
    async def wait_for_iface_ready(self):
        code, _, stderr = await run_cmd(
            cmd=f'ip -br a show {self.server_iface}',
            logger=self.logger
        )

        if not code:
            self.logger.debug(f'iface {self.server_iface} is ready')
            return None

        if (
                'Cannot find device' not in stderr
                and 'does not exist' not in stderr
                and 'Timeout' not in stderr
        ):
            raise OSError(f'Device is not ready: {stderr}')

        raise RetryException(f'iface {self.server_iface} is not ready')

    async def wait_for_daemon_started_once(self, cleanup_on_loaded_programs: bool = False):
        code, _, stderr = await run_cmd(
            cmd=f'{self.path_to_executable} --start',
            logger=self.logger,
            log_output=True
        )

        if not code:
            return

        if 'Some eBPF programs are still loaded' in stderr:
            self.logger.warning('detected not correctly stopped app')
            if cleanup_on_loaded_programs:
                await self._stop_daemon()
            raise RetryException(f'app is not stopped correctly')

        raise RetryException(f'daemon {self.network_interface} is not started. Error: {stderr}')

    @retry_on_failure(RetryException)
    async def wait_for_daemon_started(self):
        await self.wait_for_daemon_started_once(cleanup_on_loaded_programs=True)

    @retry_on_failure(RetryException)
    async def wait_for_daemon_stop(self):
        code, _, stderr = await run_cmd(
            cmd=f"{self.path_to_executable} --stop",
            logger=self.logger,
            log_output=True
        )

        if not code:
            return

        raise RetryException(f'daemon {self.network_interface} is not started. Error: {stderr}')

    @retry_on_failure(RetryException, max_time=20)
    async def wait_for_grpc_connection_ready(self, ip: str, port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=ip, port=port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            self.logger.debug(f'available on {ip}:{port}')
            return True

        except Exception as e:
            raise RetryException(f'error while connection establishing on {ip}:{port}: {e}') from e

    def _with_tmp_config(self, cmd: str) -> str:
        if not self.path_to_config:
            return cmd

        return f'TFW_CFG_FILE={self.path_to_config} TFW_LOG_CFG_FILE={self.tfw_logger_config_file} {cmd}'

    async def _start_daemon(self):
        await self.wait_for_iface_ready()
        if self.retry_daemon_start:
            await self.wait_for_daemon_started()
        else:
            await self.wait_for_daemon_started_once()
        await self.wait_for_grpc_connection_ready(self.ipv4, self.port)
        self.logger.debug('daemon started')

    async def _stop_daemon(self):
        await self.wait_for_iface_ready()
        await self.wait_for_daemon_stop()
        self.logger.debug('daemon stopped')

    async def run_stop(self):
        await self._stop_daemon()
        self._state = State.stopped

    @staticmethod
    def write_config(file_path: str, content: str):
        config_dir = os.path.dirname(file_path)

        if not os.path.exists(config_dir):
            os.makedirs(config_dir)

        with open(file_path, 'w') as f:
            f.write(content)

    async def set_host(self, ipv4: str = None, ipv6: str = None, port: int = None, iface: str = None):
        await super().set_host(ipv4, ipv6, port, iface=self.server_iface)

    async def run_start(self):
        self.logger.info(f'starting on {self.ip}:{self.port}')

        self.write_config(
            file_path=self.path_to_config,
            content=self.config
        )
        self.write_config(
            file_path=self.tfw_logger_config_file,
            content=self.xfw_logger_config
        )
        await self._start_daemon()

        self._state = State.started

    async def restart_daemon(self):
        code, _, stderr = await run_cmd(
            cmd=f"{self.path_to_executable} --restart",
            logger=self.logger,
            log_output=True
        )

        if code:
            raise RuntimeError(f'Can not restart daemon: {stderr}')

    async def __rules_push(self, cmd: str):
        code, stdout, stderr = await run_cmd(
            cmd=f'LD_LIBRARY_PATH={self.build_dir}/lib  ./bin/tfw push '
                f'--server={self.ipv4} '
                f'--port={self.port} '
                f'{cmd}',
            logger=self.logger,
            cwd=self.build_dir,
	        log_output=True
        )

        if code != 0:
            raise ValueError(f'{stdout}\n{stderr}')

    async def rules_push_config(self, new_rules: str, param: str = '--conf'):
        with open(self.rules_config_path, 'w') as f:
            f.write(new_rules)

        self.logger.info(f'push rules: {new_rules}')
        await self.__rules_push(f'{param} {self.rules_config_path}')

    async def rules_push_config_short(self, new_rules: str):
        return await self.rules_push_config(new_rules, param='-c')

    async def rules_push_config_inline(self, new_rules: str):
        self.logger.info(f'push rules: {new_rules}')
        await self.__rules_push(f'--conf-inline "{new_rules}"')

    async def rules_push_patch(self, new_rules: str, param: str = '--patch'):
        with open(self.rules_config_path, 'w') as f:
            f.write(new_rules)

        self.logger.info(f'push rules: {new_rules}')
        await self.__rules_push(f'{param} {self.rules_config_path}')

    async def rules_push_patch_short(self, new_rules: str):
        return await self.rules_push_patch(new_rules, param='-P')

    async def rules_push_patch_inline(self, new_rules: str):
        self.logger.info(f'push rules: {new_rules}')
        await self.__rules_push(f'--patch-inline "{new_rules}"')

    def __add_to_rules_net_directive(self, rules: str, ip4: str = None, ip6: str = None):
        ip_version = 'ip4' if ip4 else 'ip6'
        ip = ip4 or ip6
        additional_directive = f' net { ip_version } {{ {ip} }} '

        if 'net' in rules:
            self.logger.warning('The NET directive already exists')
            return rules

        hash_sum_before = hashlib.sha1(rules.encode())
        rules = rules.replace('xfw {', f'xfw {{ {additional_directive}')
        hash_sub_after = hashlib.sha1(rules.encode())

        if hash_sum_before.hexdigest() != hash_sub_after.hexdigest():
            return rules

        self.logger.debug(f'Updated rule: {rules}')
        raise ValueError(
            'NET directive was not inserted, please check the original rule'
            ' and made necessary changes'
        )

    async def rules_set(self, new_rules: str) -> None:
        return await self.rules_push_config(new_rules)

    async def rules_patch(self, new_rules: str) -> None:
        return await self.rules_push_patch(new_rules)

    def http_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=f'http://{self.ip}:{self.http_port}',
        )

    @staticmethod
    async def wait_softirq():
        """
        There is a huge time lag if TCP client sends packets
        with the same packet ACK
        """
        await asyncio.sleep(3)

    async def metrics(self) -> dict[str, int]:
        client = self.http_client()
        response = await client.get('/metrics')

        if response.status_code != 200:
            raise ValueError('Failed to get metrics')

        metrics = {}

        for metric in response.text.split('\n'):
            if metric.startswith('#'):
                continue

            pair = metric.split(' ')

            if len(pair) != 2:
                continue

            key, value = pair
            metrics[key] = int(value)

        return metrics

    @asynccontextmanager
    async def metrics_diff(
            self,
            metrics: list[str] = None,
            wait_softirq: bool = False,
            non_zero: bool = False
    ) -> dict[str, int]:
        metrics_before = await self.metrics()

        if metrics:
            diff = {metric: 0 for metric in metrics}
        else:
            diff = {}
            metrics = set(metrics_before.keys())

        yield diff

        if wait_softirq:
            await self.wait_softirq()

        metrics_after = await self.metrics()

        for metric in metrics:
            metric_delta = metrics_after[metric] - metrics_before[metric]

            if non_zero and not metric_delta:
                continue

            diff[metric] = metric_delta

    async def set_http_port(self, port: int):
        self.http_port = port

    async def set_config(self, new_config: str):
        self.config = new_config

    async def syncookies_read_stats(self) -> tuple[int, int, int]:
        """
        Return values of SyncookieSent, SyncookieRecv, SyncookieFailed
        """
        code, stats, _ = await run_cmd(
            cmd="cat /proc/net/netstat | grep -A1 Syncookie | tail -n 1 | awk '{print $2, $3, $4}'",
            logger=self.logger,
        )
        assert code == 0, 'Can not read netstat'

        return tuple((int(stat.strip()) for stat in stats.split(' ')))

    async def syncookies_value_get(self) -> int:
        code, stdout, stderr = await run_cmd(
            cmd='sysctl -n net.ipv4.tcp_syncookies',
            logger=self.logger,
        )

        assert code == 0, f'Failed to read IPv4 syncookies mode: {stderr}'

        return int(stdout.strip())

    async def syncookies_value_set(self, value: int) -> int:
        # also works for ipv6
        code, _, stderr = await run_cmd(
            cmd=f'sysctl -w net.ipv4.tcp_syncookies={value}',
            logger=self.logger,
        )

        assert code == 0, f'Failed to restore IPv4 syncookies mode: {stderr}'

    async def syncookies_always(self):
        await self.syncookies_value_set(2)

    async def syncookies_never(self):
        await self.syncookies_value_set(0)

    async def set_mtu(self, size: int = 1500) -> None:
        ifaces = [iface.strip() for iface in self.network_interface.split(' ')]

        for iface in ifaces:
            code, _, stderr = await self.run_host_cmd(
                cmd=f"ip link set {iface} mtu {size}")
            assert code == 0, f'Can not set MTU: {stderr}'

            self.logger.info(f'MTU changed to {size}')


class XFWRemote(RemoteServer, XFW):
    remote_methods = [
        'start',
        'stop',
        'restart',
        'rules_set',
        'rules_push_config',
        'rules_push_config_short',
        'rules_push_config_inline',
        'rules_push_patch',
        'rules_push_patch_short',
        'rules_push_patch_inline',
        'set_http_port',
        'set_config',
        'syncookies_read_stats',
        'set_mtu',
    ]

    def __init__(self, *args, **kwargs) -> None:
        RemoteServer.__init__(self, *args, **kwargs)
        XFW.__init__(self, *args, **kwargs)
