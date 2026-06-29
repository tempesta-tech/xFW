# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from framework.stateful import NetworkStateful


class TrafficReplayClient(NetworkStateful):
    def __init__(
            self,
            *args,
            tcpreplay_exec_file: str,
            tcprewrite_exec_file: str,
            pcap_prepared_out_file: str = '/tmp/ddos.pcapng',
            **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.tcpreplay_exec_file = tcpreplay_exec_file
        self.tcprewrite_exec_file = tcprewrite_exec_file
        self.pcap_prepared_out_file = pcap_prepared_out_file

    async def run_start(self):
        code, _, stderr = await self.run_host_cmd(f'{self.tcpreplay_exec_file} --help')

        if code:
            raise RuntimeError(f'{self.tcpreplay_exec_file} is not available: {stderr}')

        code, _, stderr = await self.run_host_cmd(f'{self.tcprewrite_exec_file} --help')

        if code:
            raise RuntimeError(f'{self.tcprewrite_exec_file} is not available: {stderr}')

    async def run_stop(self):
        ...

    async def prepare_pcap(
            self,
            file_path: str,
            dst_original_ip: str,
            dst_original_port: str = None,
            dst_rewrote_port: int = None
    ):
        cmd = (
            f'{self.tcprewrite_exec_file} --infile={file_path} '
            f'--outfile={self.pcap_prepared_out_file} '
            f'--dstipmap={dst_original_ip}:{self.remote_ip} '
        )

        if dst_original_port is not None and dst_rewrote_port is not None:
            cmd += f'--portmap={dst_original_port}:{dst_rewrote_port} '

        code, _, stderr = await self.run_host_cmd(cmd=cmd)

        if code:
            raise RuntimeError(f'Can not rewrite pcap file ({file_path}): {stderr}')

        return self.pcap_prepared_out_file

    async def replay_pcap(
            self,
            file_path: str,
            packets_per_second: int = 10
    ):
        code, _ , stderr = await self.run_host_cmd(
            cmd=(
                f'{self.tcpreplay_exec_file} '
                f'--intf1={self.network_interface} '
                f'--pps={packets_per_second} '
                f'{file_path}'
            )
        )
