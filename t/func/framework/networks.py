# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import abc
import asyncio
import logging
import os
import shutil
from ipaddress import ip_network

from config import ConfigSettings
from framework.utils import run_cmd


class BaseNetwork:
    def __init__(self, logger: logging.Logger, config: ConfigSettings):
        self.logger = logger
        self.config = config
        self._rto_min_suffix = "rto_min 5000"  # ms

    @abc.abstractmethod
    async def prepare(self):
        """
        Create a new network
        """

    @abc.abstractmethod
    async def destroy(self):
        """
        Clean up the created network
        """


class LocalVeth(BaseNetwork):
    @staticmethod
    def _with_netns(cmd: str, namespace: str = None) -> str:
        if namespace:
            return f"ip netns exec {namespace} {cmd}"

        return cmd

    async def _force_ipv6_neighbor_update(self, ipv6: str, namespace: str = None):
        code, _, stderr = await run_cmd(
            cmd=self._with_netns(cmd=f"ping6 -c 1 {ipv6}", namespace=namespace),
            logger=self.logger,
        )
        assert code == 0, f"Could not update ipv6 neighbor: {stderr}"

    async def create_links(self, link_from: str, link_to: str):
        code, _, stderr = await run_cmd(
            cmd=f"ip link add {link_from} type veth peer {link_to}",
            logger=self.logger,
        )
        assert code == 0 or "File exists" in stderr, f"Could not create veth peer: {stderr}"

    async def _create_namespace(self, name: str):
        code, _, stderr = await run_cmd(
            cmd=f"ip netns add {name}",
            logger=self.logger,
        )
        assert code == 0 or "File exists" in stderr, f"Could not create namespace: {stderr}"

        await asyncio.sleep(1)

    async def _move_iface_into_namespace(self, iface: str, namespace: str):
        code, _, stderr = await run_cmd(
            cmd=f"ip link set {iface} netns {namespace}",
            logger=self.logger,
        )
        assert code == 0, f"Could not move clients iface into namespace: {stderr}"

    async def _turn_on_iface(self, name: str, namespace: str = None):
        code, *_ = await run_cmd(
            cmd=self._with_netns(f"ip link set {name} up", namespace), logger=self.logger
        )
        assert code == 0, f"Could not bring link up {_}"

    async def _turn_off_offload_on_iface(self, iface: str):
        code, *_ = await run_cmd(
            cmd=f"ethtool --offload {iface} rx off tx off",
            logger=self.logger,
        )
        assert code == 0, f"Could not turn off rx tx offloading {_}"

    async def _iface_add_addr(self, iface: str, ip4: str, ip6: str, namespace: str = None):
        code, _, stderr = await run_cmd(
            cmd=self._with_netns(
                cmd=f"ip addr add {ip4}/24 dev {iface}",
                namespace=namespace,
            ),
            logger=self.logger,
        )
        assert code == 0, f"Could assign new ip4 address  {stderr}"

        code, _, stderr = await run_cmd(
            cmd=self._with_netns(
                cmd=f"ip -6 addr add {ip6}/64 dev {iface} nodad",
                namespace=namespace,
            ),
            logger=self.logger,
        )
        assert code == 0, f"Could assign new ip6 address  {stderr}"

    async def _add_default_route(self, iface: str, ip4: str, ip6: str, namespace: str = None):
        code, _, stderr = await run_cmd(
            cmd=self._with_netns(
                cmd=f"ip route replace default via {ip4} dev {iface} {self._rto_min_suffix}",
                namespace=namespace,
            ),
            logger=self.logger,
        )

        assert code == 0, f"Could not replace default ip4 route: {stderr}"

        code, _, stderr = await run_cmd(
            cmd=self._with_netns(
                cmd=f"ip -6 route replace default via {ip6} dev {iface} {self._rto_min_suffix}",
                namespace=namespace,
            ),
            logger=self.logger,
        )
        assert code == 0, f"Could not replace default ip6 route: {stderr}"

    async def _add_route(
        self,
        iface: str,
        ip4_address_to: str,
        ip4_address_mask: int,
        ip6_address_to: str = None,
        ip6_address_mask: int = None,
        namespace: str = None,
    ):
        net = ip_network(f"{ip4_address_to}/{ip4_address_mask}", strict=False)

        code, _, stderr = await run_cmd(
            cmd=self._with_netns(
                cmd=(
                    f"ip route replace {net.network_address}/{ip4_address_mask}"
                    f" dev {iface} {self._rto_min_suffix}"
                ),
                namespace=namespace,
            ),
            logger=self.logger,
        )
        assert code == 0, f"Could not add ip4 route: {stderr}"

        if not ip6_address_to:
            return

        net6 = ip_network(f"{ip6_address_to}/{ip6_address_mask}", strict=False)
        code, _, stderr = await run_cmd(
            cmd=self._with_netns(
                cmd=(
                    f"ip -6 route replace {net6.network_address}/{ip6_address_mask}"
                    f" dev {iface} {self._rto_min_suffix}"
                ),
                namespace=namespace,
            ),
            logger=self.logger,
        )
        assert code == 0, f"Could not add ip6 route: {stderr}"

    async def _add_route_via(
        self,
        iface: str,
        ip4_address_to: str,
        ip4_address_via: str,
        ip6_address_to: str,
        ip6_address_via: str,
        namespace: str = None,
        onlink: bool = False,
    ):
        cmd_end = " onlink" if onlink else ""
        code, _, stderr = await run_cmd(
            cmd=self._with_netns(
                cmd=(
                    f"ip route replace {ip4_address_to} via {ip4_address_via}"
                    f" dev {iface} {cmd_end} {self._rto_min_suffix}"
                ),
                namespace=namespace,
            ),
            logger=self.logger,
        )
        assert code == 0, f"Could not replace default ip4 route: {stderr}"

        code, _, stderr = await run_cmd(
            cmd=self._with_netns(
                cmd=(
                    f"ip -6 route replace {ip6_address_to} via {ip6_address_via} "
                    f"dev {iface} {cmd_end} {self._rto_min_suffix}"
                ),
                namespace=namespace,
            ),
            logger=self.logger,
        )
        assert code == 0, f"Could not replace default ip6 route: {stderr}"

    async def _sysctl_settings(self):
        code, _, stderr = await run_cmd(
            cmd="sysctl -w net.ipv4.conf.xfw0.rp_filter=0",
            logger=self.logger,
        )

    async def _additional_clean(self):
        dirs_to_del = ["/sys/fs/bpf/tc/", "/sys/fs/bpf/xdp/"]
        files_to_del = ["/var/run/tempesta_mgr.pid"]
        for path in dirs_to_del:
            if not os.path.exists(path):
                continue

            shutil.rmtree(path)
            self.logger.debug(f"removed {path}")

        self.logger.debug("removed bpf files")

        for path in files_to_del:
            if not os.path.exists(path):
                continue

            os.remove(path)
            self.logger.debug(f"removed {path}")

    async def wait_until_removed(self, retry: int = 0, interval: float = 0.1, times: int = 100):
        code, *_ = await run_cmd(
            cmd=f"ip netns exec {self.config.client_namespace} ip a show {self.config.client_interface}",
            logger=self.logger,
        )

        if code:
            return

        retry += 1

        if retry >= times:
            raise SystemError("Netns still exists")

        self.logger.debug("NETNS is still exists")
        return await self.wait_until_removed(retry=retry, interval=interval, times=times)

    async def _delete_namespace(self, name: str, strict: bool = True):
        code, *_ = await run_cmd(
            cmd=f"ip netns delete {name}",
            logger=self.logger,
        )
        await self.wait_until_removed()

        if strict:
            assert code == 0, f"Could not remove netns: {_}"
        else:
            assert code in {0, 1}, f"Could not remove netns: {_}"

    async def prepare(self):
        await self.create_links(
            link_from=self.config.client_interface, link_to=self.config.backend_interface
        )
        await self._create_namespace(name=self.config.client_namespace)
        await self._move_iface_into_namespace(
            iface=self.config.client_interface, namespace=self.config.client_namespace
        )
        await self._turn_on_iface(
            name=self.config.client_interface, namespace=self.config.client_namespace
        )
        await self._turn_on_iface(name=self.config.backend_interface)
        await self._turn_off_offload_on_iface(iface=self.config.backend_interface)

        await self._iface_add_addr(
            iface=self.config.backend_interface,
            ip4=self.config.backend_ipv4,
            ip6=self.config.backend_ipv6,
        )
        await self._iface_add_addr(
            iface=self.config.backend_interface,
            ip4=self.config.backend_ipv4_host,
            ip6=self.config.backend_ipv6_host,
        )

        await self._iface_add_addr(
            iface=self.config.client_interface,
            ip4=self.config.client_ipv4_host,
            ip6=self.config.client_ipv6_host,
            namespace=self.config.client_namespace,
        )
        await self._iface_add_addr(
            iface=self.config.client_interface,
            ip4=self.config.client_ipv4,
            ip6=self.config.client_ipv6,
            namespace=self.config.client_namespace,
        )

        await self._add_route(
            iface=self.config.backend_interface,
            ip4_address_to=self.config.client_ipv4,
            ip4_address_mask=self.config.client_ipv4_mask,
            ip6_address_to=self.config.client_ipv6,
            ip6_address_mask=self.config.client_ipv6_mask,
        )
        await self._add_route(
            iface=self.config.client_interface,
            ip4_address_to=self.config.backend_ipv4,
            ip4_address_mask=self.config.backend_ipv4_mask,
            ip6_address_to=self.config.backend_ipv6,
            ip6_address_mask=self.config.backend_ipv6_mask,
            namespace=self.config.client_namespace,
        )
        # await self._turn_off_offload_on_servers_iface()
        # await self._turn_off_offload_on_clients_iface()

    async def destroy(self):
        await self._delete_namespace(name=self.config.client_namespace)

    async def flush_arp_cache(self, namespace: str) -> None:
        """
        Resets (clears) the IPv4 and IPv6 neighbor tables inside the specified namespace.

        - 'ip neigh flush all' — deletes all ARP (IPv4) entries.
        - 'ip -6 neigh flush all' — deletes all Neighbor Discovery (IPv6) entries.

        This forces the OS to redefine MAC addresses at the first opportunity.
        when trying to contact a neighboring node in a new test.
        """
        await asyncio.gather(
            run_cmd(
                cmd=self._with_netns(cmd="ip neigh flush all", namespace=namespace),
                logger=self.logger,
            ),
            run_cmd(
                cmd=self._with_netns(cmd="ip -6 neigh flush all", namespace=namespace),
                logger=self.logger,
            ),
        )


class LocalGateVeth(LocalVeth):

    async def _toggle_ip_forwarding(self, turn_on: bool = True):
        forward = 1

        if not turn_on:
            forward = 0

        code, _, stderr = await run_cmd(
            cmd=f"sysctl -w net.ipv4.ip_forward={forward}",
            logger=self.logger,
        )
        assert code == 0, f"Could set ip4 forwarding = {forward}: {stderr}"

        code, _, stderr = await run_cmd(
            cmd=f"sysctl -w net.ipv6.conf.all.forwarding={forward}",
            logger=self.logger,
        )
        assert code == 0, f"Could not set ip6 forwarding={forward}: {stderr}"

    async def _nft_table_prepare(
        self,
        table_name: str,
        table_path: str,
        client_iface: str,
        backend_iface: str,
    ):
        nft_config = "\n".join(
            [
                "#!/usr/sbin/nft -f",
                "table inet {table_name} {{".format(table_name=table_name),
                "   chain input {",
                "        type filter hook input priority 0; policy accept;",
                "        counter accept;",
                "   }",
                "   chain output {",
                "        type filter hook output priority 0; policy accept;",
                "        counter accept;",
                "   }",
                "   chain forward {",
                "        type filter hook forward priority 0; policy drop;",
                "        ip6 nexthdr udp ct state { new, invalid } accept;",
                '        iifname "{client_iface}" oifname "{backend_iface}" counter accept;'.format(
                    client_iface=client_iface, backend_iface=backend_iface
                ),
                '        iifname "{backend_iface}" oifname "{client_iface}" counter accept;'.format(
                    client_iface=client_iface, backend_iface=backend_iface
                ),
                "   }",
                "   chain prerouting {",
                "        type filter hook prerouting priority mangle; policy accept;",
                "        ip6 nexthdr udp ct state { new, invalid } accept;",
                "   }",
                "}",
            ]
        )
        with open(table_path, "w") as f:
            f.write(nft_config)

        code, _, stderr = await run_cmd(
            cmd=f"nft -f {table_path}",
            logger=self.logger,
        )
        assert code == 0, f"Could not prepare nft table: {stderr}"

    async def _nft_table_delete(self, name: str):
        code, _, stderr = await run_cmd(
            cmd=f"nft delete table inet {name}",
            logger=self.logger,
        )
        assert code == 0, f"Could not delete nft table: {stderr}"

    async def prepare(self):
        # create link
        await self.create_links(
            link_from=self.config.client_interface_host, link_to=self.config.client_interface
        )
        await self.create_links(
            link_from=self.config.backend_interface_host, link_to=self.config.backend_interface
        )

        # create namespaces
        await self._create_namespace(name=self.config.client_namespace)
        await self._create_namespace(name=self.config.backend_namespace)

        # move each link into own namespace
        await self._move_iface_into_namespace(
            iface=self.config.client_interface, namespace=self.config.client_namespace
        )
        await self._move_iface_into_namespace(
            iface=self.config.backend_interface, namespace=self.config.backend_namespace
        )

        # turn on links
        await self._turn_on_iface(
            name=self.config.client_interface, namespace=self.config.client_namespace
        )
        await self._turn_on_iface(
            name=self.config.client_interface_host,
        )
        await self._turn_on_iface(
            name=self.config.backend_interface, namespace=self.config.backend_namespace
        )
        await self._turn_on_iface(
            name=self.config.backend_interface_host,
        )
        # add ip4/6 addresses
        await self._iface_add_addr(
            iface=self.config.backend_interface_host,
            ip4=self.config.backend_ipv4_host,
            ip6=self.config.backend_ipv6_host,
        )
        await self._iface_add_addr(
            iface=self.config.backend_interface,
            ip4=self.config.backend_ipv4,
            ip6=self.config.backend_ipv6,
            namespace=self.config.backend_namespace,
        )
        await self._iface_add_addr(
            iface=self.config.client_interface_host,
            ip4=self.config.client_ipv4_host,
            ip6=self.config.client_ipv6_host,
        )
        await self._iface_add_addr(
            iface=self.config.client_interface,
            ip4=self.config.client_ipv4,
            ip6=self.config.client_ipv6,
            namespace=self.config.client_namespace,
        )

        # add to client link gateway addresses
        await self._iface_add_addr(
            iface=self.config.client_interface_host,
            ip4=self.config.gateway_ip4_backend,
            ip6=self.config.gateway_ip6_backend,
        )
        await self._iface_add_addr(
            iface=self.config.client_interface_host,
            ip4=self.config.gateway_ip4_xfw,
            ip6=self.config.gateway_ip6_xfw,
        )

        # add default routes
        await self._add_default_route(
            iface=self.config.backend_interface,
            ip4=self.config.backend_ipv4_host,
            ip6=self.config.backend_ipv6_host,
            namespace=self.config.backend_namespace,
        )
        await self._add_default_route(
            iface=self.config.client_interface,
            ip4=self.config.client_ipv4_host,
            ip6=self.config.client_ipv6_host,
            namespace=self.config.client_namespace,
        )

        # add gateway routes to the clients
        await self._add_route_via(
            iface=self.config.client_interface,
            ip4_address_to=self.config.gateway_ip4_backend,
            ip4_address_via=self.config.client_ipv4_host,
            ip6_address_to=self.config.gateway_ip6_backend,
            ip6_address_via=self.config.client_ipv6_host,
            namespace=self.config.client_namespace,
        )
        await self._nft_table_prepare(
            table_name=self.config.gateway_nft_table_name,
            table_path=self.config.gateway_nft_table_name_path,
            client_iface=self.config.client_interface_host,
            backend_iface=self.config.backend_interface_host,
        )
        await self._toggle_ip_forwarding()
        await self._force_ipv6_neighbor_update(
            ipv6=self.config.backend_ipv6,
        )

    async def destroy(self):
        await self._delete_namespace(self.config.client_namespace)
        await self._delete_namespace(self.config.backend_namespace)
        await self._nft_table_delete(self.config.gateway_nft_table_name)
        await self._toggle_ip_forwarding(False)


class LocalNatVeth(LocalGateVeth):
    async def _nft_table_prepare(
        self,
        table_name: str,
        table_path: str,
        backend_ip4: str,
        backend_ip4_mask: int,
        backend_ip6: str,
        backend_ip6_mask: int,
        backend_ip4_host: str,
        backend_ip6_host: str,
        backend_iface_host: str,
    ):
        nft_config = "\n".join(
            [
                f"#!/usr/sbin/nft -f",
                f"table inet {table_name} {{",
                f"   chain prerouting_raw {{",
                f"        type filter hook prerouting priority raw; policy drop;",
                f'        meta iifname {{ "xfwc0", "xfwb0", "lo" }} accept;',
                f"   }}",
                f"   chain prerouting_dnat {{",
                f"        type nat hook prerouting priority dstnat; policy accept;",
                f"        meta nftrace set 1;",
                f"        ip daddr {backend_ip4_host} counter dnat to {backend_ip4};",
                f"        ip6 daddr {backend_ip6_host} counter dnat to {backend_ip6};",
                f"   }}",
                f"   chain input {{",
                f"        type filter hook input priority 0; policy accept;",
                f"        counter accept;",
                f"   }}",
                f"   chain forward {{",
                f"        type filter hook forward priority 0; policy accept;",
                f"        counter accept;",
                f"   }}",
                f"   chain postrouting {{",
                f"        type nat hook postrouting priority srcnat; policy accept;",
                f"        ip saddr {backend_ip4}/{backend_ip4_mask} counter snat to {backend_ip4_host}",
                f"        ip6 saddr {backend_ip6}/{backend_ip6_mask} counter snat to {backend_ip6_host}",
                f"   }}",
                f"   chain output {{",
                f"        type filter hook output priority 0; policy accept;",
                f"        counter accept;",
                f"   }}",
                f"}}",
            ]
        )
        with open(table_path, "w") as f:
            f.write(nft_config)

        code, _, stderr = await run_cmd(
            cmd=f"nft -f {table_path}",
            logger=self.logger,
        )
        assert code == 0, f"Could not prepare nft table: {stderr}"

    async def prepare(self):
        # create link
        await self.create_links(
            link_from=self.config.client_interface_host, link_to=self.config.client_interface
        )
        await self.create_links(
            link_from=self.config.backend_interface_host, link_to=self.config.backend_interface
        )

        # create namespaces
        await self._create_namespace(name=self.config.client_namespace)
        await self._create_namespace(name=self.config.backend_namespace)

        # move each link into own namespace
        await self._move_iface_into_namespace(
            iface=self.config.client_interface, namespace=self.config.client_namespace
        )
        await self._move_iface_into_namespace(
            iface=self.config.backend_interface, namespace=self.config.backend_namespace
        )

        # turn on links
        await self._turn_on_iface(
            name=self.config.client_interface, namespace=self.config.client_namespace
        )
        await self._turn_on_iface(
            name=self.config.client_interface_host,
        )
        await self._turn_on_iface(
            name=self.config.backend_interface, namespace=self.config.backend_namespace
        )
        await self._turn_on_iface(
            name=self.config.backend_interface_host,
        )
        # add ip4/6 addresses
        await self._iface_add_addr(
            iface=self.config.backend_interface_host,
            ip4=self.config.backend_ipv4_host,
            ip6=self.config.backend_ipv6_host,
        )
        await self._iface_add_addr(
            iface=self.config.backend_interface,
            ip4=self.config.backend_ipv4,
            ip6=self.config.backend_ipv6,
            namespace=self.config.backend_namespace,
        )
        await self._iface_add_addr(
            iface=self.config.client_interface_host,
            ip4=self.config.client_ipv4_host,
            ip6=self.config.client_ipv6_host,
        )
        await self._iface_add_addr(
            iface=self.config.client_interface,
            ip4=self.config.client_ipv4,
            ip6=self.config.client_ipv6,
            namespace=self.config.client_namespace,
        )

        # add to client link gateway addresses
        await self._iface_add_addr(
            iface=self.config.client_interface_host,
            ip4=self.config.gateway_ip4_backend,
            ip6=self.config.gateway_ip6_backend,
        )
        await self._iface_add_addr(
            iface=self.config.client_interface_host,
            ip4=self.config.gateway_ip4_xfw,
            ip6=self.config.gateway_ip6_xfw,
        )

        # routes on private backend net
        await self._add_route_via(
            iface=self.config.backend_interface,
            ip4_address_to=self.config.client_ipv4,
            ip4_address_via=self.config.backend_ipv4_host,
            ip6_address_to=self.config.client_ipv6,
            ip6_address_via=self.config.backend_ipv6_host,
            namespace=self.config.backend_namespace,
            onlink=True,
        )

        await self._add_route(
            iface=self.config.backend_interface,
            ip4_address_to=self.config.backend_ipv4_host,
            ip4_address_mask=self.config.backend_ipv4_mask,
            ip6_address_to=self.config.backend_ipv6_host,
            ip6_address_mask=self.config.backend_ipv6_mask,
            namespace=self.config.backend_namespace,
        )

        # routes on public backend host
        await self._add_route(
            iface=self.config.backend_interface_host,
            ip4_address_to=self.config.backend_ipv4,
            ip4_address_mask=self.config.backend_ipv4_mask,
            ip6_address_to=self.config.backend_ipv6,
            ip6_address_mask=self.config.backend_ipv6_mask,
        )

        # routes for private client net
        await self._add_default_route(
            iface=self.config.client_interface,
            ip4=self.config.client_ipv4_host,
            ip6=self.config.client_ipv6_host,
            namespace=self.config.client_namespace,
        )
        await self._add_route_via(
            iface=self.config.client_interface,
            ip4_address_to=self.config.gateway_ip4_backend,
            ip4_address_via=self.config.client_ipv4_host,
            ip6_address_to=self.config.gateway_ip6_backend,
            ip6_address_via=self.config.client_ipv6_host,
            namespace=self.config.client_namespace,
        )
        await self._add_route_via(
            iface=self.config.client_interface,
            ip4_address_to=self.config.backend_ipv4_host,
            ip4_address_via=self.config.client_ipv4_host,
            ip6_address_to=self.config.backend_ipv6_host,
            ip6_address_via=self.config.client_ipv6_host,
            namespace=self.config.client_namespace,
        )

        # prepare nft rules and turn on forwarding
        await self._nft_table_prepare(
            table_name=self.config.gateway_nft_table_name,
            table_path=self.config.gateway_nft_table_name_path,
            backend_ip4=self.config.backend_ipv4,
            backend_ip4_mask=self.config.backend_ipv4_mask,
            backend_ip6=self.config.backend_ipv6,
            backend_ip6_mask=self.config.backend_ipv6_mask,
            backend_ip4_host=self.config.backend_ipv4_host,
            backend_ip6_host=self.config.backend_ipv6_host,
            backend_iface_host=self.config.backend_interface_host,
        )

        await self._toggle_ip_forwarding()
        await self._force_ipv6_neighbor_update(
            ipv6=self.config.backend_ipv6_host, namespace=self.config.backend_namespace
        )


class LocalVirtualizedNIC(LocalVeth):
    async def _flush_address(self, iface: str, namespace: str = None):
        code, _, stderr = await run_cmd(
            cmd=self._with_netns(cmd=f"ip addr flush dev {iface}", namespace=namespace),
            logger=self.logger,
        )
        assert code == 0, f"Could not flush address of iface={iface}: {stderr}"

    async def _turn_off_iface(self, iface: str, namespace: str = None):
        code, _, stderr = await run_cmd(
            cmd=self._with_netns(cmd=f"ip link set {iface} down", namespace=namespace),
            logger=self.logger,
        )
        assert code == 0, f"Could not turn off iface={iface}: {stderr}"

    async def prepare(self):
        await self._create_namespace(name=self.config.client_namespace)
        await self._move_iface_into_namespace(
            iface=self.config.client_interface, namespace=self.config.client_namespace
        )
        await self._turn_on_iface(
            name=self.config.client_interface, namespace=self.config.client_namespace
        )
        await self._turn_on_iface(
            name=self.config.backend_interface,
        )

        await self._iface_add_addr(
            iface=self.config.backend_interface,
            ip4=self.config.backend_ipv4,
            ip6=self.config.backend_ipv6,
        )
        await self._iface_add_addr(
            iface=self.config.client_interface,
            ip4=self.config.client_ipv4,
            ip6=self.config.client_ipv6,
            namespace=self.config.client_namespace,
        )
        await self._add_route(
            iface=self.config.backend_interface,
            ip4_address_to=self.config.client_ipv4,
            ip4_address_mask=self.config.client_ipv4_mask,
            ip6_address_to=self.config.client_ipv6,
            ip6_address_mask=self.config.client_ipv6_mask,
        )
        await self._add_route(
            iface=self.config.client_interface,
            ip4_address_to=self.config.backend_ipv4,
            ip4_address_mask=self.config.backend_ipv4_mask,
            ip6_address_to=self.config.backend_ipv6,
            ip6_address_mask=self.config.backend_ipv6_mask,
            namespace=self.config.client_namespace,
        )

        await self._turn_off_offload_on_iface(self.config.backend_interface)

    async def destroy(self):
        await super().destroy()

        # after ns deleting we need to wait some time
        # until network manager activate it again and
        # then continue

        await asyncio.sleep(3)
        await self._flush_address(iface=self.config.backend_interface)
        await self._flush_address(
            iface=self.config.client_interface,
        )
        await self._turn_off_iface(iface=self.config.backend_interface)
        await self._turn_off_iface(
            iface=self.config.client_interface,
        )
