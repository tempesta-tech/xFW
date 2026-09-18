# Tempesta xFW testing framework

## Requirements

 * Python3.10 <=
 * ~~ TrafGen 0.6.8 <= ~~
 * ~~ TcpReplay 4.4.4 <= ~~

### Build XFW
```bash
make clean
DEBUG=3 make
sudo make install
```

In the project we use [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)


### Prepare Venv. First Run

```bash
# activate root
sudo su

# enter into the tests dir
cd t/func

# create env and install the requirements
./setup.sh

# activate python env
source .venv/bin/activate

# run tests
pytest -s -vvv
```

If you have some non-default projects dirs, you might update the tests config
```bash
# You can also leave only the variables you’ve changed in the .env file. Default values can be found in *config.py*.
# Please check **XFW\_SOURCE\_DIR** and **XFW\_BUILD\_DIR** in the config—you may need to update them.
cp example.env .env
```

Next time after setup, you might run
```bash
# activate root
sudo su

# enter into the tests dir
cd t/func

# activate python env
source .venv/bin/activate

# run tests
pytest -s -vvv
```

### Run tests options

Add tests output
```bash
source .venv/bin/activate
pytest -s -vvv
```

Start the debugger on error
```bash
source .venv/bin/activate
pytest -s -vvv --pdb
```

Run specific tests from dir/file/test
```bash
pytest -s -vvv tests
pytest -s -vvv tests/test_metric.py
pytest -s -vvv tests/test_metric.py::test_metrics_changes
pytest -s -vvv tests/test_metric.py::test_metrics_changes[udp]
pytest -s -vvv tests/test_metric.py::test_metrics_changes[udp-ip4]
```

## How to

### Reconfigure XFW
```python
from framework.xfw import XFW

async def test_new_config(xfw: XFW):
    await xfw.rules_set(
        '''
        xfw {
            dst ip4.tcp : allow {
                20.0.0.0:9000
            }
        }
        '''
    )
```
At this stage, *xfw* is already running. You can just make some changes, and *rules_set* will apply them immediately.

### Start Backend and Client
All possible server and client fixtures

```python
async def test_new_config(
        tcp_ip4_server,
        tcp_ip6_server,
        upd_ip4_server,
        upd_ip6_server,

        tcp_ip4_client,
        tcp_ip6_client,
        udp_ip4_client,
        udp_ip6_client
):
    await tcp_ip4_server.start()
    await tcp_ip4_client.start()

    await tcp_ip4_client.send('test')
    assert await tcp_ip4_server.receive() == 'test'
```

But there are global autofixtures *server* and *client* that automatically iterate over all of the above.
The *server* fixture automatically iterates through *tcp\_ip4\_server*, *tcp\_ip6\_server*, *udp\_ip4\_server*, and *udp\_ip6\_server*.
The *client* fixture, respectively, iterates through *tcp\_ip4\_client*, *tcp\_ip6\_client*, *udp\_ip4\_client*, and *udp\_ip6\_client*.

Additionally, the *ip\_version* fixture returns *ip4* or *ip6* if needed for the xfw config, and the *protocol* fixture
returns *tcp* or *udp*.


```python
async def test_new_config(server, client, protocol, ip_version):
    await server.start()
    await client.start()

    await client.send('test')
    assert await server.receive() == 'test'
```

Here is an example of how to write a test for ip4/ip6 and tcp/udp client-server
```python
from framework.stateful import (
    RegularKernelSocketNetworkStateful
)
from framework.xfw import XFW
async def test_dst_allowed(
        xfw: XFW,
        protocol: str,
        ip_version: str,
        server: RegularKernelSocketNetworkStateful,
        client: RegularKernelSocketNetworkStateful,
        establish_connection
):
    await xfw.rules_set(
        f'''
        xfw {{
            dst {ip_version}.{protocol} : allow {{
                {server.ip}:{server.port}
            }}
        }}
        '''
    )

    assert await check_connection(client, server), \
        f'Server ({server.ip}:{server.port}) is not available'

```

If you need to use a non-default backend-client address or port, use generators

```python
async def test_new_ip(
        server: RegularKernelSocketNetworkStateful,
):
    new_ip = server.generate_new_addresses()[0]
    new_port = server.generate_new_ports()[0]
    await server.start_on(ip=new_ip, port=new_port)
```

Or if you need a range of addresses or ports

```python
async def test_new_ip(
        server: RegularKernelSocketNetworkStateful,
):
    new_ips = server.generate_new_addresses(amount=10)
    new_ports = server.generate_new_ports(amount=10)
    pairs = [i for i in zip(new_ips, new_ports)]
```

Anyway, use generators to create new addresses, since all network settings are configured through config and fixtures.

### Get metrics
```python
async def test_metrics(
        xfw: XFW,
):
    metrics = await xfw.metrics()
```


# Network topology
## Local network. Host

For local development, we use network namespaces. It’s not enough to just create a regular peer interface pair
and attach XFW to one of them. The issue in that case is Linux optimization, which forces traffic over the
loopback interface when interfaces are in the same local network.

Network namespaces allow creating a fully independent network stack, as if it were another machine. In our
setup, we have the xfwb1 interface for the backends and XFW, while xfwc1 is moved into the xfw-ns namespace. Each
interface is in a separate network. 

In total, we have three networks. This topology allows us to create any number of clients and servers with
different IP addresses.

```
      ( netns: xfw-ns )                                      ( root ns )
      clients (/32,/128)                                backends + xfw (/32,/128)
  109.245.0.1 … 109.245.0.255                                20.0.0.0 - 20.0.0.255
  2001:8c8::1 … 2001:8c8::ffff                           fd00:20::0 - fd00:20::ffff
            │                                                        │
            │                                                        │
         [ xfwc1 ] ────────────── p2p L3 link ────────────────── [ xfwb1 (XDP/TC) ]
      fd00:ffff::0/127                                         fd00:ffff::1/127
```

Network namespaces aren’t available in the Python standard library, so there’s a hack to enable them.
The testing framework is fully asynchronous, but the namespace hack uses synchronous socket binding.
That’s a quick operation, but it’s still better to create the clients first and then send asynchronous
requests as usual. The only thing to keep in mind is that it’s enough to create a socket inside the
namespace—after that you can use it as usual. We can probably create several namespaces, create each
required client sequentially, and then use them asynchronously.

### Prepare the local network automatically
There is a test helper that prepares the network automatically:

```bash
pytest -m 'prepare_network'
```

It forces the tests to perform the standard network setup required to run, but it stops inside the fake test at 
an input prompt and waits for the user to enter some commands.

## Local network. Gate

```
      ( netns: xfw-nc )                  ( root ns )                     ( netns: xfw-nb )                                      
      clients (/32,/128)                xfw (30.0.0.1)                  backends (/32,/128)
  109.245.0.1 … 109.245.0.255            ip_forward=1                   20.0.0.0 - 20.0.0.255
  2001:8c8::1 … 2001:8c8::ffff            nft rules                  fd00:20::0 - fd00:20::ffff
            │                                 │                                  │
            │                                 │                                  │
         [ xfwc1 ] ──── veth ──── xfwc0 (XDP) │ xfwb0 (TC) ────  veth ──── [ xfwb1 ]
```

The xFW `mode=gate` is tested with `ip_forward=1` enabled.  

To make the system look more realistic, the backends and clients are separated into different network namespaces.  
Each end of the VETH pairs (from clients and backends) resides on the host machine.  
xFW uses those host-side VETH ends to attach XDP and TC hooks.

## Local network. NAT+HOST

```
      ( netns: xfw-nc )                  ( root ns )                        ( netns: xfw-nb )                                      
      clients (/32,/128)                xfw (30.0.0.1)                      backends (/32,/128)
  109.245.0.1 … 109.245.0.255            ip_forward=1                          192.100.0.1
  2001:8c8::1 … 2001:8c8::ffff            nft rules                            fe80:20::1
            │                                 │ (20.0.0.1)                         │
            │                                 │ (fd00:20::1)                       │
         [ xfwc1 ] ──── veth ──── xfwc0 (XDP) │ xfwb0 (TC) ────  veth ──── [ xfwb1 ]
```

Mostly the same as in the case with Gate, but now we have NFT rules for `xfwb0`  
that use NAT and rewrite the destination IP to 192.100.0.1. As a result,  
the clients send packets directly to xfwb0, but actually they are  
transmitted/forwarded to xfwb1.

## 1 VM + Virtual NICs
To activate XDP on a “real” NIC we can use drivers such as rtl8139, e1000, or vmxnet3 in a VM. We could create several VMs, 
each with a different NIC, but for tests one VM with multiple NICs is enough.
One thing to remember (as with the local-network setup) is that Linux may optimize traffic between local interfaces. 
That means we cannot directly send traffic, for example, from e1000 to vmxnet3 because Linux will route it via loopback. 
To avoid this — as we did for the local-network case — we must put the client interface into a network namespace.

We also need to connect the two interfaces somehow. If we create a Linux bridge between the interfaces, 
Linux still treats bridge traffic as local and forwards it through loopback. To bypass that, we must create the bridge 
outside of the VM, on the host. QEMU exposes TAP interfaces for host–guest communication; by connecting two TAP interfaces 
with a host bridge, we force traffic to go out of the VM to the host and then back in.

The final architecture looks like the diagram below.

The configuration of Guest machine is simple: we just need to add 3 NICs, with virsh we can do it 
in such way

```
+-----------------------------------------------+
|                                               |
|                HOST MACHINE                   |
|                                               |
|        +-------------------------+            |
|        | HOST BRIDGE (escudo-br )|            |
|        +-------------------------+            |
|              ↕            ↕                   |
|        +-----------+ +-----------+            |
|    +---| TAP e1000 | |TAP rtl8139|--------+   |
|    |   +-----------+ +-----------+        |   |
|    |         ↕              ↕             |   |
|    |   +-----------+ +--------------+     |   |
|    |   +-----------+ |  NAMESPACE   |     |   |
|    |   |   e1000   | | +----------+ |     |   |
|    |   +-----------+ | | rtl8139  | |     |   |
|    |                 | +----------+ |     |   |
|    |                 +--------------+     |   |
|    +--------------------------------------+   |
|    |      Virtual Machine (escudo-1)      |   |
|    +--------------------------------------+   |
|                                               |
+-----------------------------------------------+
```

```bash
# replace NIC_TYPE with rtl8139, e1000 and vmxnet3, virtio
virsh attach-interface\
   --domain escudo-1\
   --type network\
   --source default\
   --model NIC_TYPE\
   --config
```

If you want to see human-readable names for your NICs, create a link file for your NIC in `/etc/systemd/network`.
For example: `/etc/systemd/network/10-custom-e1000.link`

```ini
[Match]
MACAddress=52:54:00:35:18:40

[Link]
Name=e1000
```

The `MACAddress` should match your NIC’s MAC, and `Name` can be set to whatever you want.
Linux normally generates names like `ens0/1/2`; to identify your required NIC, use:

```bash
ethtools -i ens0
```

After that, we need to reboot the VM to apply the latest changes
```bash
virsh destroy escudo-1
virsh start escudo-1
```

Now we need to create a bridge on the host machine and add the VM’s TAP interfaces to it

```bash
ip link add name escudo-br type bridge
ip link set escudo-br up
ip link set e1000 master escudo-br 
```

Very important thing is to set the MTU to 9000 (or higher, at least 4 KB) on the TAP interfaces 
and the bridge. This is required for several DNS tests.

```bash
ip link set escudo-br mtu 9000
ip link set e1000 mtu 9000
```


## Run Different Configurations

### Host Mode + Veth
The default network configuration. Nothing additional required. Just run

```bash
pytest
# or
pytest -c profiles/host.veth.ini
```

### Host Mode + TFW Logger
The tests require the Clickhouse to be started. The default configuration uses default Clickhouse Settings.

```bash
pytest -c=profiles/host.tfw_logger.ini
```

### Host Mode + NIC (VIRTIO)
Allow to test different drivers and physical NICs. You have to configure the env first `.env`

```dotenv
network_type=2
xfw_interface=xfwb0
xfw_server_iface=xfwb0
backend_interface=xfwb0
client_interface=xfwc0
```
Then run
```bash
pytest -c=profiles/host.veth.ini
```

### Gate Mode (Forwarding) + Veth
Turn on forwarding on the server and use XFW to filtering routing traffic

```bash
cp .gate.env .env
pytest -c=profiles/host.gate.short.ini
pytest -c=profiles/host.gate.long.ini
```

Short - for PR, just the most crucial
Long - for daily

### Host + DDOS
Run tests from pcap files and verify XFW configs to prevent DDOS simulating

```bash
pytest -c=profiles/host.ddos.ini
```

### Host + NAT
Similar to Gate Mode, but destination servers are under the NAT

```base
cp .nat.env .env
pytest -c=profiles/host.nat.long.ini
pytest -c=profiles/host.nat.short.ini
```


## Fast and Normal modes

Originally, each test required the xfw fixture that restarts the xfw application. This guaranteed a clean test 
environment, as every test recreated sockets, cleared connections, and so on. However, each xfw restart takes 
about 1 second. With over 1,000 tests, a significant amount of time was spent just on application reloads.

The Fast mode uses a rules reset instead of a full xfw restart. The rules reset is a PUSH command with 
the empty rule `xfw {}`. It is important to understand that even this empty rule 
still activates some internal filters (for example, udp_anomaly_filter), unlike a full restart which stops 
all filtration. In addition, some metrics may still be collected and can affect the final results.

This mode is potentially dangerous and should only be used with a full understanding of the above behaviour. 
The main advantage is that a rules reset completes in milliseconds, eliminating the long pauses caused by 
application restarts. This makes Fast mode especially useful for Pull Request checks - the total time 
of various PR checks can be reduced from about 3 hours to around 30 minutes.

How to run Normal mode (default):

```bash
pytest
```

How to run Fast mode:
```bash
pytest --xfw-use-rule-reset
```
