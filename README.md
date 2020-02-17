# dpdk-tcp-generator

Generates TCP DNS queries from randomized source IP addresses and ports
and provides response rate statistics.

## Build

dpdk-tcp-generator has the following dependencies:

* DPDK 19.05

### Compiling

Run `make` with `RTE_SDK` set to the install dir of DPDK.

## Running

Before running the application, it is necessary to perform the following steps:

1. Allocate hugepages
2. Bind the desired network interface to a DPDK-compatible driver
3. Manually set up ARP entries, NDP entries and routes on the server subject to testing

### Allocation of hugepages

It is necessary to allocate hugepages before running the application (ideally 4GiB of hugepages):

```sh
sysctl vm.nr_hugepages=2048 # Allocates 2048x2MB as huge pages (requires 4G free memory)
# echo 2048 > /proc/sys/vm/nr_hugepages # Alternative to sysctl command
```

### Binding NIC to DPDK-compatible driver

First, check which network interfaces are available by running `dpdk-devbind --status` as root. Bind the desired network interface to a DPDK-compatible driver (`igb_uio` in the case of Intel interfaces) by running `dpdk-devbind -b igb_uio bus:slot.func` where `bus:slot.func` identifies the desired PCI device (as seen in the output of `dpdk-devbind --status`). If the `igb_uio` module isn't available, load it by running `modprobe igb_uio` (it might be necessary to run `depmod` after installing DPDK).

### Usage

```
tcpgen [EAL options] -- -p PORTMASK -c CONFIG --pcap PCAP [-g TCP_GAP] [-r RUNTIME] [--results RESULTS]
  -p PORTMASK: Hexadecimal bitmask of ports to generate traffic on
  -c CONFIG: Generator configuration file (see example.conf)
  --pcap PCAP: File containing reference packets for generating queries
  -g TCP_GAP: Open a new TCP connection no earlier than every TCP_GAP{h|m|s|ms|us|ns} (default: microseconds)
  -r RUNTIME: Stop after RUNTIME{h|m|s|ms|us|ns} (default: microseconds)
  --results RESULTS: Name of file containing per-lcore results in JSON format
```

* The only EAL option that needs to be supplied is the core mask (supplied by the `-c` argument).

* Use `PORTMASK` to select ports on which to generate traffic (bit mask that selects interfaces bound to a DPDK-compatible driver in the order displayed in `dpdk-devbind --status`)
* Use `TCP_GAP` to specify delay between opening new TCP connections. If the argument isn't supplied, a very slow rate of approximately 10 connections per second will be used. If the argument has a value of 0, TCP connections will be opened with the maximum possible frequency.
* Use `RUNTIME` to specify the total runtime of the generator. If no runtime limit is given, the generator will run until stopped.
* All other configuration is specified in the configuration file. See `example.conf`.

### Notes

Suppose we have the following configuration:
```
source-mac de:ad:be:ef:ca:fe
destination-mac 90:e2:ba:00:00:01

ipv6-source-network fcaa:dead:beef:cafe::
ipv6-source-netmask ffff:ffff:ffff:ffff:ffff:ffff::
ipv6-destination-ip fcbb:1::1

ipv4-source-network 10.10.64.0
ipv4-source-netmask 255.255.192.0
ipv4-destination-ip 10.99.0.1

tcp-destination-port 53
```

The routing table of the server should contain a route for the randomized query subnet (you can use any destination IP, the generator doesn't care):

```shell
ip route add 10.10.64.0/18 via 10.99.0.254
ip -6 route add fcaa:dead:beef:cafe::/96 via fcbb:1::2
```

However, the ARP and NDP tables of the server must then contain a corresponding entry, matching `de:ad:be:ef:ca:fe` with the IP address added to the routing table:

```shell
arp -s 10.99.0.254 de:ad:be:ef:ca:fe
ip -6 neigh add fcbb:1::2 lladdr de:ad:be:ef:ca:fe dev enp1s0f0
```

This will result in response traffic being correctly sent out of the same interface with the destination MAC of `de:ad:be:ef:ca:fe`. Please note that it is important that the source IP address range of queries does not overlap with the subnet of the server NIC to prevent the server from performing ARP lookups for the random IP addresses of the queries.

It is recommended to first test everything with the default TCP gap (very low frequency of new connections) and `tcpdump` to see if traffic is getting sent out of the correct interface and if the server is responding.

## Troubleshooting
`tcpdump` or write me an email: Matej Postolka <xposto02@stud.fit.vutbr.cz> or <matej@postolka.net>
