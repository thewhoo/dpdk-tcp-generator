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
3. Manually set up ARP entries and routes on the server subject to testing

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
./tcpgen [EAL options] -- -p PORTMASK [-t TCP GAP] -f QNAME file --src-mac SRC_MAC --dst-mac DST_MAC --src-ip-mask SRC_IP_MASK --dst-ip DST_IP
  -p PORTMASK: Hexadecimal bitmask of ports to generate traffic on
  -t TCP GAP: TSC delay before opening a new TCP connection
  -f QNAME file: File containing a list of QNAMEs used for generating queries
  --src-mac: Source MAC address of queries
  --dst-mac: Destination MAC address of queries
  --src-subnet: Source subnet of queries (for example 10.10.0.0/16)
  --dst-ip: Destinatio IP of queries
```

* The only EAL option that needs to be supplied is the core mask (supplied by the `-c` argument. It is currently recommended to use a single core as it can generate a sufficient amount of traffic and multi-core scenarios have not been sufficiently tested).

* Use the portmask to select ports on which to generate traffic (bit mask that selects interfaces bound to a DPDK-compatible driver in the order displayed in `dpdk-devbind --status`)
* The tcp gap is the CPU clock cycle interval between opening new TCP connections (the default is 10 000 000 000 which means ~1 new connection every 3 seconds on a 3.3 GHz CPU). A value of 0 will cause new connections to be opened with the maximum possible frequency.
* Feel free to choose any source MAC you want, but you will manually have to add it to the ARP table of the server subject to testing.
* The destination MAC should be the MAC of the NIC on the server subject to testing
* The source subnet specifies the subnet of source IP addresses of queries.
A subnet of `10.10.64.0/18` will result in queries arriving from a range of IP addresses between `10.10.64.0` and `10.10.127.255`.
Queries will not be sent from network and broadcast addresses.
* The destination IP should be the IP address of the interface on the server (in a different subnet than the source IP range)

### Example

The generator uses a user-supplied list of QNAMEs in the queries it generates. This list is supplied in a file with the `-f` argument and should contain one FQDN per line, including the dot at the end (same format as in zone files):

```
a.test.
b.test.
c.test.
x2443.asdf.invalid.
a.b.c.d.
```

Running the generator with the following arguments
```shell
./tcpgen -c 1 -- -p 1 -t 10000 --src-mac de:ad:be:ef:ca:fe --dst-mac 90:e2:ba:ee:ee:ee --src-subnet 10.10.64.0/18 --dst-ip 10.99.0.1 -f qname_file
```

will cause the application to begin generating A queries for randomly selected hostnames from the QNAME file from IP addresses in the `10.10.64.0` - `10.10.127.255` range with random source ports. The MAC address of the server interface should be `90:e2:ba:ee:ee:ee` and the configured IP address should be `10.99.0.1`.

The routing table of the server should contain a route for the randomized query subnet (you can use any destination IP, the generator doesn't care):

```shell
ip route add 10.10.64.0/18 via 10.99.0.254
```

However, the ARP table of the server must then contain a corresponding entry, matching `de:ad:be:ef:ca:fe` with the IP address added to the routing table:

```shell
arp -s 10.99.0.254 de:ad:be:ef:ca:fe
```

This will result in response traffic being correctly sent out of the same interface with the destination MAC of `de:ad:be:ef:ca:fe`. Please note that it is important that the source IP address range of queries does not overlap with the subnet of the server NIC to prevent the server from performing ARP lookups for the random IP addresses of the queries.

It is recommended to first test everything with the default TCP gap (very low frequency of new connections) and `tcpdump` to see if traffic is getting sent out of the correct interface and if the server is responding.

An example zone file that causes the server to return a NOERROR response for `a.test`, NXDOMAIN for `b.test` and `c.test` and REFUSED for other QNAMES:

```shell
test.           86400    IN      SOA     ns.test.    test.test.  2019021300 1800 900 604800 86400
test.           86400    IN      NS      ns.test.
ns.test.        86400    IN      A       127.0.0.1
ns.test.        86400    IN      AAAA    ::1
a.test.         86400    IN      A       127.0.0.1
```

## Troubleshooting
`tcpdump` or write me an email: Matej Postolka <xposto02@stud.fit.vutbr.cz> or <matej@postolka.net>
