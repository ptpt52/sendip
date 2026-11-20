sendip
======

[SendIP tarballs](https://www-x.antd.nist.gov/ipv6/sendip.html) converted to a Git repository.

[Original README](README)

### Module compatibility

SendIP and its modules use the standard C `bool` type from `<stdbool.h>`.
After upgrading from a version that used `typedef int bool`, rebuild SendIP
and all protocol and crypto modules together to match the new module ABI.
The AH/ESP private structures also contain per-instance crypto module pointers;
rebuild external crypto modules whenever these module headers change.
Finalized packet headers can start at any byte offset. Use the supplied packed
wire types or byte-wise copies when accessing headers in protocol modules.

Protocol modules may export `void destroy(sendip_data *pack)` to release their
private per-packet state. SendIP calls it before replacing or unloading a packet,
including on option and finalization failures. The callback must leave `pack` and
`pack->data` to the caller, and must not depend on packet data still being live.
Modules without this optional entry point remain supported.

Protocol modules may also export `uint32_t randomize_arg(const char *option,
uint32_t value)` to constrain a generated bare-`r` argument to the selected field's
range. SendIP still passes a decimal string to `do_opt`; explicit arguments
retain their normal validation. Modules without this callback keep the legacy
32-bit random value.

### File arguments

The `fF` argument form reads text values one line at a time. LF and CRLF line
endings are removed; a carriage return elsewhere remains part of the value.
The `-f` packet-data option continues to read raw file bytes.

### IPv4 byte order

Assembled and dumped IPv4 headers use network byte order on every platform,
including encapsulated headers. The outer header is temporarily adapted only
when sending through Darwin or pre-11 FreeBSD raw sockets; FreeBSD 11 and later
use network order directly.

### Enhancements

This version adds the ability to dump packets to `stdout` rather than sending them to their
destinations, with the `-D` flag.

For IPv6 payloads larger than 65535 bytes, supply a matching Jumbo Payload
option in the immediately following Hop-by-Hop header. Automatic IPv6 payload
length is then zero; automatic UDP length is zero when the UDP datagram itself
exceeds 65535 bytes. Explicit wire-length overrides remain available for packet
experiments.

For example, this will generate a TCP/IPv4 packet with 1000 bytes of random data and random
source/dest addresses, and convert it to a PCAP file for analysis with wireshark or tcpdump.

ipv4:
```sh
./sendip -D -p ipv4 -p tcp -d r1000 -id r -is r \
		| od -Ax -tx1 -v | text2pcap -e 0x800 - /tmp/test.pcap
```

ipv6:
```sh
./sendip -D -p ipv6 -6s 9901::180 -6d 9901::100 -p icmp -d r100 \
		| od -Ax -tx1 -v | text2pcap -e 0x86DD - /tmp/test.pcap
```
