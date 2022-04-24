sendip
======

[SendIP tarballs](https://www-x.antd.nist.gov/ipv6/sendip.html) converted to a Git repository.

[Original README](README)

### Enhancements

This version adds the ability to dump packets to `stdout` rather than sending them to their
destinations, with the `-D` flag.

For example, this will generate a TCP/IPv4 packet with 1000 bytes of random data and random
source/dest addresses, and convert it to a PCAP file for analysis with wireshark or tcpdump.

```sh
./sendip -D -p ipv4 -p tcp -d r1000 -d r1000 -id r -is r \
         | od -Ax -tx1 -v | text2pcap -e 0x800 - /tmp/test.pcap
```
