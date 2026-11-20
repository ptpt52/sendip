#! /bin/sh

# Usage: wake <host> [<MAC address>]
#
# <host> can be a host name or a dotted-quad IP address.
# If the <MAC address> is not given, it is taken from ethers(5).
# For this to work, if you give a host name as first argument, ethers
# has to contain host names (as opposed to IP addresses).
#
# Unless you have it already, you can build your ethers file like this:
#
# nmap -sP -PI 192.168.1.0/24	# prepare ARP cache with a ping-sweep
# arp -a | awk '$5 == "[ether]" { printf("%s\t%s\n", $4, $1); }' \
#        | sort >>/etc/ethers
#
# The 'magic packet' consists of 6 times 0xFF followed by 16 times
# the hardware address of the NIC. This sequence can be encapsulated
# in any kind of packet; I chose UDP to the discard port (9).

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ -z "$1" ]; then
  printf 'Usage: %s <host> [MAC address]\n' "$0" >&2
  exit 1
fi
host=$1

if [ "$#" -eq 1 ]; then
  ETHER=$(SENDIP_WAKE_HOST="$host" awk '
    NF >= 2 && $1 !~ /^#/ && ("h" $2) == ("h" ENVIRON["SENDIP_WAKE_HOST"]) {
      print $1
      exit
    }
  ' /etc/ethers) || exit 1
  if [ -z "$ETHER" ]; then
    printf '%s: host %s is not in /etc/ethers\n' "$0" "$host" >&2
    exit 1
  fi
else
  ETHER=$2
fi

case "$ETHER" in
  ??:??:??:??:??:??) ETHER=$(printf '%s' "$ETHER" | tr -d ':') || exit 1 ;;
esac
case "$ETHER" in
  *[!0123456789abcdefABCDEF]*) ETHER= ;;
esac
if [ "${#ETHER}" -ne 12 ]; then
  printf '%s: expected a 12-digit or colon-separated MAC address\n' "$0" >&2
  exit 1
fi

ETHER="${ETHER}${ETHER}${ETHER}${ETHER}"		# 4 x MAC
ETHER="FFFFFFFFFFFF${ETHER}${ETHER}${ETHER}${ETHER}"	# Preamble + 16 x MAC

sendip -p ipv4 -p udp.so -ud 9 -d "0x$ETHER" -- "$host"
