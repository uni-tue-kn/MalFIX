from ipaddress import IPv4Address, IPv6Address
from numbers import Number

import pyfixbuf

from scapy.compat import raw
from scapy.layers.inet import ICMP, TCP, UDP, IP
from scapy.layers.inet6 import IPv6

print_debug = True


def ipfix_to_ip(data):
    src_ip: IPv4Address = data["sourceIPv4Address"]
    dst_ip: IPv4Address = data["destinationIPv4Address"]
    src_ip6: IPv6Address = data["sourceIPv6Address"]
    dst_ip6: IPv6Address = data["destinationIPv6Address"]
    protocol_identifier: Number = data["protocolIdentifier"]
    src_port: Number = data["sourceTransportPort"]
    dst_port: Number = data["destinationTransportPort"]

    pyfixbuf.InfoElementSpec("destinationTransportPort"),
    is_ipv6 = str(src_ip) == "0.0.0.0" and str(dst_ip) == "0.0.0.0"
    packet = (IPv6(dst=dst_ip6, src=src_ip6) if is_ipv6 else IP(
        dst=dst_ip,
        src=src_ip))
    if protocol_identifier == 1:  # ICMP
        # YAF:
        # destinationTransportPort 2 bytes unsigned
        # For ICMP flows, contains (ICMP-type * 256 + ICMP-code).
        if not is_ipv6:
            icmp_type: Number = data["icmpTypeIPv4"]
            icmp_code: Number = data["icmpCodeIPv4"]
            packet /= ICMP(type=icmp_type, code=icmp_code)
    elif protocol_identifier == 6:  # TCP
        packet /= TCP(sport=src_port, dport=dst_port)
    elif protocol_identifier == 17:  # UDP
        packet /= UDP(sport=src_port, dport=dst_port)

    if print_debug:
        print(packet)
    return raw(packet)
