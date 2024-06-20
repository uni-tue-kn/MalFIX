import ipaddress
import struct
from ipaddress import IPv4Address, IPv6Address
from numbers import Number
from typing import Tuple, Optional

import pyfixbuf

from scapy.compat import raw
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6

print_debug = False
yaf = False

# Is needed because of a bug in the pyfixbuf lib "pyfixbuf_set_value"
_ = ""


def write_maltrail_to_record(event: Tuple, record: pyfixbuf.Record, maltrail_only: bool):
    global _
    if not maltrail_only:
        sec, usec, src_ip, src_port, dst_ip, dst_port, _, _, _, _, _ = event
        if ipaddress.ip_address(src_ip).version == 4:
            record["sourceIPv4Address"] = src_ip
            record["destinationIPv4Address"] = dst_ip
        else:
            record["sourceIPv6Address"] = src_ip
            record["destinationIPv6Address"] = dst_ip

        record["sourceTransportPort"] = src_port
        record["destinationTransportPort"] = dst_port
    _ = maltrail_event_to_string(event)
    record["maltrail"] = _


def ipfix_to_ip(data, dns_info: Optional[Tuple[str, Number]]):
    src_ip: IPv4Address = data["sourceIPv4Address"]
    dst_ip: IPv4Address = data["destinationIPv4Address"]
    src_ip6: IPv6Address = data["sourceIPv6Address"]
    dst_ip6: IPv6Address = data["destinationIPv6Address"]
    protocol_identifier: Number = data["protocolIdentifier"]
    src_port: Number = data["sourceTransportPort"]
    dst_port: Number = data["destinationTransportPort"]
    dns_name: Optional[str] = None
    dns_type: Optional[str] = None
    if dns_info:
        dns_name: str = dns_info[0]
        dns_type: str = "A" if dns_info[1] == 4 else "AAAA"

    is_ipv6 = str(src_ip) == "0.0.0.0" and str(dst_ip) == "0.0.0.0"
    packet = (IPv6(dst=dst_ip6, src=src_ip6) if is_ipv6 else IP(
        dst=dst_ip,
        src=src_ip))
    if protocol_identifier == 1:  # ICMP
        # YAF:
        # destinationTransportPort 2 bytes unsigned
        # For ICMP flows, contains (ICMP-type * 256 + ICMP-code).
        if not is_ipv6:
            icmp_type: Number = data["icmpTypeIPv4"] if not yaf \
                else int(format(data["destinationTransportPort"], '016b')[:8], 2)
            icmp_code: Number = data["icmpCodeIPv4"] if not yaf \
                else int(format(data["destinationTransportPort"], '016b')[-8:], 2)
            packet /= ICMP(type=icmp_type, code=icmp_code)
    elif protocol_identifier == 6:  # TCP
        packet /= TCP(sport=src_port, dport=dst_port)
        if dns_name:
            packet /= DNS(qd=DNSQR(qname=dns_name, qtype=dns_type))
    elif protocol_identifier == 17:  # UDP
        packet /= UDP(sport=src_port, dport=dst_port)
        if dns_name:
            packet /= DNS(qd=DNSQR(qname=dns_name, qtype=dns_type))

    if print_debug:
        print(packet)
    return raw(packet)


def maltrail_event_to_string(event: Tuple) -> str:
    _, _, _, _, _, _, _, mal_type, trail, info, reference = event
    return f"mal_type: {mal_type} trail: {trail} info: {info} reference: {reference}"
