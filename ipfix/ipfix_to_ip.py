from ipaddress import IPv4Address, IPv6Address
from numbers import Number
from typing import Tuple, Optional

from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6

yaf = False

packet_mapping = {
    "ip_packet": IP(),
    "ip_tcp_packet": IP() / TCP(),
    "ip_udp_packet": IP() / UDP(),
    "ip_tcp_dns_packet": IP() / TCP() / DNS(qd=DNSQR()),
    "ip_udp_dns_packet": IP() / UDP() / DNS(qd=DNSQR()),

    "ipv6_packet": IPv6(),
    "ipv6_tcp_packet": IPv6() / TCP(),
    "ipv6_udp_packet": IPv6() / UDP(),
    "ipv6_tcp_dns_packet": IPv6() / TCP() / DNS(qd=DNSQR()),
    "ipv6_udp_dns_packet": IPv6() / UDP() / DNS(qd=DNSQR())
}


def create_raw_packet(packet, src, dst, sport, dport, dns_name, dns_type):
    packet.src = src
    packet.dst = dst
    if sport and dport:
        packet.sport = sport
        packet.dport = dport
        if dns_name and dns_type:
            packet.qd.qname = dns_name
            packet.qd.qtype = dns_type
    return bytes(packet)


def get_packet_type(is_ipv6: bool, dns_name: Optional[str], protocol_identifier: Optional[int]):
    if dns_name:
        prefix = "ipv6_" if is_ipv6 else "ip_"
        suffix = "tcp_dns_packet" if protocol_identifier == 6 else "udp_dns_packet" if protocol_identifier == 17 else "dns_packet"
    elif protocol_identifier:
        prefix = "ipv6_" if is_ipv6 else "ip_"
        suffix = "tcp_packet" if protocol_identifier == 6 else "udp_packet" if protocol_identifier == 17 else "packet"
    else:
        prefix = "ipv6_" if is_ipv6 else "ip_"
        suffix = "packet"

    return prefix + suffix


def ipfix_to_ip(data, dns_info: Optional[Tuple[str, Number]]):
    src_ip: IPv4Address = data["sourceIPv4Address"]
    dst_ip: IPv4Address = data["destinationIPv4Address"]
    src_ip6: IPv6Address = data["sourceIPv6Address"]
    dst_ip6: IPv6Address = data["destinationIPv6Address"]
    protocol_identifier: int = data["protocolIdentifier"]
    src_port: int = data["sourceTransportPort"]
    dst_port: int = data["destinationTransportPort"]
    dns_name: Optional[str] = None
    dns_type: Optional[str] = None
    is_ipv6 = str(src_ip) == "0.0.0.0" and str(dst_ip) == "0.0.0.0"
    if dns_info:
        dns_name: str = dns_info[0]
        dns_type: str = "A" if dns_info[1] == 4 else "AAAA"

    if protocol_identifier == 1:  # ICMP
        # YAF:
        # destinationTransportPort 2 bytes unsigned
        # For ICMP flows, contains (ICMP-type * 256 + ICMP-code).
        packet = (IPv6(dst=dst_ip6, src=src_ip6) if is_ipv6 else IP(
            dst=dst_ip,
            src=src_ip))
        if not is_ipv6:
            icmp_type: Number = data["icmpTypeIPv4"] if not yaf \
                else int(format(data["destinationTransportPort"], '016b')[:8], 2)
            icmp_code: Number = data["icmpCodeIPv4"] if not yaf \
                else int(format(data["destinationTransportPort"], '016b')[-8:], 2)
            packet /= ICMP(type=icmp_type, code=icmp_code)
            return bytes(packet)
    else:
        packet_type = get_packet_type(is_ipv6, dns_name, protocol_identifier)
        packet = packet_mapping[packet_type]
        return create_raw_packet(packet, src_ip6 if is_ipv6 else src_ip, dst_ip6 if is_ipv6 else dst_ip, src_port,
                                 dst_port, dns_name, dns_type)
