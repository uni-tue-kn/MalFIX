import ipaddress
from typing import Tuple

import pyfixbuf

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


def maltrail_event_to_string(event: Tuple) -> str:
    _, _, _, _, _, _, _, mal_type, trail, info, reference = event
    return f"mal_type: {mal_type} trail: {trail} info: {info} reference: {reference}"
