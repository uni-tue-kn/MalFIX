import ipaddress
from typing import Tuple

import pyfixbuf

print_debug = False
yaf = False

# Is needed because of a bug in the pyfixbuf lib "pyfixbuf_set_value"
malfix_type = ""
malfix_trail = ""
malfix_info = ""
malfix_reference = ""


def write_maltrail_to_record(event: Tuple, record: pyfixbuf.Record, maltrail_only: bool):
    global malfix_type, malfix_trail, malfix_info, malfix_reference
    _, _, _, _, _, _, _, mal_type, trail, info, reference = event
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
    malfix_type = mal_type
    malfix_trail = trail
    malfix_info = info
    malfix_reference = reference
    record["malfix_type"] = malfix_type
    record["malfix_trail"] = malfix_trail
    record["malfix_info"] = malfix_info
    record["malfix_reference"] = malfix_reference
