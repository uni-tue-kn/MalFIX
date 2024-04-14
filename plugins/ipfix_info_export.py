#!/usr/bin/env python
from ipfix.ipfix import write_maltrail_info_to_current_record


def plugin(event_tuple, packet=None):
    sec, usec, src_ip, src_port, dst_ip, dst_port, proto, type, trail, info, reference = event_tuple
    print("Sending " + info + " to record!")
    write_maltrail_info_to_current_record(info)
