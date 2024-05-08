#!/usr/bin/env python
from ipfix.ipfix import global_malfix

print_debug = False


def plugin(event_tuple, packet=None):
    global_malfix.report_event(event_tuple)
