# Import pyfixbuf
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Callable

import time
import pyfixbuf
# If using the CERT information elements
import pyfixbuf.cert

from scapy.compat import raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from core.settings import config

global_listener: Optional[pyfixbuf.Listener] = None
global_export_rec: Optional[pyfixbuf.Record] = None

print_debug = False


# def _process_packet(packet, sec, usec, ip_offset) -> None:
def capture_ipfix(process_packet: Callable[[any, any, any, any], None]):
    global global_listener, global_export_rec

    infomodel = pyfixbuf.InfoModel()
    pyfixbuf.cert.add_elements_to_model(infomodel)
    infomodel.add_element(pyfixbuf.InfoElement('maltrail', 1337, 1, type=pyfixbuf.DataType.STRING))

    import_template = pyfixbuf.Template(infomodel)
    export_template = pyfixbuf.Template(infomodel)

    relevant_import_elements = [
        pyfixbuf.InfoElementSpec("sourceIPv4Address"),
        pyfixbuf.InfoElementSpec("destinationIPv4Address"),
        pyfixbuf.InfoElementSpec("sourceIPv6Address"),
        pyfixbuf.InfoElementSpec("destinationIPv6Address"),
        pyfixbuf.InfoElementSpec("sourceTransportPort"),
        pyfixbuf.InfoElementSpec("destinationTransportPort"),
        pyfixbuf.InfoElementSpec("silkAppLabel"),
    ]

    relevant_export_elements = [
        pyfixbuf.InfoElementSpec("sourceIPv4Address"),
        pyfixbuf.InfoElementSpec("destinationIPv4Address"),
        pyfixbuf.InfoElementSpec("sourceIPv6Address"),
        pyfixbuf.InfoElementSpec("destinationIPv6Address"),
        pyfixbuf.InfoElementSpec("sourceTransportPort"),
        pyfixbuf.InfoElementSpec("destinationTransportPort"),
        pyfixbuf.InfoElementSpec("silkAppLabel"),
        pyfixbuf.InfoElementSpec("maltrail")
    ]

    import_template.add_spec_list(relevant_import_elements)
    export_template.add_spec_list(relevant_export_elements)

    import_session = pyfixbuf.Session(infomodel)
    export_session = pyfixbuf.Session(infomodel)

    import_template_id = import_session.add_internal_template(import_template)
    export_template_id = export_session.add_template(export_template)

    import_rec = pyfixbuf.Record(infomodel, import_template)
    export_rec = pyfixbuf.Record(infomodel, export_template)
    global_export_rec = export_rec

    listener = pyfixbuf.Listener(import_session, "localhost", config.ipfix_listen_protocol, config.ipfix_listen_port)
    global_listener = listener
    import_buffer = listener.wait()
    import_buffer.set_record(import_rec)
    import_buffer.set_internal_template(import_template_id)

    exporter = pyfixbuf.Exporter()
    exporter.init_net("localhost", config.ipfix_export_protocol, config.ipfix_export_port)

    export_buffer = pyfixbuf.Buffer(export_rec)
    export_buffer.init_export(export_session, exporter)
    export_buffer.set_internal_template(export_template_id)
    export_buffer.set_export_template(export_template_id)

    packet_num = 0
    while True:
        try:
            data = next(import_buffer)
        except StopIteration:
            if not listener:
                break
            else:
                import_buffer = listener.wait()
                import_buffer.set_record(import_rec)
                import_buffer.set_internal_template(import_template_id)
                continue

        if print_debug:
            print("Packet: " + str(packet_num))
        export_rec.copy(import_rec)
        sec, usec = [int(_) for _ in ("%.6f" % time.time()).split('.')]
        process_packet(ipfix_to_ip(data), sec, usec, 0)
        export_buffer.append(export_rec)
        export_rec.clear()

        if print_debug:
            for field in data.iterfields():
                print(str(field.name) + ":" + str(field.value))
            print("-------------------------------------------\n\n")
            print("\n")
        if packet_num % 20 == 0:
            export_session.export_templates()
        packet_num += 1


def ipfix_to_ip(data):
    src_ip: IPv4Address = data["sourceIPv4Address"]
    dst_ip: IPv4Address = data["destinationIPv4Address"]
    src_ip6: IPv6Address = data["sourceIPv6Address"]
    dst_ip6: IPv6Address = data["destinationIPv6Address"]
    packet = (IPv6(dst=dst_ip6, src=src_ip6) if str(src_ip) == "0.0.0.0" and str(dst_ip) == "0.0.0.0" else IP(
        dst=dst_ip,
        src=src_ip))
    if print_debug:
        print(packet)
    return raw(packet)


def write_maltrail_info_to_current_record(info: str):
    global global_export_rec
    if global_export_rec is not None:
        if print_debug:
            print("Written " + info + " to record!")
        global_export_rec["maltrail"] = info


def test_capture_ipfix(process_packet: Callable[[any, any, any, any], None]):
    while True:
        sec, usec = [int(_) for _ in ("%.6f" % time.time()).split('.')]
        process_packet(ipfix_to_ip(
            {"sourceIPv4Address": IPv4Address("0.0.0.0"),
             "destinationIPv4Address": IPv4Address("0.0.0.0"),
             "sourceIPv6Address": IPv6Address("2003:df:773f:1d00:55c8:415e:445d:86e9"),
             "destinationIPv6Address": IPv6Address("2a04:4e42:400:0:0:0:0:396")}), sec, usec, 0)
        time.sleep(1)


def cleanup():
    if global_listener:
        print("[i] Please add ipfix listen socket cleanup")
