# Import pyfixbuf
import time
from typing import Optional, Callable

import pyfixbuf
# If using the CERT information elements
import pyfixbuf.cert

from core.settings import config
from ipfix.ipfix_to_ip import ipfix_to_ip
from ipfix.relevant_information_elements import relevant_import_elements, relevant_export_elements
from ipfix.yaf_dns import extract_dns_info

global_listener: Optional[pyfixbuf.Listener] = None
global_export_rec: Optional[pyfixbuf.Record] = None

print_debug = False


# def _process_packet(packet, sec, usec, ip_offset) -> None:
def capture_ipfix(process_packet: Callable[[any, any, any, any], None]):
    global global_listener, global_export_rec

    infomodel = pyfixbuf.InfoModel()
    pyfixbuf.cert.add_elements_to_model(infomodel)
    infomodel.add_element(pyfixbuf.InfoElement('maltrail', 420, 1, type=pyfixbuf.DataType.STRING))
    infomodel.add_element(pyfixbuf.InfoElement('dnsName', 420, 2, type=pyfixbuf.DataType.STRING))
    infomodel.add_element(pyfixbuf.InfoElement('dnsType', 420, 3, type=pyfixbuf.DataType.UINT8))

    import_template = pyfixbuf.Template(infomodel)
    export_template = pyfixbuf.Template(infomodel)

    import_template.add_spec_list(relevant_import_elements)
    export_template.add_spec_list(relevant_export_elements)

    import_session = pyfixbuf.Session(infomodel)
    export_session = pyfixbuf.Session(infomodel)

    import_template_id = import_session.add_internal_template(import_template)
    export_template_id = export_session.add_template(export_template)

    import_rec = pyfixbuf.Record(infomodel, import_template)
    export_rec = pyfixbuf.Record(infomodel, export_template)
    global_export_rec = export_rec

    listener = pyfixbuf.Listener(import_session, "0.0.0.0", config.ipfix_listen_protocol, config.ipfix_listen_port)
    global_listener = listener
    import_buffer = listener.wait()
    import_buffer.set_record(import_rec)
    import_buffer.set_internal_template(import_template_id)

    exporter = pyfixbuf.Exporter()
    exporter.init_net(config.ipfix_export_host, config.ipfix_export_protocol, config.ipfix_export_port)

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

        export_rec.copy(import_rec)
        if print_debug:
            print("Packet: " + str(packet_num))
        dns_info = extract_dns_info(data)
        if dns_info[1] != 0:
            import_rec["dnsName"] = dns_info[0]
            import_rec["dnsType"] = dns_info[1]
            export_rec["dnsName"] = dns_info[0]
            export_rec["dnsType"] = dns_info[1]

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


def write_maltrail_info_to_current_record(info: str):
    global global_export_rec
    if global_export_rec is not None:
        if print_debug:
            print("Written " + info + " to record!")
        global_export_rec["maltrail"] = info
