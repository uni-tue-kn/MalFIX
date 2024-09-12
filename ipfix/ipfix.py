import random
import sys
import time
from numbers import Number
from typing import Optional, Callable, Tuple

import pyfixbuf
import pyfixbuf.cert

from core.settings import config
from ipfix import helper
from ipfix.information_elements import import_ie, maltrail_ie, export_ie
from ipfix.ipfix_to_ip import ipfix_to_ip
from sensor import _process_packet

print_debug = False


def _print(text):
    if print_debug:
        print(text.as_dict() if isinstance(text, pyfixbuf.Record) else text)


class MalFix:
    def __init__(self, _process_packet: Callable[[any, any, any, any], None]):
        self._process_packet: Callable[[any, any, any, any], None] = _process_packet
        self._last_export_time = 0

        self._export_session: Optional[pyfixbuf.Session] = None
        self._import_buffer: Optional[pyfixbuf.Buffer] = None
        self._export_buffer: Optional[pyfixbuf.Buffer] = None
        self._listener: Optional[pyfixbuf.Listener] = None
        self._export_rec: Optional[pyfixbuf.Record] = None
        self._import_rec: Optional[pyfixbuf.Record] = None
        self._import_template_id: Number = 0
        self._import_elements: Optional[list] = import_ie
        self._export_elements: Optional[list] = None

        self._last_report_time = time.time()
        self._delta_packet_count = 0
        self._total_packet_count = 0

    def setup_pyfixbuf(self):
        self._export_elements = export_ie if config.ipfix_forward else maltrail_ie
        infomodel = pyfixbuf.InfoModel()
        pyfixbuf.cert.add_elements_to_model(infomodel)
        infomodel.add_element_list([pyfixbuf.InfoElement('dnsName', 420, 1, type=pyfixbuf.DataType.STRING),
                                    pyfixbuf.InfoElement('dnsType', 420, 2, type=pyfixbuf.DataType.UINT8),
                                    pyfixbuf.InfoElement("malfix_type", 420, 3, type=pyfixbuf.DataType.STRING),
                                    pyfixbuf.InfoElement("malfix_trail", 420, 4, type=pyfixbuf.DataType.STRING),
                                    pyfixbuf.InfoElement("malfix_info", 420, 5, type=pyfixbuf.DataType.STRING),
                                    pyfixbuf.InfoElement("malfix_reference", 420, 6, type=pyfixbuf.DataType.STRING),
                                    ])
        self._setup_import(infomodel)
        self._setup_export(infomodel)

    def _setup_import(self, infomodel: pyfixbuf.InfoModel):
        import_template = pyfixbuf.Template(infomodel)
        import_template.add_spec_list(self._import_elements)
        import_session = pyfixbuf.Session(infomodel)
        self._import_template_id = import_session.add_internal_template(import_template)
        self._import_rec = pyfixbuf.Record(infomodel, import_template)
        self._listener = pyfixbuf.Listener(import_session, "0.0.0.0", config.ipfix_listen_protocol,
                                           config.ipfix_listen_port)

    def _setup_export(self, infomodel: pyfixbuf.InfoModel):
        export_template = pyfixbuf.Template(infomodel)
        export_template.add_spec_list(self._export_elements)
        self._export_session = pyfixbuf.Session(infomodel)
        export_template_id = self._export_session.add_template(export_template)
        self._export_rec = pyfixbuf.Record(infomodel, export_template)
        exporter = pyfixbuf.Exporter()
        exporter.init_net(config.ipfix_export_host, config.ipfix_export_protocol, config.ipfix_export_port)
        self._export_buffer = pyfixbuf.Buffer(self._export_rec)
        self._export_buffer.init_export(self._export_session, exporter)
        self._export_buffer.set_internal_template(export_template_id)
        self._export_buffer.set_export_template(export_template_id)

    def capture_ipfix(self):
        while True:
            try:
                data = next(self._import_buffer)
                if config.ipfix_forward:
                    self._export_rec.copy(data)
                _print("Receiving: ")
                _print(data)
            except (StopIteration, TypeError):
                if not self._listener:
                    break
                else:
                    self._import_buffer = self._listener.wait()
                    self._import_buffer.set_record(self._import_rec)
                    self._import_buffer.set_internal_template(self._import_template_id)
                    continue
            dns_info: Optional[Tuple[str, Number]] = None
            if "dnsName" in data and data['dnsName'] != "" and data['dnsName'] is not None:
                dns_info = (data['dnsName'], data['dnsType'])
                self._export_rec["dnsName"] = dns_info[0]
                self._export_rec["dnsType"] = dns_info[1]
            sec, usec = [int(_) for _ in ("%.6f" % time.time()).split('.')]
            self._process_packet(ipfix_to_ip(data, dns_info), sec + random.randint(0, sys.maxsize), usec, 0)
            if config.ipfix_forward:
                self._send_ipfix()

    def report_event(self, event: Tuple):
        helper.write_maltrail_to_record(event, self._export_rec, config.ipfix_forward)
        if not config.ipfix_forward:
            self._send_ipfix()

    def _send_ipfix(self):
        _print("Sending: ")
        _print(self._export_rec)
        current_time = time.time()
        self._export_template(current_time)
        self._export_buffer.append(self._export_rec)
        self._export_rec.clear()
        self._record_stats(current_time)

    def _export_template(self, current_time):
        if current_time - self._last_export_time > (60 * 10):
            self._export_session.export_templates()
            self._last_export_time = current_time

    def _record_stats(self, current_time):
        self._delta_packet_count += 1
        elapsed_time = current_time - self._last_report_time
        if elapsed_time >= 10.0:  # Report packets/sec every second
            packets_per_sec = self._delta_packet_count / elapsed_time
            self._total_packet_count += self._delta_packet_count
            print(f"records/sec: {round(packets_per_sec)}, total: {self._total_packet_count}")
            self._delta_packet_count = 0
            self._last_report_time = current_time


global_malfix = MalFix(_process_packet)
