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

print_debug = True


def _print(text):
    if print_debug:
        print(text)


class MalFix:
    def __init__(self, _process_packet: Callable[[any, any, any, any], None]):
        self._initialized: bool = False
        self._process_packet: Callable[[any, any, any, any], None] = _process_packet
        self._packet_count: int = 0

        self._export_session: Optional[pyfixbuf.Session] = None
        self._import_buffer: Optional[pyfixbuf.Buffer] = None
        self._export_buffer: Optional[pyfixbuf.Buffer] = None
        self._listener: Optional[pyfixbuf.Listener] = None
        self._export_rec: Optional[pyfixbuf.Record] = None
        self._import_rec: Optional[pyfixbuf.Record] = None
        self._import_template_id: Number = 0
        self._import_elements: Optional[list] = import_ie
        self._export_elements: Optional[list] = None

        self._start_time = time.time()
        self._last_report_time = self._start_time
        self._delta_packet_count = 0
        self._total_packet_count = 0

        self._start_processing = None
        self._processing_time_list = []

    def setup_pyfixbuf(self):
        self._export_elements = export_ie if config.ipfix_pass_through else maltrail_ie
        infomodel = pyfixbuf.InfoModel()
        pyfixbuf.cert.add_elements_to_model(infomodel)
        infomodel.add_element(pyfixbuf.InfoElement('maltrail', 420, 1, type=pyfixbuf.DataType.STRING))
        infomodel.add_element(pyfixbuf.InfoElement('dnsName', 420, 2, type=pyfixbuf.DataType.STRING))
        infomodel.add_element(pyfixbuf.InfoElement('dnsType', 420, 3, type=pyfixbuf.DataType.UINT8))
        self._setup_import(infomodel)
        self._setup_export(infomodel)
        self._initialized = True

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
        count = 0
        self._import_buffer = self._listener.wait()
        self._import_buffer.set_record(self._import_rec)
        self._import_buffer.set_internal_template(self._import_template_id)
        if not self._initialized:
            print('IPFix not init!')
            return
        while True:
            try:
                self._start_processing = time.time()
                data = next(self._import_buffer)
                if config.ipfix_pass_through:
                    self._export_rec.copy(data)
                _print("Receiving: ")
                _print(data.as_dict())
            except StopIteration:
                if not self._listener:
                    break
                else:
                    self._import_buffer = self._listener.wait()
                    self._import_buffer.set_record(self._import_rec)
                    self._import_buffer.set_internal_template(self._import_template_id)
                    continue

            dns_info: Optional[Tuple[str, Number]] = None
            if "dnsName" in data:
                dns_info = (data['dnsName'], data['dnsType'])
                self._export_rec["dnsName"] = dns_info[0]
                self._export_rec["dnsType"] = dns_info[1]

            count = (count + 1) % 100000
            sec, usec = [int(_) for _ in ("%.6f" % time.time()).split('.')]
            self._process_packet(ipfix_to_ip(data, dns_info), sec+count, usec, 0)

            if config.ipfix_pass_through:
                self._send_ipfix()

    def _send_ipfix(self):
        _print("Sending: ")
        _print(self._export_rec.as_dict())
        self._export_buffer.append(self._export_rec)
        self._export_rec.clear()

        self._delta_packet_count += 1
        current_time = time.time()
        self._processing_time_list.append(current_time - self._start_processing)
        elapsed_time = current_time - self._last_report_time
        if elapsed_time >= 10.0:  # Report packets/sec every second
            packets_per_sec = self._delta_packet_count / elapsed_time
            self._total_packet_count += self._delta_packet_count
            print(f"records/sec: {round(packets_per_sec)}, total: {self._total_packet_count}")
            print(f"per flow: {round(sum(self._processing_time_list) / self._delta_packet_count, 6)}")
            self._processing_time_list = []
            self._delta_packet_count = 0
            self._last_report_time = current_time
        print(self._total_packet_count + self._delta_packet_count)
        if self._packet_count % 20000 == 0:
            self._export_session.export_templates()
            self._packet_count = 1
        else:
            self._packet_count += 1

    def report_event(self, event: Tuple):
        helper.write_maltrail_to_record(event, self._export_rec, config.ipfix_pass_through)
        if not config.ipfix_pass_through:
            self._send_ipfix()


global_malfix = MalFix(_process_packet)
