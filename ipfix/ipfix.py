# Import pyfixbuf
import pyfixbuf
# If using the CERT information elements
import pyfixbuf.cert


def capture_ipfix():
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

    listener = pyfixbuf.Listener(import_session, "localhost", "tcp", "18001")
    import_buffer = listener.wait()
    import_buffer.set_record(import_rec)
    import_buffer.set_internal_template(import_template_id)

    exporter = pyfixbuf.Exporter()
    exporter.init_net("localhost", "udp", "9999")

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
        export_rec["maltrail"] = "ipfix stinkt"
        export_buffer.append(export_rec)
        export_rec.clear()

        print("Packet: " + str(packet_num))
        for field in data.iterfields():
            print(str(field.name) + ":" + str(field.value))
        print("-------------------------------------------\n\n")
        packet_num += 1
        if packet_num % 20 == 0:
            export_session.export_templates()
