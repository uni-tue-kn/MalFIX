import pyfixbuf

relevant_import_elements = [
    pyfixbuf.InfoElementSpec("sourceIPv4Address"),
    pyfixbuf.InfoElementSpec("destinationIPv4Address"),
    pyfixbuf.InfoElementSpec("sourceIPv6Address"),
    pyfixbuf.InfoElementSpec("destinationIPv6Address"),

    pyfixbuf.InfoElementSpec("sourceTransportPort"),
    pyfixbuf.InfoElementSpec("destinationTransportPort"),

    pyfixbuf.InfoElementSpec("icmpTypeIPv4"),
    pyfixbuf.InfoElementSpec("icmpCodeIPv4"),

    pyfixbuf.InfoElementSpec("protocolIdentifier"),
    pyfixbuf.InfoElementSpec("silkAppLabel"),

    pyfixbuf.InfoElementSpec("packetTotalCount"),
    pyfixbuf.InfoElementSpec("octetTotalCount"),
    pyfixbuf.InfoElementSpec("reversePacketTotalCount"),
    pyfixbuf.InfoElementSpec("reverseOctetTotalCount"),

    pyfixbuf.InfoElementSpec("packetDeltaCount"),
    pyfixbuf.InfoElementSpec("octetDeltaCount"),
    pyfixbuf.InfoElementSpec("reversePacketDeltaCount"),
    pyfixbuf.InfoElementSpec("reverseOctetDeltaCount"),

    pyfixbuf.InfoElementSpec("dnsName"),
    pyfixbuf.InfoElementSpec("dnsType"),

    pyfixbuf.InfoElementSpec("subTemplateMultiList")
]

relevant_export_elements = [
    pyfixbuf.InfoElementSpec("sourceIPv4Address"),
    pyfixbuf.InfoElementSpec("destinationIPv4Address"),
    pyfixbuf.InfoElementSpec("sourceIPv6Address"),
    pyfixbuf.InfoElementSpec("destinationIPv6Address"),

    pyfixbuf.InfoElementSpec("sourceTransportPort"),
    pyfixbuf.InfoElementSpec("destinationTransportPort"),

    pyfixbuf.InfoElementSpec("protocolIdentifier"),
    pyfixbuf.InfoElementSpec("silkAppLabel"),

    pyfixbuf.InfoElementSpec("maltrail"),

    pyfixbuf.InfoElementSpec("packetTotalCount"),
    pyfixbuf.InfoElementSpec("octetTotalCount"),
    pyfixbuf.InfoElementSpec("reversePacketTotalCount"),
    pyfixbuf.InfoElementSpec("reverseOctetTotalCount"),

    pyfixbuf.InfoElementSpec("packetDeltaCount"),
    pyfixbuf.InfoElementSpec("octetDeltaCount"),
    pyfixbuf.InfoElementSpec("reversePacketDeltaCount"),
    pyfixbuf.InfoElementSpec("reverseOctetDeltaCount"),

    pyfixbuf.InfoElementSpec("dnsName"),
    pyfixbuf.InfoElementSpec("dnsType")
]
