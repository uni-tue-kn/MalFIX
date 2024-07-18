import pyfixbuf

import_ie = [
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
    pyfixbuf.InfoElementSpec("dnsType")
]

export_ie = [
    pyfixbuf.InfoElementSpec("sourceIPv4Address"),
    pyfixbuf.InfoElementSpec("destinationIPv4Address"),
    pyfixbuf.InfoElementSpec("sourceIPv6Address"),
    pyfixbuf.InfoElementSpec("destinationIPv6Address"),

    pyfixbuf.InfoElementSpec("sourceTransportPort"),
    pyfixbuf.InfoElementSpec("destinationTransportPort"),

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
    pyfixbuf.InfoElementSpec("malfix_type"),
    pyfixbuf.InfoElementSpec("malfix_trail"),
    pyfixbuf.InfoElementSpec("malfix_info"),
    pyfixbuf.InfoElementSpec("malfix_reference"),
]


maltrail_ie = [
    pyfixbuf.InfoElementSpec("sourceIPv4Address"),
    pyfixbuf.InfoElementSpec("destinationIPv4Address"),
    pyfixbuf.InfoElementSpec("sourceIPv6Address"),
    pyfixbuf.InfoElementSpec("destinationIPv6Address"),

    pyfixbuf.InfoElementSpec("sourceTransportPort"),
    pyfixbuf.InfoElementSpec("destinationTransportPort"),

    pyfixbuf.InfoElementSpec("protocolIdentifier"),

    pyfixbuf.InfoElementSpec("dnsName"),
    pyfixbuf.InfoElementSpec("dnsType"),

    pyfixbuf.InfoElementSpec("malfix_type"),
    pyfixbuf.InfoElementSpec("malfix_trail"),
    pyfixbuf.InfoElementSpec("malfix_info"),
    pyfixbuf.InfoElementSpec("malfix_reference"),
]
