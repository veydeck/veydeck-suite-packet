from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Padding, Raw

from app.services.packet_utils import (
    get_tcp_application_payload_len,
    get_transport_payload_bytes,
    get_transport_protocol,
    parse_raw_packet,
)
from app.services.pcap_parser import detect_protocol, packet_to_summary_dict


def test_parse_raw_packet_handles_ip_only_bytes():
    original = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=22)
    parsed = parse_raw_packet(bytes(original))

    assert IP in parsed
    assert TCP in parsed
    assert get_transport_protocol(parsed) == "TCP"


def test_tcp_payload_helpers_ignore_link_padding():
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="A")
        / Padding(b"\x00" * 6)
    )

    assert get_tcp_application_payload_len(pkt[TCP]) == 0
    assert get_transport_payload_bytes(pkt, "TCP") == b""


def test_tcp_payload_helpers_keep_real_raw_payload():
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="PA")
        / Raw(b"hello")
    )

    assert get_tcp_application_payload_len(pkt[TCP]) == 5
    assert get_transport_payload_bytes(pkt, "TCP") == b"hello"


def test_detect_protocol_classifies_http_only_for_request_response_layers():
    http_request = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="PA")
        / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    continuation = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="PA")
        / Raw(b"body bytes")
    )

    assert detect_protocol(parse_raw_packet(bytes(http_request))) == "HTTP"
    assert detect_protocol(continuation) == "TCP"


def test_packet_summary_extracts_endpoints_and_ports():
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=5353, dport=53)
        / Raw(b"payload")
    )

    summary = packet_to_summary_dict(7, pkt)

    assert summary["packet_index"] == 7
    assert summary["src_mac"] == "00:11:22:33:44:55"
    assert summary["dst_mac"] == "66:77:88:99:aa:bb"
    assert summary["src_ip"] == "10.0.0.1"
    assert summary["dst_ip"] == "10.0.0.2"
    assert summary["src_port"] == 5353
    assert summary["dst_port"] == 53
