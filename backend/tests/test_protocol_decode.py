from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from app.services.pcap_parser import detect_protocol
from app.services.protocol_decode import decode_application_protocols


def packet_with_payload(payload: bytes, sport: int, dport: int):
    return (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=sport, dport=dport, flags="PA")
        / Raw(payload)
    )


def test_decode_ssh_banner():
    pkt = packet_with_payload(b"SSH-2.0-OpenSSH_9.6\r\n", 22, 54321)

    insights = decode_application_protocols(pkt)

    assert detect_protocol(pkt) == "SSH"
    assert insights[0]["fields"]["protocol_version"] == "2.0"
    assert insights[0]["fields"]["software"] == "OpenSSH_9.6"


def test_decode_ftp_command_and_mask_password():
    pkt = packet_with_payload(b"PASS secret\r\n", 54321, 21)

    insights = decode_application_protocols(pkt)

    assert detect_protocol(pkt) == "FTP"
    assert insights[0]["fields"]["command"] == "PASS"
    assert insights[0]["fields"]["argument"] == "***"


def test_decode_mqtt_connect():
    payload = b"\x10\x12\x00\x04MQTT\x04\x02\x00<\x00\x06client"
    pkt = packet_with_payload(payload, 54321, 1883)

    insights = decode_application_protocols(pkt)

    assert detect_protocol(pkt) == "MQTT"
    assert insights[0]["fields"]["packet_type"] == "CONNECT"
    assert insights[0]["fields"]["client_id"] == "client"


def test_decode_http2_preface():
    pkt = packet_with_payload(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 54321, 80)

    insights = decode_application_protocols(pkt)

    assert detect_protocol(pkt) == "HTTP/2"
    assert insights[0]["fields"]["preface"] == "PRI * HTTP/2.0"


def test_decode_tls_client_hello_sni_and_alpn():
    client_hello = bytes.fromhex(
        "".join(
            [
                "160301004c",
                "01000048",
                "0303",
                "00" * 32,
                "00",
                "0002",
                "1301",
                "01",
                "00",
                "001d",
                "0000",
                "0010",
                "000e",
                "0000",
                "0b",
                "6578616d706c652e636f6d",
                "0010",
                "0005",
                "0003",
                "02",
                "6832",
            ]
        )
    )
    pkt = packet_with_payload(client_hello, 54321, 443)

    insights = decode_application_protocols(pkt)

    assert detect_protocol(pkt) == "TLS"
    assert insights[0]["fields"]["handshake_type"] == "ClientHello"
    assert insights[0]["fields"]["sni"] == "example.com"
    assert insights[0]["fields"]["alpn"] == "h2"
