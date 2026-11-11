from tempfile import NamedTemporaryFile

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Padding, Raw
from scapy.utils import rdpcap, wrpcap
from starlette.requests import Request

from app.api.builders import build_pcap
from app.core.config import settings
from app.db.session import Base
from app.models.models import PacketSummary, PcapFile
from app.schemas.schemas import BuilderSchemaResponse, LayerSpec, PcapBuildRequest
from app.schemas.schemas import PacketPreviewRequest
from app.services.packet_builder import build_packet_from_spec, get_builder_schema
from app.services.packet_detail import packet_to_detail


def _create_test_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'packet-test.db'}")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_builder_schema_is_valid_and_includes_core_layers():
    schema = BuilderSchemaResponse(**get_builder_schema())
    layer_names = {layer.name for layer in schema.layers}

    assert {
        "Ether",
        "Dot1Q",
        "ARP",
        "IP",
        "TCP",
        "UDP",
        "DNS",
        "DNSQR",
        "Raw",
        "Padding",
    }.issubset(layer_names)


def test_build_arp_request_and_response_are_wrapped_in_ethernet_and_writable():
    request = {
        "layers": [
            {
                "name": "ARP",
                "fields": {
                    "op": "who-has",
                    "hwsrc": "00:11:22:33:44:55",
                    "hwdst": "00:00:00:00:00:00",
                    "psrc": "192.168.1.10",
                    "pdst": "192.168.1.1",
                },
            }
        ]
    }
    response = {
        "layers": [
            {
                "name": "ARP",
                "fields": {
                    "op": "is-at",
                    "hwsrc": "66:77:88:99:aa:bb",
                    "hwdst": "00:11:22:33:44:55",
                    "psrc": "192.168.1.1",
                    "pdst": "192.168.1.10",
                },
            }
        ]
    }

    packets = [build_packet_from_spec(request), build_packet_from_spec(response)]

    assert packets[0][Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert packets[0][ARP].op == 1
    assert packets[1][Ether].dst == "00:11:22:33:44:55"
    assert packets[1][ARP].op == 2
    with NamedTemporaryFile(suffix=".pcap") as file:
        wrpcap(file.name, packets)


def test_build_normalizes_numeric_protocol_enums_from_packet_detail():
    arp_request = build_packet_from_spec(
        {
            "layers": [
                {
                    "name": "ARP",
                    "fields": {
                        "op": "1",
                        "hwsrc": "00:11:22:33:44:55",
                        "hwdst": "00:00:00:00:00:00",
                        "psrc": "192.168.1.10",
                        "pdst": "192.168.1.1",
                    },
                }
            ]
        }
    )
    arp_response = build_packet_from_spec(
        {
            "layers": [
                {
                    "name": "ARP",
                    "fields": {
                        "op": "2",
                        "hwsrc": "66:77:88:99:aa:bb",
                        "hwdst": "00:11:22:33:44:55",
                        "psrc": "192.168.1.1",
                        "pdst": "192.168.1.10",
                    },
                }
            ]
        }
    )
    dns_query = build_packet_from_spec(
        {
            "layers": [
                {"name": "IP", "fields": {"src": "192.168.1.10", "dst": "8.8.8.8"}},
                {"name": "UDP", "fields": {"sport": "51234", "dport": "53"}},
                {"name": "DNS", "fields": {"id": "1234", "qr": "0", "rd": "1"}},
                {
                    "name": "DNSQR",
                    "fields": {"qname": "example.com", "qtype": "28"},
                },
            ]
        }
    )
    tcp_syn_ack = build_packet_from_spec(
        {
            "layers": [
                {
                    "name": "IP",
                    "fields": {"src": "192.168.1.10", "dst": "192.168.1.20"},
                },
                {
                    "name": "TCP",
                    "fields": {"sport": "12345", "dport": "80", "flags": "18"},
                },
            ]
        }
    )
    ip_dont_fragment = build_packet_from_spec(
        {
            "layers": [
                {
                    "name": "IP",
                    "fields": {
                        "src": "192.168.1.10",
                        "dst": "192.168.1.20",
                        "flags": "2",
                    },
                }
            ]
        }
    )

    assert arp_request[ARP].op == 1
    assert arp_response[ARP].op == 2
    assert dns_query[DNSQR].qtype == 28
    assert str(tcp_syn_ack[TCP].flags) == "SA"
    assert str(ip_dont_fragment[IP].flags) == "DF"


def test_build_tcp_raw_payload_decodes_escaped_bytes_and_recalculates_checksum():
    pkt = build_packet_from_spec(
        {
            "layers": [
                {"name": "Ether", "fields": {}},
                {
                    "name": "IP",
                    "fields": {"src": "192.168.1.10", "dst": "192.168.1.20"},
                },
                {
                    "name": "TCP",
                    "fields": {"sport": "12345", "dport": "80", "flags": "PA"},
                },
                {"name": "Raw", "fields": {"load": "GET / HTTP/1.1\\r\\n\\r\\n"}},
            ]
        }
    )

    assert IP in pkt
    assert TCP in pkt
    assert HTTPRequest in pkt
    assert bytes(pkt[TCP].payload).endswith(b"\r\n\r\n")
    assert pkt[IP].chksum is not None
    assert pkt[TCP].chksum is not None


def test_build_dns_query_appends_dot_to_qname():
    pkt = build_packet_from_spec(
        {
            "layers": [
                {"name": "Ether", "fields": {}},
                {"name": "IP", "fields": {"src": "192.168.1.10", "dst": "8.8.8.8"}},
                {"name": "UDP", "fields": {"sport": "51234", "dport": "53"}},
                {"name": "DNS", "fields": {"id": "1234", "qr": "0", "rd": "1"}},
                {"name": "DNSQR", "fields": {"qname": "example.com", "qtype": "A"}},
            ]
        }
    )

    assert DNS in pkt
    assert DNSQR in pkt
    assert pkt[DNSQR].qname == b"example.com."


def test_build_rejects_unsupported_layer_and_invalid_integer():
    with pytest.raises(ValueError, match="Unsupported layer protocol"):
        build_packet_from_spec({"layers": [{"name": "HTTP", "fields": {}}]})

    with pytest.raises(ValueError, match="Invalid value for TCP.sport"):
        build_packet_from_spec(
            {"layers": [{"name": "TCP", "fields": {"sport": "not-a-number"}}]}
        )


def test_build_pcap_records_parent_before_packet_summaries(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DATA_ROOT", tmp_path)
    db = _create_test_session(tmp_path)
    request = PcapBuildRequest(
        filename="generated.pcap",
        packets=[
            PacketPreviewRequest(
                layers=[
                    LayerSpec(name="Ether", fields={}),
                    LayerSpec(
                        name="IP",
                        fields={"src": "192.168.1.10", "dst": "93.184.216.34"},
                    ),
                    LayerSpec(
                        name="TCP",
                        fields={"sport": "49152", "dport": "80", "flags": "PA"},
                    ),
                    LayerSpec(
                        name="Raw", fields={"load": "GET / HTTP/1.1\\r\\n\\r\\n"}
                    ),
                ]
            )
        ],
    )

    try:
        http_request = Request({"type": "http", "headers": []})
        response = build_pcap(request, http_request, db)

        assert response["pcap_id"]
        assert (
            db.query(PcapFile).filter(PcapFile.id == response["pcap_id"]).count() == 1
        )
        assert (
            db.query(PacketSummary)
            .filter(PacketSummary.pcap_id == response["pcap_id"])
            .count()
            == 1
        )
    finally:
        db.close()


@pytest.mark.parametrize("padding", [b"\x00" * 18, b"\x00\xff\x80\x5c\x09\x0a\x0d"])
def test_builder_preserves_arp_padding_from_packet_details_and_pcap(tmp_path, padding):
    """详情中的填充原样进入构造器，导出 PCAP 保留零字节及非零字节。"""
    original = (
        bytes(
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
            / ARP(hwsrc="00:11:22:33:44:55", psrc="192.0.2.1", pdst="192.0.2.2")
        )
        + padding
    )
    detail = packet_to_detail(0, original)
    kept_fields = {
        "Ethernet": {"src", "dst"},
        "ARP": {"op", "hwsrc", "hwdst", "psrc", "pdst"},
        "Padding": {"load"},
    }
    spec = {
        "layers": [
            {
                "name": "Ether" if layer["name"] == "Ethernet" else layer["name"],
                "fields": {
                    field: value
                    for field, value in layer["fields"].items()
                    if field in kept_fields[layer["name"]]
                },
            }
            for layer in detail["layers"]
        ]
    }
    rebuilt = build_packet_from_spec(spec)
    assert bytes(rebuilt) == original
    assert bytes(rebuilt[Padding]) == padding
    output = tmp_path / "padded.pcap"
    wrpcap(str(output), [rebuilt])
    assert bytes(rdpcap(str(output))[0]) == original


@pytest.mark.parametrize("layer_name", ["TCP", "UDP"])
def test_padding_is_excluded_from_network_length_and_transport_checksum(layer_name):
    """业务负载保留在 IP 包内，尾部填充不计入长度或传输层校验和。"""
    transport = TCP if layer_name == "TCP" else UDP
    layers = [
        {"name": "Ether", "fields": {}},
        {"name": "IP", "fields": {"src": "192.0.2.1", "dst": "192.0.2.2"}},
        {"name": layer_name, "fields": {"sport": "12345", "dport": "54321"}},
        {"name": "Raw", "fields": {"load": r"abc\x00\xff"}},
    ]
    plain = build_packet_from_spec({"layers": layers})
    padded = build_packet_from_spec(
        {"layers": layers + [{"name": "Padding", "fields": {"load": r"\x00\xff\x00"}}]}
    )
    assert bytes(padded) == bytes(plain) + b"\x00\xff\x00"
    assert padded[IP].len == plain[IP].len
    assert padded[IP].chksum == plain[IP].chksum
    assert padded[transport].chksum == plain[transport].chksum
    assert padded[Raw].load == b"abc\x00\xff"
    if layer_name == "UDP":
        assert padded[UDP].len == plain[UDP].len


@pytest.mark.parametrize(
    "layers",
    [
        [{"name": "Padding", "fields": {"load": "pad"}}],
        [
            {"name": "Ether", "fields": {}},
            {"name": "Padding", "fields": {"load": "pad"}},
            {"name": "IP", "fields": {}},
        ],
    ],
)
def test_builder_rejects_padding_before_protocol_layers(layers):
    """拒绝无协议或非尾部的填充，避免生成不符合预期的协议长度。"""
    with pytest.raises(ValueError, match="Padding must be the final layer"):
        build_packet_from_spec({"layers": layers})
