from typing import Literal

from scapy.config import conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Padding


TransportProtocol = Literal["TCP", "UDP"]


def parse_raw_packet(raw_packet: bytes) -> Packet:
    pkt = None
    try:
        pkt = Ether(raw_packet)
    except Exception:
        pass

    if not pkt or not pkt.payload or isinstance(pkt.payload, conf.raw_layer):
        try:
            pkt = IP(raw_packet)
        except Exception:
            try:
                pkt = IPv6(raw_packet)
            except Exception:
                pkt = conf.raw_layer(raw_packet)

    return pkt


def get_transport_protocol(pkt: Packet) -> TransportProtocol | None:
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    return None


def get_transport_payload_bytes(
    pkt: Packet, protocol: TransportProtocol
) -> bytes | None:
    if protocol == "TCP":
        if TCP not in pkt:
            return None
        return get_tcp_application_payload_bytes(pkt[TCP])

    if UDP not in pkt:
        return None
    udp_layer = pkt[UDP]
    if not udp_layer.payload or getattr(udp_layer.payload, "name", "") == "NoPayload":
        return b""
    return bytes(udp_layer.payload)


def get_tcp_application_payload_bytes(tcp_layer: TCP) -> bytes:
    if not tcp_layer.payload or getattr(tcp_layer.payload, "name", "") == "NoPayload":
        return b""

    payload_bytes = bytes(tcp_layer.payload)
    if Padding in tcp_layer.payload:
        padding_bytes = bytes(tcp_layer.payload[Padding])
        if padding_bytes and payload_bytes.endswith(padding_bytes):
            payload_bytes = payload_bytes[: -len(padding_bytes)]

    return payload_bytes


def get_tcp_application_payload_len(tcp_layer: TCP) -> int:
    return len(get_tcp_application_payload_bytes(tcp_layer))
