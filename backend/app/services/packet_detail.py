import logging
from typing import Any

from scapy.packet import Packet

from app.services.packet_utils import parse_raw_packet
from app.services.protocol_decode import decode_application_protocols

logger = logging.getLogger(__name__)


def bytes_to_escaped_string(val: bytes) -> str:
    res = []
    for b in val:
        if b == 9:  # \t
            res.append(r"\t")
        elif b == 10:  # \n
            res.append(r"\n")
        elif b == 13:  # \r
            res.append(r"\r")
        elif b == 92:  # \\
            res.append(r"\\")
        elif 32 <= b < 127:
            res.append(chr(b))
        else:
            res.append(f"\\x{b:02x}")
    return "".join(res)


def scapy_value_to_json(value: Any) -> Any:
    """递归将 Scapy 字段值转换为 JSON 可接受的类型"""
    if isinstance(value, bytes):
        return bytes_to_escaped_string(value)

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    if isinstance(value, list):
        return [scapy_value_to_json(v) for v in value]

    if isinstance(value, dict):
        return {k: scapy_value_to_json(v) for k, v in value.items()}

    # 对于 Scapy 自定义类，如 Flags, 强转为 string/int
    return str(value)


def packet_to_detail(index: int, raw_packet: bytes) -> dict:
    """
    根据原始字节，反序列化为 Scapy Packet，并遍历层析字段。
    """
    pkt = parse_raw_packet(raw_packet)

    layers = []
    current = pkt
    while isinstance(current, Packet):
        fields = {}
        for field_name, field_value in current.fields.items():
            fields[field_name] = scapy_value_to_json(field_value)

        layers.append({"name": current.name, "fields": fields})
        current = current.payload
        if not isinstance(current, Packet) or current.name == "NoPayload":
            break

    return {
        "index": index,
        "summary": pkt.summary() if hasattr(pkt, "summary") else "",
        "length": len(raw_packet),
        "layers": layers,
        "hex": raw_packet.hex(),
        "protocol_insights": decode_application_protocols(pkt),
    }
