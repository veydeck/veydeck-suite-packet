import logging
from typing import Any, Dict
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

logger = logging.getLogger(__name__)

ARP_OP_ALIASES = {
    "1": "who-has",
    "who-has": "who-has",
    "2": "is-at",
    "is-at": "is-at",
}

DNS_QTYPE_ALIASES = {
    "1": "A",
    "A": "A",
    "5": "CNAME",
    "CNAME": "CNAME",
    "15": "MX",
    "MX": "MX",
    "16": "TXT",
    "TXT": "TXT",
    "28": "AAAA",
    "AAAA": "AAAA",
}

TCP_FLAG_BITS = (
    (0x01, "F"),
    (0x02, "S"),
    (0x04, "R"),
    (0x08, "P"),
    (0x10, "A"),
    (0x20, "U"),
    (0x40, "E"),
    (0x80, "C"),
)

IP_FLAG_ALIASES = {
    "0": "",
    "1": "MF",
    "2": "DF",
    "3": "MF+DF",
    "DF": "DF",
    "MF": "MF",
}

LAYER_MAP = {
    "Ether": Ether,
    "Dot1Q": Dot1Q,
    "ARP": ARP,
    "IP": IP,
    "IPv6": IPv6,
    "TCP": TCP,
    "UDP": UDP,
    "ICMP": ICMP,
    "DNS": DNS,
    "DNSQR": DNSQR,
    "Raw": Raw,
}

# 字段白名单以及其期望的数据类型转换函数
ALLOWED_FIELDS = {
    "Ether": {"src": str, "dst": str, "type": int},
    "Dot1Q": {"vlan": int, "prio": int, "type": int},
    "ARP": {
        "op": str,
        "hwsrc": str,
        "hwdst": str,
        "psrc": str,
        "pdst": str,
    },
    "IP": {"src": str, "dst": str, "ttl": int, "id": int, "flags": str, "proto": int},
    "IPv6": {"src": str, "dst": str, "hlim": int},
    "TCP": {
        "sport": int,
        "dport": int,
        "seq": int,
        "ack": int,
        "flags": str,
        "window": int,
    },
    "UDP": {"sport": int, "dport": int},
    "ICMP": {"type": int, "code": int, "id": int, "seq": int},
    "DNS": {"id": int, "qr": int, "opcode": int, "rd": int, "ra": int},
    "DNSQR": {
        "qname": str,
        "qtype": str,  # qtype/qclass 可以是整数或者字符串名，如 'A'，在 Python 中支持直接传入
        "qclass": str,
    },
    "Raw": {"load": str},
}

BUILDER_SCHEMA = {
    "layers": [
        {
            "name": "Ether",
            "label": "Ethernet",
            "fields": [
                {"key": "src", "label": "src", "placeholder": "00:11:22:33:44:55"},
                {"key": "dst", "label": "dst", "placeholder": "ff:ff:ff:ff:ff:ff"},
                {
                    "key": "type",
                    "label": "type",
                    "placeholder": "2048",
                    "advanced": True,
                    "auto": True,
                },
            ],
        },
        {
            "name": "Dot1Q",
            "label": "802.1Q VLAN",
            "fields": [
                {
                    "key": "vlan",
                    "label": "vlan",
                    "type": "number",
                    "default": "1",
                    "placeholder": "1",
                },
                {
                    "key": "prio",
                    "label": "prio",
                    "type": "number",
                    "default": "0",
                    "placeholder": "0",
                },
                {
                    "key": "type",
                    "label": "type",
                    "placeholder": "2048",
                    "advanced": True,
                    "auto": True,
                },
            ],
        },
        {
            "name": "ARP",
            "label": "ARP",
            "fields": [
                {
                    "key": "op",
                    "label": "op",
                    "type": "select",
                    "default": "who-has",
                    "options": [
                        {"label": "who-has", "value": "who-has"},
                        {"label": "is-at", "value": "is-at"},
                    ],
                },
                {
                    "key": "hwsrc",
                    "label": "hwsrc",
                    "default": "00:11:22:33:44:55",
                    "placeholder": "00:11:22:33:44:55",
                },
                {
                    "key": "hwdst",
                    "label": "hwdst",
                    "default": "00:00:00:00:00:00",
                    "placeholder": "00:00:00:00:00:00",
                },
                {
                    "key": "psrc",
                    "label": "psrc",
                    "default": "192.168.1.10",
                    "placeholder": "192.168.1.10",
                },
                {
                    "key": "pdst",
                    "label": "pdst",
                    "default": "192.168.1.1",
                    "placeholder": "192.168.1.1",
                },
            ],
        },
        {
            "name": "IP",
            "label": "IPv4",
            "fields": [
                {"key": "src", "label": "src", "placeholder": "192.168.1.10"},
                {"key": "dst", "label": "dst", "placeholder": "192.168.1.20"},
                {
                    "key": "ttl",
                    "label": "ttl",
                    "type": "number",
                    "default": "64",
                    "placeholder": "64",
                },
                {
                    "key": "id",
                    "label": "id",
                    "type": "number",
                    "placeholder": "1",
                    "advanced": True,
                },
                {
                    "key": "flags",
                    "label": "flags",
                    "type": "select",
                    "options": [
                        {"label": "none", "value": ""},
                        {"label": "DF", "value": "DF"},
                        {"label": "MF", "value": "MF"},
                    ],
                    "advanced": True,
                },
                {
                    "key": "proto",
                    "label": "proto",
                    "type": "number",
                    "advanced": True,
                    "auto": True,
                },
            ],
        },
        {
            "name": "IPv6",
            "label": "IPv6",
            "fields": [
                {"key": "src", "label": "src", "placeholder": "2001:db8::10"},
                {"key": "dst", "label": "dst", "placeholder": "2001:db8::20"},
                {
                    "key": "hlim",
                    "label": "hlim",
                    "type": "number",
                    "default": "64",
                    "placeholder": "64",
                },
            ],
        },
        {
            "name": "TCP",
            "label": "TCP",
            "fields": [
                {
                    "key": "sport",
                    "label": "sport",
                    "type": "number",
                    "default": "12345",
                    "placeholder": "12345",
                },
                {
                    "key": "dport",
                    "label": "dport",
                    "type": "number",
                    "default": "80",
                    "placeholder": "80",
                },
                {
                    "key": "flags",
                    "label": "flags",
                    "type": "select",
                    "default": "S",
                    "options": [
                        {"label": "S", "value": "S"},
                        {"label": "SA", "value": "SA"},
                        {"label": "A", "value": "A"},
                        {"label": "PA", "value": "PA"},
                        {"label": "FA", "value": "FA"},
                        {"label": "RA", "value": "RA"},
                    ],
                },
                {"key": "seq", "label": "seq", "type": "number", "placeholder": "1"},
                {"key": "ack", "label": "ack", "type": "number", "placeholder": "1"},
                {
                    "key": "window",
                    "label": "window",
                    "type": "number",
                    "placeholder": "8192",
                    "advanced": True,
                },
            ],
        },
        {
            "name": "UDP",
            "label": "UDP",
            "fields": [
                {
                    "key": "sport",
                    "label": "sport",
                    "type": "number",
                    "default": "12345",
                    "placeholder": "12345",
                },
                {
                    "key": "dport",
                    "label": "dport",
                    "type": "number",
                    "default": "53",
                    "placeholder": "53",
                },
            ],
        },
        {
            "name": "ICMP",
            "label": "ICMP",
            "fields": [
                {
                    "key": "type",
                    "label": "type",
                    "type": "number",
                    "default": "8",
                    "placeholder": "8",
                },
                {
                    "key": "code",
                    "label": "code",
                    "type": "number",
                    "default": "0",
                    "placeholder": "0",
                },
                {
                    "key": "id",
                    "label": "id",
                    "type": "number",
                    "default": "1",
                    "placeholder": "1",
                },
                {
                    "key": "seq",
                    "label": "seq",
                    "type": "number",
                    "default": "1",
                    "placeholder": "1",
                },
            ],
        },
        {
            "name": "DNS",
            "label": "DNS",
            "fields": [
                {
                    "key": "id",
                    "label": "id",
                    "type": "number",
                    "default": "4660",
                    "placeholder": "4660",
                },
                {
                    "key": "qr",
                    "label": "qr",
                    "type": "select",
                    "default": "0",
                    "options": [
                        {"label": "query", "value": "0"},
                        {"label": "response", "value": "1"},
                    ],
                },
                {
                    "key": "rd",
                    "label": "rd",
                    "type": "number",
                    "default": "1",
                    "placeholder": "1",
                },
                {
                    "key": "ra",
                    "label": "ra",
                    "type": "number",
                    "placeholder": "1",
                    "advanced": True,
                },
            ],
        },
        {
            "name": "DNSQR",
            "label": "DNS Question",
            "fields": [
                {
                    "key": "qname",
                    "label": "qname",
                    "placeholder": "example.com",
                    "wide": True,
                },
                {
                    "key": "qtype",
                    "label": "qtype",
                    "type": "select",
                    "default": "A",
                    "options": [
                        {"label": "A", "value": "A"},
                        {"label": "AAAA", "value": "AAAA"},
                        {"label": "CNAME", "value": "CNAME"},
                        {"label": "MX", "value": "MX"},
                        {"label": "TXT", "value": "TXT"},
                    ],
                },
                {
                    "key": "qclass",
                    "label": "qclass",
                    "default": "IN",
                    "placeholder": "IN",
                    "advanced": True,
                },
            ],
        },
        {
            "name": "Raw",
            "label": "Raw Payload",
            "fields": [
                {
                    "key": "load",
                    "label": "load",
                    "placeholder": "Hello Packet!",
                    "wide": True,
                },
            ],
        },
    ]
}


def get_builder_schema() -> Dict[str, Any]:
    return BUILDER_SCHEMA


def normalize_tcp_flags(value: str) -> str:
    try:
        numeric = int(value, 10)
    except ValueError:
        return value
    return "".join(flag for bit, flag in TCP_FLAG_BITS if numeric & bit)


def normalize_enum_field(layer_name: str, field_name: str, value: str) -> str:
    if layer_name == "ARP" and field_name == "op":
        return ARP_OP_ALIASES.get(value, value)
    if layer_name == "DNSQR" and field_name == "qtype":
        return DNS_QTYPE_ALIASES.get(value.upper(), value)
    if layer_name == "TCP" and field_name == "flags":
        return normalize_tcp_flags(value)
    if layer_name == "IP" and field_name == "flags":
        return IP_FLAG_ALIASES.get(value.upper(), value)
    return value


def sanitize_fields(layer_name: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    allowed_types = ALLOWED_FIELDS.get(layer_name)
    if allowed_types is None:
        raise ValueError(f"Unsupported layer: {layer_name}")

    sanitized = {}
    for k, v in fields.items():
        if k not in allowed_types:
            raise ValueError(f"Unsupported field for {layer_name}: {k}")
        if v is None or v == "":
            continue

        # 进行类型转换
        target_type = allowed_types[k]
        try:
            if target_type is int:
                sanitized[k] = int(v)
            elif target_type is str:
                sanitized[k] = normalize_enum_field(layer_name, k, str(v))
            else:
                sanitized[k] = v
        except (ValueError, TypeError):
            raise ValueError(
                f"Invalid value for {layer_name}.{k}: '{v}' cannot be converted to {target_type.__name__}"
            )

    return sanitized


def recalculate_checksums(pkt: Any) -> Any:
    """
    置空长度与校验和字段，然后让 Scapy 重新计算。
    """
    if IP in pkt:
        pkt[IP].len = None
        pkt[IP].chksum = None
    if IPv6 in pkt:
        pkt[IPv6].plen = None
    if TCP in pkt:
        pkt[TCP].chksum = None
    if UDP in pkt:
        pkt[UDP].chksum = None

    # 序列化为字节并重新装载，触发 Scapy 的底层校验和与长度计算
    try:
        return pkt.__class__(bytes(pkt))
    except Exception as e:
        logger.error(f"Error recalculating checksums: {e}")
        return pkt


def normalize_link_layer(pkt: Any) -> Any:
    if Ether not in pkt and ARP in pkt:
        arp_layer = pkt[ARP]
        ether_dst = (
            "ff:ff:ff:ff:ff:ff" if arp_layer.op in (1, "who-has") else arp_layer.hwdst
        )
        return Ether(src=arp_layer.hwsrc, dst=ether_dst) / pkt
    if Ether not in pkt and Dot1Q in pkt:
        return Ether() / pkt
    return pkt


def build_packet_from_spec(spec: Dict[str, Any]) -> Any:
    """
    根据前端发送的 layers 结构构造 Scapy Packet 实例。
    spec 格式: {"layers": [{"name": "Ether", "fields": {...}}, ...]}
    """
    packet = None

    for layer in spec.get("layers", []):
        layer_name = layer["name"]
        if layer_name not in LAYER_MAP:
            raise ValueError(f"Unsupported layer protocol: {layer_name}")

        fields = sanitize_fields(layer_name, layer.get("fields", {}))
        layer_cls = LAYER_MAP[layer_name]

        # 对于 Raw 载荷特别处理，需要将 utf-8 字符串转换为字节
        if layer_name == "Raw" and "load" in fields:
            # 允许使用转义字符如 \x00
            try:
                # 对字面量转义字符进行反序列化
                load_bytes = (
                    bytes(fields["load"], "utf-8")
                    .decode("unicode_escape")
                    .encode("latin1")
                )
            except Exception:
                load_bytes = fields["load"].encode("utf-8")
            fields = {"load": load_bytes}

        # 特别处理 DNSQR，qname 必须为 str
        if layer_name == "DNSQR" and "qname" in fields:
            qname = str(fields["qname"])
            # DNSQR 的域名通常需要以点号结尾
            if not qname.endswith("."):
                qname = f"{qname}."
            fields["qname"] = qname

        try:
            current_layer = layer_cls(**fields)
        except Exception as exc:
            raise ValueError(f"Invalid fields for {layer_name}: {exc}") from exc
        if packet is None:
            packet = current_layer
        elif layer_name == "DNSQR" and DNS in packet:
            packet[DNS].qd = current_layer
            packet[DNS].qdcount = 1
        else:
            packet = packet / current_layer

    if packet is None:
        raise ValueError("Packet layers cannot be empty")

    packet = normalize_link_layer(packet)
    return recalculate_checksums(packet)
