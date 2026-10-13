import hashlib
import struct
from typing import Any

from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet

from app.services.packet_utils import get_transport_payload_bytes


TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData",
}

TLS_HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
    12: "ServerKeyExchange",
    14: "ServerHelloDone",
    16: "ClientKeyExchange",
    20: "Finished",
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

MQTT_PACKET_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    8: "SUBSCRIBE",
    9: "SUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
}

HTTP2_FRAME_TYPES = {
    0: "DATA",
    1: "HEADERS",
    2: "PRIORITY",
    3: "RST_STREAM",
    4: "SETTINGS",
    5: "PUSH_PROMISE",
    6: "PING",
    7: "GOAWAY",
    8: "WINDOW_UPDATE",
    9: "CONTINUATION",
}


def _version_name(raw: int) -> str:
    return TLS_VERSIONS.get(raw, f"0x{raw:04x}")


def _read_uint24(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 3], "big")


def _safe_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip("\x00\r\n ")


def _parse_tls_client_hello(body: bytes) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if len(body) < 38:
        return fields

    fields["legacy_version"] = _version_name(struct.unpack("!H", body[:2])[0])
    offset = 34
    session_len = body[offset]
    offset += 1 + session_len
    if offset + 2 > len(body):
        return fields

    cipher_len = struct.unpack("!H", body[offset : offset + 2])[0]
    fields["cipher_suite_count"] = cipher_len // 2
    offset += 2 + cipher_len
    if offset >= len(body):
        return fields

    compression_len = body[offset]
    offset += 1 + compression_len
    if offset + 2 > len(body):
        return fields

    ext_total = struct.unpack("!H", body[offset : offset + 2])[0]
    offset += 2
    ext_end = min(len(body), offset + ext_total)
    alpn: list[str] = []
    supported_versions: list[str] = []

    while offset + 4 <= ext_end:
        ext_type = struct.unpack("!H", body[offset : offset + 2])[0]
        ext_len = struct.unpack("!H", body[offset + 2 : offset + 4])[0]
        ext_data = body[offset + 4 : offset + 4 + ext_len]
        offset += 4 + ext_len

        if ext_type == 0 and len(ext_data) >= 5:
            names_len = struct.unpack("!H", ext_data[:2])[0]
            name_offset = 2
            if name_offset + 3 <= len(ext_data) and names_len > 0:
                name_type = ext_data[name_offset]
                name_len = struct.unpack(
                    "!H", ext_data[name_offset + 1 : name_offset + 3]
                )[0]
                name_offset += 3
                if name_type == 0 and name_offset + name_len <= len(ext_data):
                    server_name = ext_data[name_offset : name_offset + name_len]
                    fields["sni"] = _safe_text(server_name)
        elif ext_type == 16 and len(ext_data) >= 2:
            list_len = struct.unpack("!H", ext_data[:2])[0]
            pos = 2
            while pos < min(len(ext_data), 2 + list_len):
                name_len = ext_data[pos]
                pos += 1
                alpn.append(_safe_text(ext_data[pos : pos + name_len]))
                pos += name_len
        elif ext_type == 43 and ext_data:
            version_len = ext_data[0]
            pos = 1
            while pos + 1 < min(len(ext_data), 1 + version_len):
                supported_versions.append(
                    _version_name(struct.unpack("!H", ext_data[pos : pos + 2])[0])
                )
                pos += 2

    if alpn:
        fields["alpn"] = ", ".join(alpn)
    if supported_versions:
        fields["supported_versions"] = ", ".join(supported_versions)
    return fields


def _parse_tls_server_hello(body: bytes) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if len(body) < 38:
        return fields

    fields["legacy_version"] = _version_name(struct.unpack("!H", body[:2])[0])
    offset = 34
    session_len = body[offset]
    offset += 1 + session_len
    if offset + 2 <= len(body):
        fields["selected_cipher_suite"] = f"0x{body[offset : offset + 2].hex()}"
    return fields


def _parse_tls_certificate(body: bytes) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if len(body) < 3:
        return fields

    certs_len = _read_uint24(body, 0)
    offset = 3
    count = 0
    first_cert = None
    while offset + 3 <= min(len(body), 3 + certs_len):
        cert_len = _read_uint24(body, offset)
        offset += 3
        cert = body[offset : offset + cert_len]
        offset += cert_len
        if first_cert is None:
            first_cert = cert
        count += 1

    fields["certificate_count"] = count
    if first_cert:
        fields["first_certificate_sha256"] = hashlib.sha256(first_cert).hexdigest()
        fields["first_certificate_bytes"] = len(first_cert)
    return fields


def decode_tls(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 5 or payload[0] not in TLS_CONTENT_TYPES:
        return None

    version = struct.unpack("!H", payload[1:3])[0]
    record_len = struct.unpack("!H", payload[3:5])[0]
    record_body = payload[5 : 5 + record_len]
    fields: dict[str, Any] = {
        "record_type": TLS_CONTENT_TYPES[payload[0]],
        "record_version": _version_name(version),
        "record_length": record_len,
    }

    if payload[0] == 22 and len(record_body) >= 4:
        handshake_type = record_body[0]
        handshake_len = _read_uint24(record_body, 1)
        handshake_body = record_body[4 : 4 + handshake_len]
        fields["handshake_type"] = TLS_HANDSHAKE_TYPES.get(
            handshake_type, f"Unknown({handshake_type})"
        )
        fields["handshake_length"] = handshake_len
        if handshake_type == 1:
            fields.update(_parse_tls_client_hello(handshake_body))
        elif handshake_type == 2:
            fields.update(_parse_tls_server_hello(handshake_body))
        elif handshake_type == 11:
            fields.update(_parse_tls_certificate(handshake_body))

    return {"protocol": "TLS", "title": "TLS/SSL Handshake", "fields": fields}


def decode_ssh(payload: bytes) -> dict[str, Any] | None:
    if not payload.startswith(b"SSH-"):
        return None

    banner = _safe_text(payload.splitlines()[0])
    parts = banner.split("-", 2)
    fields = {"banner": banner}
    if len(parts) >= 3:
        fields["protocol_version"] = parts[1]
        fields["software"] = parts[2]
    return {"protocol": "SSH", "title": "SSH Banner", "fields": fields}


def decode_ftp(payload: bytes) -> dict[str, Any] | None:
    if not payload:
        return None

    line = _safe_text(payload.splitlines()[0])
    if not line:
        return None

    fields: dict[str, Any] = {"line": line}
    if len(line) >= 3 and line[:3].isdigit():
        fields["response_code"] = line[:3]
        fields["message"] = line[4:] if len(line) > 4 else ""
        return {"protocol": "FTP", "title": "FTP Response", "fields": fields}

    command = line.split(" ", 1)[0].upper()
    if command in {
        "USER",
        "PASS",
        "RETR",
        "STOR",
        "LIST",
        "PASV",
        "PORT",
        "CWD",
        "PWD",
        "TYPE",
        "SYST",
        "FEAT",
        "QUIT",
    }:
        fields["command"] = command
        argument = line[len(command) :].strip()
        fields["argument"] = "***" if command == "PASS" and argument else argument
        return {"protocol": "FTP", "title": "FTP Command", "fields": fields}

    return None


def _mqtt_remaining_length(payload: bytes) -> tuple[int, int] | None:
    multiplier = 1
    value = 0
    offset = 1
    while offset < len(payload) and offset <= 4:
        byte = payload[offset]
        value += (byte & 127) * multiplier
        offset += 1
        if byte & 128 == 0:
            return value, offset
        multiplier *= 128
    return None


def _mqtt_utf8(data: bytes, offset: int) -> tuple[str, int] | None:
    if offset + 2 > len(data):
        return None
    length = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    if offset + length > len(data):
        return None
    return _safe_text(data[offset : offset + length]), offset + length


def decode_mqtt(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 2:
        return None

    packet_type = payload[0] >> 4
    if packet_type not in MQTT_PACKET_TYPES:
        return None

    remaining = _mqtt_remaining_length(payload)
    if remaining is None:
        return None
    remaining_len, offset = remaining
    fields: dict[str, Any] = {
        "packet_type": MQTT_PACKET_TYPES[packet_type],
        "remaining_length": remaining_len,
    }

    if packet_type == 1:
        proto = _mqtt_utf8(payload, offset)
        if proto:
            fields["protocol_name"] = proto[0]
            offset = proto[1]
        if offset + 4 <= len(payload):
            fields["protocol_level"] = payload[offset]
            fields["connect_flags"] = f"0x{payload[offset + 1]:02x}"
            fields["keep_alive"] = struct.unpack(
                "!H", payload[offset + 2 : offset + 4]
            )[0]
            offset += 4
        client_id = _mqtt_utf8(payload, offset)
        if client_id:
            fields["client_id"] = client_id[0]
    elif packet_type == 3:
        topic = _mqtt_utf8(payload, offset)
        if topic:
            fields["topic"] = topic[0]
            fields["payload_bytes"] = max(0, remaining_len - (topic[1] - offset))

    return {"protocol": "MQTT", "title": "MQTT Packet", "fields": fields}


def decode_http2(payload: bytes) -> dict[str, Any] | None:
    if payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        return {
            "protocol": "HTTP/2",
            "title": "HTTP/2 Connection Preface",
            "fields": {"preface": "PRI * HTTP/2.0"},
        }

    if len(payload) < 9:
        return None
    length = _read_uint24(payload, 0)
    frame_type = payload[3]
    if frame_type not in HTTP2_FRAME_TYPES:
        return None
    stream_id = struct.unpack("!I", payload[5:9])[0] & 0x7FFFFFFF
    return {
        "protocol": "HTTP/2",
        "title": "HTTP/2 Frame",
        "fields": {
            "frame_type": HTTP2_FRAME_TYPES[frame_type],
            "length": length,
            "flags": f"0x{payload[4]:02x}",
            "stream_id": stream_id,
        },
    }


def decode_application_protocols(pkt: Packet) -> list[dict[str, Any]]:
    payload = None
    ports: set[int] = set()

    if TCP in pkt:
        payload = get_transport_payload_bytes(pkt, "TCP")
        ports.update({int(pkt[TCP].sport), int(pkt[TCP].dport)})
    elif UDP in pkt:
        payload = get_transport_payload_bytes(pkt, "UDP")
        ports.update({int(pkt[UDP].sport), int(pkt[UDP].dport)})

    if not payload:
        return []

    decoders = []
    if ports & {443, 465, 993, 995, 8443, 8883} or payload[:1] in {
        b"\x14",
        b"\x15",
        b"\x16",
        b"\x17",
    }:
        decoders.append(decode_tls)
    if 22 in ports or payload.startswith(b"SSH-"):
        decoders.append(decode_ssh)
    if 21 in ports:
        decoders.append(decode_ftp)
    if 1883 in ports or 8883 in ports:
        decoders.append(decode_mqtt)
    if 80 in ports or 8080 in ports or payload.startswith(b"PRI * HTTP/2.0"):
        decoders.append(decode_http2)

    insights = []
    seen = set()
    for decoder in decoders:
        decoded = decoder(payload)
        if decoded and decoded["protocol"] not in seen:
            insights.append(decoded)
            seen.add(decoded["protocol"])
    return insights


def detect_application_protocol(pkt: Packet) -> str | None:
    insights = decode_application_protocols(pkt)
    return insights[0]["protocol"] if insights else None
