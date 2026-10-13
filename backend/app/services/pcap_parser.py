import json
import logging
from typing import Any
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.models import PcapFile, PacketSummary
from app.services.packet_utils import get_tcp_application_payload_len
from app.services.protocol_decode import detect_application_protocol
from app.services.operation_audit import emit, pcap_event
from veydeck_suite_runtime import OperationImpact, OperationOutcome

logger = logging.getLogger(__name__)


def detect_protocol(pkt: Any) -> str:
    app_protocol = detect_application_protocol(pkt)
    if app_protocol:
        return app_protocol
    if HTTPRequest in pkt or HTTPResponse in pkt:
        return "HTTP"
    if DNS in pkt:
        return "DNS"
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    if ARP in pkt:
        return "ARP"
    if IPv6 in pkt:
        return "IPv6"
    if IP in pkt:
        return "IP"
    if Ether in pkt:
        return "Ether"
    return "UNKNOWN"


def packet_to_summary_dict(index: int, pkt: Any) -> dict:
    layers = []
    # 逐层提取协议名
    temp = pkt
    while temp:
        layers.append(temp.name if hasattr(temp, "name") else temp.__class__.__name__)
        temp = temp.payload
        if not temp or temp.name == "NoPayload":
            break

    item = {
        "packet_index": index,
        "timestamp": float(pkt.time)
        if hasattr(pkt, "time") and pkt.time is not None
        else None,
        "length": len(pkt),
        "protocol": detect_protocol(pkt),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "summary": pkt.summary() if hasattr(pkt, "summary") else "",
        "raw_layers": json.dumps(layers),
        "raw_packet": bytes(pkt),  # 保存原始数据包的字节流
        "anomalies": None,
    }

    if Ether in pkt:
        item["src_mac"] = pkt[Ether].src
        item["dst_mac"] = pkt[Ether].dst

    if IP in pkt:
        item["src_ip"] = pkt[IP].src
        item["dst_ip"] = pkt[IP].dst
    elif IPv6 in pkt:
        item["src_ip"] = pkt[IPv6].src
        item["dst_ip"] = pkt[IPv6].dst

    if TCP in pkt:
        item["src_port"] = pkt[TCP].sport
        item["dst_port"] = pkt[TCP].dport
    elif UDP in pkt:
        item["src_port"] = pkt[UDP].sport
        item["dst_port"] = pkt[UDP].dport

    return item


def parse_pcap_task(
    pcap_id: str, file_path: str, operation_context_id: str | None = None
):
    """
    后台执行的 PCAP 解析任务。
    自己开启独立的数据库 Session 避免多线程并发冲突。
    """
    db = SessionLocal()
    try:
        # 更新状态为 parsing
        pcap_file = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
        if not pcap_file:
            logger.error(f"Pcap file record not found: {pcap_id}")
            return
        pcap_file.status = "parsing"
        db.commit()

        logger.info(f"Start parsing PCAP: {file_path}")

        batch = []
        count = 0

        tcp_states = {}  # key: (src_ip, sport, dst_ip, dport)

        with PcapReader(file_path) as reader:
            for index, pkt in enumerate(reader):
                # 包的索引从 1 开始
                pkt_index = index + 1

                # 安全限制检测
                if index >= settings.MAX_PACKET_COUNT:
                    logger.warning(
                        f"PCAP packet count exceeded maximum limit {settings.MAX_PACKET_COUNT}. Stopping parse."
                    )
                    break

                summary_data = packet_to_summary_dict(pkt_index, pkt)
                summary_data["pcap_id"] = pcap_id

                # Detect TCP anomalies
                has_ip = IP in pkt or IPv6 in pkt
                if has_ip and TCP in pkt:
                    ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    seq = pkt[TCP].seq
                    flags = str(pkt[TCP].flags)
                    payload_len = get_tcp_application_payload_len(pkt[TCP])

                    conn_key = (src_ip, sport, dst_ip, dport)
                    anomalies = []

                    if conn_key not in tcp_states:
                        tcp_states[conn_key] = {
                            "seen_seqs": {seq} if payload_len > 0 else set(),
                            "max_seq": seq,
                            "next_seq": seq + payload_len,
                            "seen_syn": "S" in flags,
                        }
                    else:
                        state = tcp_states[conn_key]

                        # 1. TCP Dup SYN
                        if "S" in flags and state["seen_syn"]:
                            anomalies.append("TCP Dup SYN")

                        # 2. TCP Retransmission
                        if payload_len > 0 and seq in state["seen_seqs"]:
                            anomalies.append("TCP Retransmission")
                        # 3. TCP Out-of-Order
                        elif seq < state["max_seq"] and payload_len > 0:
                            # Verify if it's not a Keep-Alive
                            is_keepalive = (payload_len <= 1) and (
                                seq == state["next_seq"] - 1
                                or seq == state["max_seq"] - 1
                            )
                            if not is_keepalive:
                                anomalies.append("TCP Out-of-Order")

                        # Update state
                        if payload_len > 0:
                            state["seen_seqs"].add(seq)
                        if "S" in flags:
                            state["seen_syn"] = True
                        if seq > state["max_seq"]:
                            state["max_seq"] = seq
                        if seq + payload_len > state["next_seq"]:
                            state["next_seq"] = seq + payload_len

                    if anomalies:
                        summary_data["anomalies"] = ",".join(anomalies)

                batch.append(summary_data)
                count += 1

                # 达到 BATCH_SIZE 批量写入
                if len(batch) >= settings.BATCH_SIZE:
                    db.bulk_insert_mappings(PacketSummary, batch)
                    db.commit()
                    batch.clear()

        # 写入剩余包
        if batch:
            db.bulk_insert_mappings(PacketSummary, batch)
            db.commit()

        # 更新解析完毕状态
        pcap_file = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
        if pcap_file is None:
            logger.error(f"Pcap file record not found after parsing: {pcap_id}")
            return
        pcap_file.status = "parsed"
        pcap_file.packet_count = count
        db.commit()
        logger.info(f"Finished parsing PCAP: {pcap_id}. Total packets parsed: {count}")
        emit(
            pcap_event(
                "pcap_parse_succeeded",
                "流量解析完成",
                "Traffic parsing completed",
                pcap_id,
                OperationOutcome.SUCCESS,
                OperationImpact.INFO,
                operation_context_id=operation_context_id,
                packet_count=count,
            )
        )

    except Exception as e:
        logger.exception(f"Error parsing PCAP: {e}")
        db.rollback()
        pcap_file = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
        if pcap_file:
            pcap_file.status = "failed"
            pcap_file.error_message = str(e)
            db.commit()
        emit(
            pcap_event(
                "pcap_parse_failed",
                "流量解析失败",
                "Traffic parsing failed",
                pcap_id,
                OperationOutcome.FAILURE,
                OperationImpact.ERROR,
                operation_context_id=operation_context_id,
                error_code="PCAP_PARSE_FAILED",
                error_summary="PCAP parsing failed",
            )
        )
    finally:
        db.close()
