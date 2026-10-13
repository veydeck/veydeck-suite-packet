from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.db.session import get_db
from app.models.models import PacketSummary
from app.schemas.schemas import (
    FollowStreamResponse,
    PacketDetailResponse,
    PacketListResponse,
)
from app.services.packet_detail import bytes_to_escaped_string, packet_to_detail
from app.services.packet_utils import (
    get_transport_payload_bytes,
    get_transport_protocol,
    parse_raw_packet,
)

router = APIRouter()


@router.get("", response_model=PacketListResponse)
def get_packet_list(
    pcap_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    protocol: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    port: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(PacketSummary).filter(PacketSummary.pcap_id == pcap_id)

    # 过滤器过滤
    if protocol:
        query = query.filter(PacketSummary.protocol == protocol.upper())
    if src_ip:
        query = query.filter(PacketSummary.src_ip == src_ip)
    if dst_ip:
        query = query.filter(PacketSummary.dst_ip == dst_ip)
    if port:
        query = query.filter(
            or_(PacketSummary.src_port == port, PacketSummary.dst_port == port)
        )

    # 统计总数并进行分页
    total = query.count()
    items = (
        query.order_by(PacketSummary.packet_index.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{packet_index}", response_model=PacketDetailResponse)
def get_packet_details(pcap_id: str, packet_index: int, db: Session = Depends(get_db)):
    summary_record = (
        db.query(PacketSummary)
        .filter(
            PacketSummary.pcap_id == pcap_id, PacketSummary.packet_index == packet_index
        )
        .first()
    )

    if not summary_record:
        raise HTTPException(status_code=404, detail="Packet not found in this PCAP")

    try:
        # 使用数据库缓存的原始字节，免去从磁盘流式读取的开销
        detail_data = packet_to_detail(packet_index, summary_record.raw_packet)
        return detail_data
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to parse packet details: {str(e)}"
        )


@router.get("/{packet_index}/follow-stream", response_model=FollowStreamResponse)
def follow_stream(pcap_id: str, packet_index: int, db: Session = Depends(get_db)):
    from scapy.layers.inet import TCP

    # 1. 找到对应的包摘要，用于提取它的双向会话端点
    summary_record = (
        db.query(PacketSummary)
        .filter(
            PacketSummary.pcap_id == pcap_id,
            PacketSummary.packet_index == packet_index,
        )
        .first()
    )

    if not summary_record:
        raise HTTPException(status_code=404, detail="Packet not found in this PCAP")

    pkt_instance = parse_raw_packet(summary_record.raw_packet)
    proto = get_transport_protocol(pkt_instance)
    if proto is None:
        raise HTTPException(
            status_code=400,
            detail=f"Follow stream is only supported for TCP or UDP transport protocols, but got high-level protocol {summary_record.protocol or 'unknown'}",
        )

    # 提取两端的 IP 和 Port
    src_ip = summary_record.src_ip
    dst_ip = summary_record.dst_ip
    src_port = summary_record.src_port
    dst_port = summary_record.dst_port

    if not src_ip or not dst_ip or src_port is None or dst_port is None:
        raise HTTPException(
            status_code=400,
            detail="Incomplete IP or Port information for this packet",
        )

    # 2. 查询该会话的所有数据包（双向）
    query = db.query(PacketSummary).filter(
        PacketSummary.pcap_id == pcap_id,
    )

    # TCP / UDP 双向过滤条件
    query = query.filter(
        or_(
            and_(
                PacketSummary.src_ip == src_ip,
                PacketSummary.dst_ip == dst_ip,
                PacketSummary.src_port == src_port,
                PacketSummary.dst_port == dst_port,
            ),
            and_(
                PacketSummary.src_ip == dst_ip,
                PacketSummary.dst_ip == src_ip,
                PacketSummary.src_port == dst_port,
                PacketSummary.dst_port == src_port,
            ),
        )
    )

    # 按 packet_index 升序排列（时序），再按实际传输层协议过滤。
    # protocol 字段可能是 HTTP/DNS 等高层协议，不能直接用它判断 TCP/UDP。
    stream_candidates = query.order_by(PacketSummary.packet_index.asc()).all()
    stream_packets = []
    for candidate in stream_candidates:
        candidate_pkt = parse_raw_packet(candidate.raw_packet)
        if get_transport_protocol(candidate_pkt) == proto:
            stream_packets.append((candidate, candidate_pkt))

    if not stream_packets:
        raise HTTPException(status_code=404, detail="No flow packets found")

    # 3. 确定 Client。TCP 优先使用 SYN 且非 ACK 的发起方；否则使用时序首包。
    first_stream_packet = stream_packets[0][0]
    client_ip = first_stream_packet.src_ip
    server_ip = first_stream_packet.dst_ip
    client_port = first_stream_packet.src_port
    server_port = first_stream_packet.dst_port
    if proto == "TCP":
        for s_pkt, parsed_pkt in stream_packets:
            flags = str(parsed_pkt[TCP].flags) if TCP in parsed_pkt else ""
            if "S" in flags and "A" not in flags:
                client_ip = s_pkt.src_ip
                server_ip = s_pkt.dst_ip
                client_port = s_pkt.src_port
                server_port = s_pkt.dst_port
                break

    chunks = []
    byte_count = 0

    # 遍历时合并连续的同一方向载荷，以减少传输块数并方便前端渲染
    current_direction = None
    current_chunk_data = []
    current_chunk_start_idx = None
    current_chunk_end_idx = None

    for s_pkt, parsed_pkt in stream_packets:
        payload_bytes = get_transport_payload_bytes(parsed_pkt, proto)
        if not payload_bytes:
            continue

        byte_count += len(payload_bytes)

        # 确定方向
        direction = "client" if s_pkt.src_ip == client_ip else "server"

        if current_direction is None:
            current_direction = direction
            current_chunk_data.append(payload_bytes)
            current_chunk_start_idx = s_pkt.packet_index
            current_chunk_end_idx = s_pkt.packet_index
        elif current_direction == direction:
            current_chunk_data.append(payload_bytes)
            current_chunk_end_idx = s_pkt.packet_index
        else:
            # 方向改变，打包之前的块
            merged_bytes = b"".join(current_chunk_data)
            chunks.append(
                {
                    "direction": current_direction,
                    "packet_index": current_chunk_start_idx,
                    "start_packet_index": current_chunk_start_idx,
                    "end_packet_index": current_chunk_end_idx,
                    "byte_count": len(merged_bytes),
                    "data": bytes_to_escaped_string(merged_bytes),
                }
            )
            # 开启新块
            current_direction = direction
            current_chunk_data = [payload_bytes]
            current_chunk_start_idx = s_pkt.packet_index
            current_chunk_end_idx = s_pkt.packet_index

    # 合并收尾最后一个块
    if current_direction is not None and current_chunk_data:
        merged_bytes = b"".join(current_chunk_data)
        chunks.append(
            {
                "direction": current_direction,
                "packet_index": current_chunk_start_idx,
                "start_packet_index": current_chunk_start_idx,
                "end_packet_index": current_chunk_end_idx,
                "byte_count": len(merged_bytes),
                "data": bytes_to_escaped_string(merged_bytes),
            }
        )

    return {
        "protocol": proto,
        "client_ip": client_ip,
        "server_ip": server_ip,
        "client_port": client_port,
        "server_port": server_port,
        "packet_count": len(stream_packets),
        "byte_count": byte_count,
        "chunks": chunks,
    }
