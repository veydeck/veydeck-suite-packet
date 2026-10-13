from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.models.models import PcapFile, PacketSummary
from app.schemas.schemas import PcapStatsResponse

router = APIRouter()


@router.get("", response_model=PcapStatsResponse)
def get_pcap_stats(pcap_id: str, db: Session = Depends(get_db)):
    # 校验 PCAP 记录是否存在
    pcap_record = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    if not pcap_record:
        raise HTTPException(status_code=404, detail="PCAP file not found")

    if pcap_record.status != "parsed":
        raise HTTPException(
            status_code=400, detail="PCAP analysis is not completed yet"
        )

    # 1. 协议分布
    proto_query = (
        db.query(PacketSummary.protocol, func.count(PacketSummary.id))
        .filter(PacketSummary.pcap_id == pcap_id)
        .group_by(PacketSummary.protocol)
        .all()
    )
    protocol_distribution = {proto or "UNKNOWN": count for proto, count in proto_query}

    # 2. Top Source IPs
    src_ip_query = (
        db.query(PacketSummary.src_ip, func.count(PacketSummary.id).label("count"))
        .filter(PacketSummary.pcap_id == pcap_id, PacketSummary.src_ip.isnot(None))
        .group_by(PacketSummary.src_ip)
        .order_by(func.count(PacketSummary.id).desc())
        .limit(10)
        .all()
    )
    top_src_ips = [{"ip": ip, "count": count} for ip, count in src_ip_query]

    # 3. Top Destination IPs
    dst_ip_query = (
        db.query(PacketSummary.dst_ip, func.count(PacketSummary.id).label("count"))
        .filter(PacketSummary.pcap_id == pcap_id, PacketSummary.dst_ip.isnot(None))
        .group_by(PacketSummary.dst_ip)
        .order_by(func.count(PacketSummary.id).desc())
        .limit(10)
        .all()
    )
    top_dst_ips = [{"ip": ip, "count": count} for ip, count in dst_ip_query]

    # 4. Top Destination Ports
    dst_port_query = (
        db.query(PacketSummary.dst_port, func.count(PacketSummary.id).label("count"))
        .filter(PacketSummary.pcap_id == pcap_id, PacketSummary.dst_port.isnot(None))
        .group_by(PacketSummary.dst_port)
        .order_by(func.count(PacketSummary.id).desc())
        .limit(10)
        .all()
    )
    top_dst_ports = [{"port": port, "count": count} for port, count in dst_port_query]

    return {
        "total_packets": pcap_record.packet_count,
        "protocol_distribution": protocol_distribution,
        "top_src_ips": top_src_ips,
        "top_dst_ips": top_dst_ips,
        "top_dst_ports": top_dst_ports,
    }
