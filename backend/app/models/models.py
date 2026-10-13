from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class PcapFile(Base):
    """PCAP 文件记录。"""

    __tablename__ = "pcap_files"

    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    """PCAP 唯一标识。"""
    filename: Mapped[str] = mapped_column(String, nullable=False)
    """存储文件名。"""
    original_filename: Mapped[str] = mapped_column(String, nullable=False)
    """原始上传文件名。"""
    file_path: Mapped[str] = mapped_column(String, nullable=False)
    """本地存储路径。"""
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    """文件大小，单位字节。"""
    status: Mapped[str] = mapped_column(String, default="uploaded", nullable=False)
    """解析状态。"""
    packet_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    """已解析包数量。"""
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)
    """解析失败原因。"""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    """创建时间。"""
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
    """更新时间。"""

    packets: Mapped[list["PacketSummary"]] = relationship(
        "PacketSummary",
        back_populates="pcap",
        cascade="all, delete-orphan",
    )
    """关联的数据包摘要列表。"""


class PacketSummary(Base):
    """数据包摘要记录。"""

    __tablename__ = "packet_summaries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    """摘要唯一标识。"""
    pcap_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    """所属 PCAP 标识。"""
    packet_index: Mapped[int] = mapped_column(Integer, nullable=False)
    """包序号，从 1 开始。"""
    timestamp: Mapped[float | None] = mapped_column(Float, nullable=True)
    """抓包时间戳。"""
    length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    """包长度，单位字节。"""
    protocol: Mapped[str | None] = mapped_column(String, nullable=True)
    """识别出的协议名称。"""
    src_mac: Mapped[str | None] = mapped_column(String, nullable=True)
    """源 MAC 地址。"""
    dst_mac: Mapped[str | None] = mapped_column(String, nullable=True)
    """目的 MAC 地址。"""
    src_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    """源 IP 地址。"""
    dst_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    """目的 IP 地址。"""
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    """源端口。"""
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    """目的端口。"""
    summary: Mapped[str | None] = mapped_column(String, nullable=True)
    """数据包摘要文本。"""
    raw_layers: Mapped[str | None] = mapped_column(String, nullable=True)
    """JSON 序列化的协议层列表。"""
    raw_packet: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    """原始数据包二进制。"""
    anomalies: Mapped[str | None] = mapped_column(String, nullable=True)
    """异常类型标识列表，以逗号分隔。"""

    pcap: Mapped[PcapFile] = relationship("PcapFile", back_populates="packets")
    """所属 PCAP 记录。"""


# 建立索引优化查询性能
Index("idx_packet_pcap_id", PacketSummary.pcap_id)
Index("idx_packet_protocol", PacketSummary.protocol)
Index("idx_packet_src_ip", PacketSummary.src_ip)
Index("idx_packet_dst_ip", PacketSummary.dst_ip)
Index("idx_packet_ports", PacketSummary.src_port, PacketSummary.dst_port)
