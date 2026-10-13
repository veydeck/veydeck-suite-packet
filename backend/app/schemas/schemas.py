from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# Pcap File schemas
class PcapFileBase(BaseModel):
    filename: str
    original_filename: str
    file_size: int


class PcapFileResponse(PcapFileBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    packet_count: int
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# Packet Summary schemas
class PacketSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    index: int = Field(
        ..., validation_alias="packet_index", serialization_alias="index"
    )
    timestamp: Optional[float] = None
    length: int
    protocol: str
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    summary: str
    anomalies: Optional[str] = None


class PacketListResponse(BaseModel):
    items: List[PacketSummaryResponse]
    total: int
    page: int
    page_size: int


# Packet Detail schemas
class PacketLayer(BaseModel):
    name: str
    fields: Dict[str, Any]


class ProtocolInsight(BaseModel):
    protocol: str
    title: str
    fields: Dict[str, Any]


class PacketDetailResponse(BaseModel):
    index: int
    summary: str
    length: int
    layers: List[PacketLayer]
    hex: str
    protocol_insights: List[ProtocolInsight] = []


# Stats schemas
class TopIpStat(BaseModel):
    ip: str
    count: int


class TopPortStat(BaseModel):
    port: int
    count: int


class PcapStatsResponse(BaseModel):
    total_packets: int
    protocol_distribution: Dict[str, int]
    top_src_ips: List[TopIpStat]
    top_dst_ips: List[TopIpStat]
    top_dst_ports: List[TopPortStat]


# Packet Builder schemas
class BuilderFieldOption(BaseModel):
    label: str
    value: str


class BuilderFieldSpec(BaseModel):
    key: str
    label: str
    type: str = "text"
    default: Optional[str] = None
    placeholder: Optional[str] = None
    options: Optional[List[BuilderFieldOption]] = None
    wide: bool = False
    advanced: bool = False
    auto: bool = False


class BuilderLayerSpec(BaseModel):
    name: str
    label: str
    fields: List[BuilderFieldSpec]


class BuilderSchemaResponse(BaseModel):
    layers: List[BuilderLayerSpec]


class LayerSpec(BaseModel):
    name: str
    fields: Optional[Dict[str, Any]] = None


class PacketPreviewRequest(BaseModel):
    layers: List[LayerSpec]


class PacketPreviewResponse(BaseModel):
    summary: str
    layers: List[PacketLayer]
    hex: str
    warnings: List[str] = []


class PcapBuildRequest(BaseModel):
    filename: str = "generated.pcap"
    packets: List[PacketPreviewRequest]


class PcapBuildResponse(BaseModel):
    pcap_id: str
    download_url: str


# Follow Stream schemas
class StreamChunk(BaseModel):
    direction: str
    packet_index: int
    start_packet_index: int
    end_packet_index: int
    byte_count: int
    data: str


class FollowStreamResponse(BaseModel):
    protocol: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    packet_count: int
    byte_count: int
    chunks: List[StreamChunk]
