import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from scapy.utils import wrpcap

from app.core.config import settings
from app.db.session import get_db
from app.models.models import PacketSummary, PcapFile
from app.schemas.schemas import (
    BuilderSchemaResponse,
    PacketPreviewRequest,
    PacketPreviewResponse,
    PcapBuildRequest,
    PcapBuildResponse,
)
from app.services.packet_builder import build_packet_from_spec, get_builder_schema
from app.services.packet_detail import packet_to_detail
from app.services.pcap_parser import packet_to_summary_dict
from app.services.operation_audit import emit, pcap_event
from veydeck_suite_runtime import (
    OperationImpact,
    OperationOutcome,
    operation_context_from_headers,
)

router = APIRouter()


def _safe_pcap_filename(filename: str) -> str:
    safe_name = Path(filename or "generated.pcap").name
    return safe_name if safe_name.lower().endswith(".pcap") else f"{safe_name}.pcap"


@router.get("/packets/builder/schema", response_model=BuilderSchemaResponse)
def builder_schema():
    return get_builder_schema()


def _preview_warnings(request: PacketPreviewRequest) -> list[str]:
    warnings = []
    for index, layer in enumerate(request.layers, start=1):
        fields = layer.fields or {}
        for auto_field in ("type", "proto", "len", "chksum"):
            if fields.get(auto_field) not in (None, ""):
                warnings.append(
                    f"Layer #{index} {layer.name}.{auto_field} may be recalculated automatically"
                )
    return warnings


@router.post("/packets/preview", response_model=PacketPreviewResponse)
def preview_packet(request: PacketPreviewRequest):
    try:
        # 构造 Scapy packet 实例
        pkt = build_packet_from_spec(request.model_dump())
        raw_bytes = bytes(pkt)

        # 使用 packet_to_detail 解构并获取结构化显示和 hex
        detail = packet_to_detail(0, raw_bytes)
        return {
            "summary": detail["summary"],
            "layers": detail["layers"],
            "hex": detail["hex"],
            "warnings": _preview_warnings(request),
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to build packet preview: {str(e)}"
        )


@router.post("/pcaps/build", response_model=PcapBuildResponse)
def build_pcap(
    request: PcapBuildRequest, http_request: Request, db: Session = Depends(get_db)
):
    operation_context_id = operation_context_from_headers(http_request.headers)
    if not request.packets:
        raise HTTPException(status_code=400, detail="Packet list cannot be empty")
    if len(request.packets) > settings.MAX_BUILD_PACKET_COUNT:
        raise HTTPException(
            status_code=413,
            detail=f"Packet list exceeds maximum count of {settings.MAX_BUILD_PACKET_COUNT}",
        )

    pcap_id = str(uuid.uuid4())
    filename = _safe_pcap_filename(request.filename)
    safe_filename = f"{pcap_id}.pcap"
    file_path = settings.GENERATED_DIR / safe_filename

    scapy_packets = []
    try:
        # 逐个解析并构建包
        for spec in request.packets:
            pkt = build_packet_from_spec(spec.model_dump())
            scapy_packets.append(pkt)
    except ValueError as ve:
        emit_build_failure(pcap_id, "PCAP_BUILD_INVALID", operation_context_id)
        raise HTTPException(
            status_code=400, detail=f"Validation error in packet definition: {str(ve)}"
        )
    except Exception as e:
        emit_build_failure(pcap_id, "PCAP_BUILD_FAILED", operation_context_id)
        raise HTTPException(
            status_code=500, detail=f"Failed to compile packets: {str(e)}"
        )

    # 使用 Scapy 的 wrpcap 保存为 pcap 文件
    try:
        wrpcap(str(file_path), scapy_packets)
    except Exception as e:
        emit_build_failure(pcap_id, "PCAP_WRITE_FAILED", operation_context_id)
        raise HTTPException(
            status_code=500, detail=f"Failed to write PCAP file to disk: {str(e)}"
        )

    # 获取文件大小
    file_size = file_path.stat().st_size

    # 在同一个事务中，将此构建的 pcap 注册进系统，方便直接在页面上查看
    try:
        pcap_record = PcapFile(
            id=pcap_id,
            filename=safe_filename,
            original_filename=filename,
            file_path=str(file_path),
            file_size=file_size,
            status="parsed",  # 已经是解析过的了
            packet_count=len(scapy_packets),
        )
        db.add(pcap_record)
        # bulk_insert_mappings 不会自动 flush pending ORM 对象，先写入父记录以满足外键约束。
        db.flush()

        # 批量入库包摘要，这样生成的文件可以直接在列表和详情里看！
        summaries = []
        for index, pkt in enumerate(scapy_packets):
            summary_data = packet_to_summary_dict(index + 1, pkt)
            summary_data["pcap_id"] = pcap_id
            summaries.append(summary_data)

        db.bulk_insert_mappings(PacketSummary, summaries)
        db.commit()
    except Exception as e:
        db.rollback()
        # 如果数据库出错，清理掉磁盘上的临时文件
        file_path.unlink(missing_ok=True)
        emit_build_failure(pcap_id, "PCAP_RECORD_FAILED", operation_context_id)
        raise HTTPException(
            status_code=500, detail=f"Failed to record built PCAP in database: {str(e)}"
        )

    emit(
        pcap_event(
            "pcap_built",
            "构建流量文件",
            "Build traffic file",
            pcap_id,
            OperationOutcome.SUCCESS,
            OperationImpact.INFO,
            operation_context_id=operation_context_id,
            packet_count=len(scapy_packets),
        )
    )

    return {"pcap_id": pcap_id, "download_url": f"/api/pcaps/{pcap_id}/download"}


def emit_build_failure(
    pcap_id: str, error_code: str, operation_context_id: str | None
) -> None:
    emit(
        pcap_event(
            "pcap_built",
            "构建流量文件",
            "Build traffic file",
            pcap_id,
            OperationOutcome.FAILURE,
            OperationImpact.ERROR,
            operation_context_id=operation_context_id,
            error_code=error_code,
            error_summary="PCAP build failed",
        )
    )
