"""向 Veydeck Agent 提交套件语义操作事件，失败时不改变业务结果。"""

import asyncio
import logging

from veydeck_suite_runtime import (
    OperationEvent,
    OperationImpact,
    OperationOutcome,
    OperationTarget,
    RuntimeClient,
)

logger = logging.getLogger(__name__)


def emit(event: OperationEvent) -> None:
    """供 FastAPI 同步处理器和后台线程调用的非传播上报入口。"""
    try:
        asyncio.run(_emit(event))
    except Exception as error:
        logger.error(
            "Operation audit event %s was not accepted: %s",
            event.event_id,
            error,
        )


async def _emit(event: OperationEvent) -> None:
    client = await RuntimeClient.from_environment("operation-logs.write")
    try:
        await client.submit_operation_event(event)
    finally:
        await client.aclose()


def pcap_event(
    code: str,
    zh_cn: str,
    en_us: str,
    pcap_id: str,
    outcome: OperationOutcome,
    impact: OperationImpact,
    *,
    operation_context_id: str | None = None,
    task_id: str | None = None,
    packet_count: int | None = None,
    error_code: str | None = None,
    error_summary: str | None = None,
) -> OperationEvent:
    """构建不包含文件内容和原始异常的 PCAP 目标事件。"""
    parameters: dict[str, str | int | float | bool] = {}
    if packet_count is not None:
        parameters["packetCount"] = packet_count
    return OperationEvent(
        event_code=code,
        zh_cn=zh_cn,
        en_us=en_us,
        outcome=outcome,
        impact=impact,
        target=OperationTarget(kind="pcap", id=pcap_id),
        operation_context_id=operation_context_id,
        task_id=task_id,
        parameters=parameters,
        error_code=error_code,
        error_summary=error_summary,
    )
