from app.services.operation_audit import pcap_event
from veydeck_suite_runtime import OperationImpact, OperationOutcome


def test_pcap_event_contains_only_safe_summary() -> None:
    event = pcap_event(
        "pcap_built",
        "构建流量文件",
        "Build traffic file",
        "pcap-1",
        OperationOutcome.SUCCESS,
        OperationImpact.INFO,
        operation_context_id="context-1",
        packet_count=7,
    )
    payload = event.to_dict()
    assert payload["target"] == {
        "kind": "pcap",
        "id": "pcap-1",
        "displayName": None,
        "ownership": None,
    }
    parameters = payload["parameters"]
    assert isinstance(parameters, dict)
    assert parameters == {"packetCount": 7}
    assert "filename" not in parameters
    assert payload["operationContextId"] == "context-1"
    assert payload["taskId"] is None
