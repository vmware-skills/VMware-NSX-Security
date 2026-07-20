"""MCP tools for NSX Traceflow (1 write run, 1 read result)."""

from typing import Optional

from vmware_policy import vmware_tool

from vmware_nsx_security.mcp_server._shared import _DOCTOR_HINT, _get_connection, _safe_error, mcp


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def run_traceflow(
    src_lport_id: str,
    src_ip: str,
    dst_ip: str,
    protocol: str = "TCP",
    dst_port: int = 80,
    src_port: int = 1234,
    ttl: int = 64,
    timeout_seconds: int = 20,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Run a Traceflow to trace a packet's path through the NSX overlay.

    Injects a synthetic probe from the source port. Returns traceflow_id,
    operation_state (IN_PROGRESS / FINISHED / FAILED) and hop-by-hop
    observations typed by resource_type; Dropped* ones carry reason and
    acl_rule_id. Use it to find which DFW rule drops a flow, then
    get_dfw_rule_stats on that rule. A FINISHED traceflow is deleted
    server-side and its id 404s; only one still IN_PROGRESS at
    timeout_seconds survives for get_traceflow_result to poll.

    Args:
        src_lport_id: Source logical port ID — the VM NIC attachment UUID.
            This skill does not enumerate ports; run vmware-nsx's
            get_segment_port_for_vm to obtain one.
        src_ip: Probe source IP.
        dst_ip: Destination IP.
        protocol: TCP, UDP or ICMP (default TCP).
        dst_port: Destination port for TCP/UDP (default 80).
        src_port: Source port for TCP/UDP (default 1234).
        ttl: IP TTL (default 64).
        timeout_seconds: Max seconds to wait (default 20).
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.traceflow import run_traceflow as _fn

        client = _get_connection(target)
        return _fn(
            client, src_lport_id, src_ip, dst_ip,
            protocol=protocol, dst_port=dst_port,
            src_port=src_port, ttl=ttl, timeout_seconds=timeout_seconds,
        )
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_traceflow_result(traceflow_id: str, target: Optional[str] = None) -> dict:
    """[READ] Get the current state and observations of an existing Traceflow.

    Use this to check a previously initiated traceflow without waiting.
    Returns operation_state (IN_PROGRESS / FINISHED / FAILED) and
    observations typed by resource_type; Dropped* ones carry reason and
    acl_rule_id. Only a traceflow run_traceflow left IN_PROGRESS at its
    timeout is still on the manager — a completed one is deleted
    server-side and its id 404s here.

    Args:
        traceflow_id: Traceflow ID from a previous run_traceflow call.
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.traceflow import get_traceflow_result as _fn

        client = _get_connection(target)
        return _fn(client, traceflow_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}
