"""MCP tools for NSX security groups (2 read, 2 write)."""

from typing import Optional

from vmware_policy import vmware_tool

from mcp_server._shared import (
    _DOCTOR_HINT,
    _audit,
    _get_connection,
    _safe_error,
    _write_error,
    mcp,
)


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_groups(
    target: Optional[str] = None,
    name_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """[READ] List NSX security groups in the default domain.

    Returns the list envelope: 'items' holds each group's id, display_name,
    description, and expression count, while 'returned'/'limit'/'total'/
    'truncated'/'hint' state whether the listing is complete — a full page is
    never mistaken for the whole answer. Defaults to the first 50 matches —
    use name_filter to narrow and offset to page on large estates. 'total' is
    the real group count on an unfiltered listing and null when a name_filter
    is used.

    Args:
        target: Optional NSX Manager target name from config.
        name_filter: Optional substring/glob match on group display_name.
        limit: Max groups to return (default 50).
        offset: Number of matched groups to skip (pagination).
    """
    try:
        from vmware_nsx_security.ops.security_group import list_groups as _fn

        client = _get_connection(target)
        return _fn(client, name_filter=name_filter, limit=limit, offset=offset)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_group(group_id: str, target: Optional[str] = None) -> dict:
    """[READ] Get details of a security group including membership criteria and effective members.

    Returns expression rules and up to 50 effective VirtualMachine members.

    Args:
        group_id: Group identifier (e.g. 'web-tier-vms').
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import get_group as _fn

        client = _get_connection(target)
        return _fn(client, group_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(
    risk_level="medium",
    undo=lambda params, result: {
        "tool": "delete_group",
        "params": {"group_id": params.get("group_id"), "target": params.get("target")},
        "skill": "nsx_security",
        "note": "Inverse of create_group: delete the security group just created.",
    },
)
def create_group(
    group_id: str,
    display_name: str,
    description: str = "",
    tag_scope: Optional[str] = None,
    tag_value: Optional[str] = None,
    ip_addresses: Optional[list[str]] = None,
    segment_paths: Optional[list[str]] = None,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Create an NSX security group with optional membership criteria.

    Multiple criteria are ORed together (NSX only permits AND between
    same-member-type Conditions, so heterogeneous expression types must
    join with OR):
    - tag_scope / tag_value: include VMs matching the NSX tag
      (Condition with pipe-delimited value "scope|tag")
    - ip_addresses: include specific IP addresses or CIDRs
    - segment_paths: include all VMs on specified segments

    Args:
        group_id: Unique group identifier (alphanumeric, hyphens, underscores).
        display_name: Human-readable group name.
        description: Optional description.
        tag_scope: NSX tag scope for VM membership (e.g. 'env').
        tag_value: NSX tag value for VM membership (e.g. 'production').
        ip_addresses: List of IP addresses or CIDRs (e.g. ['10.0.1.0/24']).
        segment_paths: List of NSX segment policy paths.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import create_group as _fn

        client = _get_connection(target)
        result = _fn(
            client, group_id, display_name,
            description=description,
            tag_scope=tag_scope, tag_value=tag_value,
            ip_addresses=ip_addresses, segment_paths=segment_paths,
        )
        _audit.log(
            target=target or "default",
            operation="create_group",
            resource=group_id,
            parameters={"display_name": display_name},
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="create_group", resource=group_id,
            target=target, parameters={"display_name": display_name},
        )


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_group(group_id: str, target: Optional[str] = None) -> dict:
    """[WRITE] Delete an NSX security group.

    Refuses deletion if any entity references the group, using NSX's own
    group-associations dependency API. This covers every reference class:
    DFW rules/policies, gateway-firewall policies, nested groups (another
    group referencing this one), and service-insertion/IDS-IPS policies.
    Also refuses if the reference check itself fails (fail-safe).

    Args:
        group_id: ID of the group to delete.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import delete_group as _fn

        client = _get_connection(target)
        result = _fn(client, group_id)
        _audit.log(
            target=target or "default",
            operation="delete_group",
            resource=group_id,
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="delete_group", resource=group_id,
            target=target,
        )
