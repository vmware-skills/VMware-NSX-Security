"""MCP tools for DFW security policies (1 read collection, 1 read detail, 3 write)."""

from typing import Optional

from vmware_policy import vmware_tool

from vmware_nsx_security.mcp_server._shared import (
    _DOCTOR_HINT,
    _audit,
    _get_connection,
    _safe_error,
    _write_error,
    mcp,
)


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_dfw_policies(
    target: Optional[str] = None,
    name_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """[READ] List DFW security policies in the default domain.

    Returns the list envelope: 'items' holds each policy's id, display_name,
    category, sequence_number, stateful flag, and rule count, while
    'returned'/'limit'/'total'/'truncated'/'hint' state whether the listing
    is complete — a full page is never mistaken for the whole answer.
    Defaults to the first 50 matches — use name_filter to narrow and offset
    to page on large estates. 'total' is the real policy count on an
    unfiltered listing and null when a name_filter is used.

    Args:
        target: Optional NSX Manager target name from config. Uses default if omitted.
        name_filter: Optional substring/glob match on policy display_name.
        limit: Max policies to return (default 50).
        offset: Number of matched policies to skip (pagination).
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import list_dfw_policies as _fn

        client = _get_connection(target)
        return _fn(client, name_filter=name_filter, limit=limit, offset=offset)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_dfw_policy(policy_id: str, target: Optional[str] = None) -> dict:
    """[READ] Get full details of a single DFW security policy.

    Args:
        policy_id: Policy identifier (e.g. 'app-tier-policy').
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import get_dfw_policy as _fn

        client = _get_connection(target)
        return _fn(client, policy_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(
    risk_level="medium",
    undo=lambda params, result: {
        "tool": "delete_dfw_policy",
        "params": {"policy_id": params.get("policy_id"), "target": params.get("target")},
        "skill": "nsx_security",
        "note": "Inverse of create_dfw_policy: delete the policy just created.",
    },
)
def create_dfw_policy(
    policy_id: str,
    display_name: str,
    category: str = "Application",
    sequence_number: int = 10,
    stateful: bool = True,
    description: str = "",
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Create a new DFW security policy.

    Args:
        policy_id: Unique policy ID (alphanumeric, hyphens, underscores).
        display_name: Human-readable policy name.
        category: Policy category — Ethernet, Emergency, Infrastructure,
            Environment, or Application (default: Application). Controls
            DFW evaluation order (Ethernet first, Application last).
        sequence_number: Priority order; lower number = higher priority (default: 10).
        stateful: Whether to track connection state (default: True).
        description: Optional description.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import create_dfw_policy as _fn

        client = _get_connection(target)
        result = _fn(
            client, policy_id, display_name,
            category=category, sequence_number=sequence_number,
            stateful=stateful, description=description,
        )
        _audit.log(
            target=target or "default",
            operation="create_dfw_policy",
            resource=policy_id,
            parameters={"display_name": display_name, "category": category},
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="create_dfw_policy", resource=policy_id,
            target=target, parameters={"display_name": display_name, "category": category},
        )


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def update_dfw_policy(
    policy_id: str,
    display_name: Optional[str] = None,
    description: Optional[str] = None,
    sequence_number: Optional[int] = None,
    stateful: Optional[bool] = None,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Partially update a DFW security policy (PATCH — only provided fields change).

    Args:
        policy_id: ID of the policy to update.
        display_name: New display name (optional).
        description: New description (optional).
        sequence_number: New sequence number (optional).
        stateful: New stateful flag (optional).
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import update_dfw_policy as _fn

        client = _get_connection(target)
        result = _fn(
            client, policy_id,
            display_name=display_name, description=description,
            sequence_number=sequence_number, stateful=stateful,
        )
        _audit.log(
            target=target or "default",
            operation="update_dfw_policy",
            resource=policy_id,
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="update_dfw_policy", resource=policy_id,
            target=target,
        )


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_dfw_policy(policy_id: str, target: Optional[str] = None) -> dict:
    """[WRITE] Delete a DFW security policy.

    Raises ValueError if the policy still contains active rules.
    Delete all rules in the policy first before deleting the policy itself.

    Args:
        policy_id: ID of the policy to delete.
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import delete_dfw_policy as _fn

        client = _get_connection(target)
        result = _fn(client, policy_id)
        _audit.log(
            target=target or "default",
            operation="delete_dfw_policy",
            resource=policy_id,
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="delete_dfw_policy", resource=policy_id,
            target=target,
        )
