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

    Start here. Returns the list envelope: 'items' holds each policy's id,
    display_name, category, sequence_number, stateful flag and rule count;
    'returned'/'limit'/'total'/'truncated'/'hint' say whether the page is
    the whole answer — never read a full page as complete, narrow with
    name_filter or page with offset. Then get_dfw_policy for one policy's
    detail, or list_dfw_rules for the rules inside.

    Page with 'next_offset': pass the value back as 'offset' and stop when it
    is null. Do not loop on 'truncated' — that says this page is not the whole
    collection, which stays true on the last page of a walk.

    'rule_count' is null when NSX did not report one — that means "not
    retrieved", NOT "no rules", so do not conclude a null policy enforces
    nothing; call list_dfw_rules on it. Passing name_filter makes every
    count null (it is resolved via the Policy Search API, which carries no
    rule counts). A null anywhere adds 'rule_count_note' to the envelope.

    Args:
        target: NSX Manager target name from config; default if omitted.
        name_filter: Substring/glob match on policy display_name.
        limit: Page size, 1..1000 (default 50). Not a way to ask for
            everything — 0 or negative is rejected.
        offset: Matched policies to skip, 0 or more. Pass the previous
            response's 'next_offset'.
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

    Returns one policy object, not an envelope: category,
    sequence_number, stateful, scope and rule count. Use it once
    list_dfw_policies has narrowed to one id — never a display name. Then
    call list_dfw_rules for the rules inside.

    Args:
        policy_id: Policy identifier (e.g. 'app-tier-policy').
        target: Optional NSX Manager target from config.
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

    Returns the created policy dict (id, path, category, ...), else
    {"error", "hint"}. The policy is an empty container — rules must be
    added afterwards with create_dfw_rule.

    Args:
        policy_id: Unique policy id (alphanumerics, hyphens, underscores).
        display_name: Human-readable name.
        category: Ethernet, Emergency, Infrastructure, Environment or
            Application (default Application); sets DFW evaluation order,
            Ethernet first, Application last.
        sequence_number: Priority; lower = higher priority (default 10).
        stateful: Track connection state (default True).
        description: Optional description.
        target: Optional NSX Manager target from config.
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

    Returns the updated policy dict; omitted arguments keep their values,
    so read them with get_dfw_policy first. Use it to rename or
    re-prioritise the policy itself — to change a rule inside use
    update_dfw_rule.

    Args:
        policy_id: ID of the policy to update.
        display_name: New display name.
        description: New description.
        sequence_number: New sequence number.
        stateful: New stateful flag.
        target: Optional NSX Manager target from config.
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

    Returns {"status": "deleted", "message": ...}, else {"error", "hint"}.
    Refuses if the policy still holds active rules: list them with
    list_dfw_rules and clear each with delete_dfw_rule first.

    Args:
        policy_id: ID of the policy to delete.
        target: Optional NSX Manager target from config.
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
