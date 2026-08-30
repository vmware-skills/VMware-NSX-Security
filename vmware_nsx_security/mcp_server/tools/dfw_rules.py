"""MCP tools for DFW firewall rules (1 read stats, 3 write)."""

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
def list_dfw_rules(
    policy_id: str,
    target: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """[READ] List rules in a DFW security policy.

    Returns the list envelope: 'items' holds each rule's id, display_name,
    action, sources, destinations, services, direction, disabled flag and
    sequence number; 'returned'/'limit'/'truncated'/'hint' say whether the
    page is complete. 'total' is always null here — a full page reports
    truncated=true and must be paged with offset; one Application policy
    can hold thousands of rules. Get policy_id from list_dfw_policies;
    then get_dfw_rule_stats for a rule's hit counts.

    Page with 'next_offset': pass the value back as 'offset' and stop when it
    is null. Do not loop on 'truncated' — that says this page is not the whole
    collection, which stays true on the last page of a walk.

    Args:
        policy_id: Parent policy identifier.
        target: Optional NSX Manager target from config.
        limit: Page size, 1..1000 (default 50). Not a way to ask for
            everything — 0 or negative is rejected.
        offset: Rules to skip, 0 or more. Pass the previous response's
            'next_offset'.
    """
    try:
        from vmware_nsx_security.ops.dfw_policy import list_dfw_rules as _fn

        client = _get_connection(target)
        return _fn(client, policy_id, limit=limit, offset=offset)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_dfw_rule_stats(
    policy_id: str,
    rule_id: str,
    target: Optional[str] = None,
) -> dict:
    """[READ] Get packet/byte hit-count statistics for a DFW rule.

    Returns one flat stats object, not an envelope: packet_count,
    byte_count, session_count, hit_count, popularity_index. Use it before
    update_dfw_rule or delete_dfw_rule to see if a rule still matches
    traffic; counters are cumulative and may read zero on a new rule. Ids
    come from list_dfw_rules.

    Args:
        policy_id: Parent policy identifier.
        rule_id: Rule identifier.
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_rules import get_dfw_rule_stats as _fn

        client = _get_connection(target)
        return _fn(client, policy_id, rule_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(
    risk_level="medium",
    undo=lambda params, result: {
        "tool": "delete_dfw_rule",
        "params": {
            "policy_id": params.get("policy_id"),
            "rule_id": params.get("rule_id"),
            "target": params.get("target"),
        },
        "skill": "nsx_security",
        "note": "Inverse of create_dfw_rule: delete the rule just created.",
    },
)
def create_dfw_rule(
    policy_id: str,
    rule_id: str,
    display_name: str,
    action: str = "ALLOW",
    sources: Optional[list[str]] = None,
    destinations: Optional[list[str]] = None,
    services: Optional[list[str]] = None,
    scope: Optional[list[str]] = None,
    direction: str = "IN_OUT",
    ip_protocol: str = "IPV4_IPV6",
    logged: bool = False,
    disabled: bool = False,
    sequence_number: int = 10,
    description: str = "",
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Create a firewall rule under an existing DFW security policy.

    Returns the created rule dict (id, path, action, ...), else
    {"error", "hint"}; a bad action/direction/ip_protocol lists the valid
    values. PUT semantics: reusing a rule_id overwrites that rule,
    enforced immediately unless disabled=True. Pick policy_id with
    list_dfw_policies first; prefer update_dfw_rule to edit one and
    delete_dfw_rule to remove one.

    Args:
        policy_id: Parent policy id, from list_dfw_policies.
        rule_id: Unique rule id within that policy.
        display_name: Human-readable name.
        action: ALLOW, DROP, REJECT or JUMP_TO_APPLICATION (default
            ALLOW); JUMP_TO_APPLICATION needs an Environment policy.
        sources: Source group paths like
            ['/infra/domains/default/groups/web']; omit for any.
        destinations: Destination group paths; omit for any.
        services: Service paths; omit for all.
        scope: Applied-to group/segment paths; omit for the whole DFW.
        direction: IN, OUT or IN_OUT (default IN_OUT).
        ip_protocol: IPV4, IPV6 or IPV4_IPV6 (default IPV4_IPV6).
        logged: Log matched traffic (default False).
        disabled: Create the rule unenforced (default False).
        sequence_number: Priority; lower matches first (default 10).
        description: Optional free text.
        target: Target name from config; default if omitted.
    """
    try:
        from vmware_nsx_security.ops.dfw_rules import create_dfw_rule as _fn

        client = _get_connection(target)
        result = _fn(
            client, policy_id, rule_id, display_name,
            action=action, sources=sources, destinations=destinations,
            services=services, scope=scope, direction=direction,
            ip_protocol=ip_protocol, logged=logged, disabled=disabled,
            sequence_number=sequence_number, description=description,
        )
        _audit.log(
            target=target or "default",
            operation="create_dfw_rule",
            resource=f"{policy_id}/{rule_id}",
            parameters={"action": action, "display_name": display_name},
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="create_dfw_rule", resource=f"{policy_id}/{rule_id}",
            target=target, parameters={"action": action, "display_name": display_name},
        )


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def update_dfw_rule(
    policy_id: str,
    rule_id: str,
    display_name: Optional[str] = None,
    action: Optional[str] = None,
    sources: Optional[list[str]] = None,
    destinations: Optional[list[str]] = None,
    services: Optional[list[str]] = None,
    logged: Optional[bool] = None,
    disabled: Optional[bool] = None,
    sequence_number: Optional[int] = None,
    description: Optional[str] = None,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Partially update a DFW rule (PATCH — only provided fields change).

    Returns the updated rule dict; omitted arguments keep their values, so
    read them with list_dfw_rules first. Use it to retarget, re-prioritise
    or disable a rule — to add one use create_dfw_rule, to remove one
    delete_dfw_rule.

    Args:
        policy_id: Parent policy identifier.
        rule_id: Rule identifier to update.
        display_name: New name.
        action: New firewall action.
        sources: New source groups.
        destinations: New destination groups.
        services: New services.
        logged: New logged flag.
        disabled: New disabled flag.
        sequence_number: New sequence number.
        description: New description.
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.dfw_rules import update_dfw_rule as _fn

        client = _get_connection(target)
        result = _fn(
            client, policy_id, rule_id,
            display_name=display_name, action=action,
            sources=sources, destinations=destinations,
            services=services, logged=logged, disabled=disabled,
            sequence_number=sequence_number, description=description,
        )
        _audit.log(
            target=target or "default",
            operation="update_dfw_rule",
            resource=f"{policy_id}/{rule_id}",
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="update_dfw_rule", resource=f"{policy_id}/{rule_id}",
            target=target,
        )


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_dfw_rule(policy_id: str, rule_id: str, target: Optional[str] = None) -> dict:
    """[WRITE] Permanently delete one DFW rule from its parent security policy.

    Returns {"status": "deleted", "message": ...}, else {"error", "hint"}.
    Irreversible and immediate: traffic it matched falls through to
    lower-priority rules or the policy default. Confirm rule_id
    with list_dfw_rules and check recent hits with get_dfw_rule_stats
    first; prefer update_dfw_rule with disabled=True when you may need the
    rule back. To remove a whole policy use delete_dfw_policy — it refuses
    while rules remain, whereas this tool has no such guard.

    Args:
        policy_id: Parent policy id, from list_dfw_policies.
        rule_id: Rule id within that policy, from list_dfw_rules.
        target: Target name from config; default if omitted.
    """
    try:
        from vmware_nsx_security.ops.dfw_rules import delete_dfw_rule as _fn

        client = _get_connection(target)
        result = _fn(client, policy_id, rule_id)
        _audit.log(
            target=target or "default",
            operation="delete_dfw_rule",
            resource=f"{policy_id}/{rule_id}",
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="delete_dfw_rule", resource=f"{policy_id}/{rule_id}",
            target=target,
        )
