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
    action, sources, destinations, services, direction, disabled flag, and
    sequence number, while 'returned'/'limit'/'truncated'/'hint' state
    whether the listing is complete. Defaults to the first 50 rules — large
    Application policies can hold thousands, so use offset to page rather
    than draining every rule into context. 'total' is always null here: the
    fetch is bounded to the requested window, so a full page reports
    truncated=true and should be paged to confirm.

    Args:
        policy_id: Parent policy identifier.
        target: Optional NSX Manager target name from config.
        limit: Max rules to return (default 50).
        offset: Number of rules to skip (pagination).
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

    Returns packet_count, byte_count, session_count, hit_count, and
    popularity_index (real NSX RuleStatistics fields).

    Args:
        policy_id: Parent policy identifier.
        rule_id: Rule identifier.
        target: Optional NSX Manager target name from config.
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

    Creates via PUT, so calling again with the same rule_id replaces that
    rule's definition. The rule is enforced on the NSX data plane
    immediately unless disabled=True. Pick the policy_id with
    list_dfw_policies first; to change selected fields of an existing rule
    prefer update_dfw_rule, and to remove one use delete_dfw_rule. Calls
    are pre-checked by the vmware-policy engine (risk level: medium) and
    audited to ~/.vmware/audit.db.

    Returns the created rule dict from the NSX API (id, path, action,
    sequence_number, ...). On failure returns {"error", "hint"}; an
    invalid action/direction/ip_protocol returns an error listing the
    valid values.

    Args:
        policy_id: Parent policy ID (alphanumeric and hyphens), as
            returned by list_dfw_policies.
        rule_id: Unique rule ID within the policy (alphanumeric and
            hyphens). Reusing an existing ID overwrites that rule.
        display_name: Human-readable rule name.
        action: Firewall action — ALLOW, DROP, REJECT, or
            JUMP_TO_APPLICATION (default: ALLOW). JUMP_TO_APPLICATION is
            only valid in policies whose category is Environment.
        sources: Source group policy paths, e.g.
            ['/infra/domains/default/groups/web']. Use ['ANY'] or omit
            for any source (default: ANY).
        destinations: Destination group policy paths, same format as
            sources. Use ['ANY'] or omit for any destination (default: ANY).
        services: Service policy paths, e.g. ['/infra/services/HTTPS'].
            Use ['ANY'] or omit for all services (default: ANY).
        scope: Applied-to group/segment paths limiting where the rule is
            enforced. Omit to apply to the entire DFW.
        direction: Traffic direction — IN, OUT, or IN_OUT (default: IN_OUT).
        ip_protocol: IP version — IPV4, IPV6, or IPV4_IPV6 (default: IPV4_IPV6).
        logged: Log matched traffic (default: False).
        disabled: Create the rule disabled so it is not enforced
            (default: False).
        sequence_number: Rule priority within the policy; lower values
            match first (default: 10).
        description: Optional free-text description.
        target: Optional NSX Manager target name from config. Uses the
            default target if omitted.
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

    Args:
        policy_id: Parent policy identifier.
        rule_id: Rule identifier to update.
        display_name: New display name (optional).
        action: New firewall action (optional).
        sources: New source groups (optional).
        destinations: New destination groups (optional).
        services: New services (optional).
        logged: New logged flag (optional).
        disabled: New disabled flag (optional).
        sequence_number: New sequence number (optional).
        description: New description (optional).
        target: Optional NSX Manager target name from config.
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

    Deletion is irreversible and takes effect immediately on the NSX data
    plane: traffic the rule matched falls through to lower-priority rules
    or the policy's default action. Confirm the rule_id with
    list_dfw_rules and check recent hits with get_dfw_rule_stats before
    deleting. To remove an entire policy use delete_dfw_policy (it refuses
    while rules remain); this tool deletes a single rule without that
    guard. Calls are pre-checked by the vmware-policy engine (risk level:
    high) and audited to ~/.vmware/audit.db; the CLI equivalent
    additionally requires double confirmation.

    Returns {"status": "deleted", "message": ...} on success, or
    {"error", "hint"} on failure (e.g. rule not found, connectivity).

    Args:
        policy_id: ID of the parent security policy (alphanumeric and
            hyphens), as returned by list_dfw_policies.
        rule_id: ID of the rule to delete within that policy, as returned
            by list_dfw_rules.
        target: Optional NSX Manager target name from config. Uses the
            default target if omitted.
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
