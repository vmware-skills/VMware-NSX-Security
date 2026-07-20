"""DFW rule CRUD and statistics operations.

Covers individual rule management under a security policy:
  PUT/PATCH/DELETE /policy/api/v1/infra/domains/default/security-policies/<id>/rules/<rule-id>
  GET              /policy/api/v1/infra/domains/default/security-policies/<id>/rules/<rule-id>/statistics
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from vmware_policy import sanitize

from vmware_nsx_security.ops._validate import validate_id as _validate_id

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.dfw_rules")

_DFW_BASE = "/policy/api/v1/infra/domains/default/security-policies"

_VALID_ACTIONS = {"ALLOW", "DROP", "REJECT", "JUMP_TO_APPLICATION"}
_VALID_DIRECTIONS = {"IN", "OUT", "IN_OUT"}
_VALID_IP_PROTOS = {"IPV4", "IPV6", "IPV4_IPV6"}


# ---------------------------------------------------------------------------
# Rule CRUD
# ---------------------------------------------------------------------------


def create_dfw_rule(
    client: NsxClient,
    policy_id: str,
    rule_id: str,
    display_name: str,
    action: str = "ALLOW",
    sources: list[str] | None = None,
    destinations: list[str] | None = None,
    services: list[str] | None = None,
    scope: list[str] | None = None,
    direction: str = "IN_OUT",
    ip_protocol: str = "IPV4_IPV6",
    logged: bool = False,
    disabled: bool = False,
    sequence_number: int = 10,
    description: str = "",
) -> dict:
    """Create a DFW rule under the given policy via PUT.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Parent policy ID.
        rule_id: Unique rule identifier (alphanumeric + hyphens).
        display_name: Human-readable rule name.
        action: Firewall action — ALLOW, DROP, REJECT, or
            JUMP_TO_APPLICATION (default: ALLOW). Note:
            JUMP_TO_APPLICATION is only valid in policies whose category
            is Environment; NSX rejects it in other categories.
        sources: List of source group paths or 'ANY' (default: ANY).
        destinations: List of destination group paths or 'ANY' (default: ANY).
        services: List of service paths or 'ANY' (default: ANY).
        scope: List of scope paths (groups/segments) the rule applies to.
        direction: Traffic direction — IN, OUT, or IN_OUT (default: IN_OUT).
        ip_protocol: IP version — IPV4, IPV6, or IPV4_IPV6 (default: IPV4_IPV6).
        logged: Whether to log matching traffic (default False).
        disabled: Whether the rule is disabled (default False).
        sequence_number: Rule priority within the policy.
        description: Optional description.

    Returns:
        Created rule dict as returned by the API.

    Raises:
        ValueError: If action, direction, or ip_protocol is invalid.
    """
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")

    if action not in _VALID_ACTIONS:
        raise ValueError(
            f"Invalid action. Must be one of: {_VALID_ACTIONS}. "
            "JUMP_TO_APPLICATION requires the parent policy's category to be "
            f"Environment — run get_dfw_policy on '{policy_id}' to check. "
            f"Got: '{action}'"
        )
    if direction not in _VALID_DIRECTIONS:
        raise ValueError(f"Invalid direction '{direction}'. Must be one of: {_VALID_DIRECTIONS}")
    if ip_protocol not in _VALID_IP_PROTOS:
        raise ValueError(f"Invalid ip_protocol '{ip_protocol}'. Must be one of: {_VALID_IP_PROTOS}")

    body: dict[str, Any] = {
        "display_name": sanitize(display_name),
        "action": action,
        "source_groups": sources if sources is not None else ["ANY"],
        "destination_groups": destinations if destinations is not None else ["ANY"],
        "services": services if services is not None else ["ANY"],
        "direction": direction,
        "ip_protocol": ip_protocol,
        "logged": logged,
        "disabled": disabled,
        "sequence_number": sequence_number,
    }
    if scope:
        body["scope"] = scope
    if description:
        body["description"] = sanitize(description)

    result = client.put(f"{_DFW_BASE}/{policy_id}/rules/{rule_id}", body)
    _log.info("Created DFW rule: %s in policy %s (action=%s)", rule_id, policy_id, action)
    return result


def update_dfw_rule(
    client: NsxClient,
    policy_id: str,
    rule_id: str,
    display_name: str | None = None,
    action: str | None = None,
    sources: list[str] | None = None,
    destinations: list[str] | None = None,
    services: list[str] | None = None,
    logged: bool | None = None,
    disabled: bool | None = None,
    sequence_number: int | None = None,
    description: str | None = None,
) -> dict:
    """Partially update a DFW rule via PATCH.

    Only explicitly provided fields are modified.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Parent policy ID.
        rule_id: ID of the rule to update.
        display_name: New display name (optional).
        action: New action (optional).
        sources: New source groups (optional).
        destinations: New destination groups (optional).
        services: New services list (optional).
        logged: New logged flag (optional).
        disabled: New disabled flag (optional).
        sequence_number: New sequence number (optional).
        description: New description (optional).

    Returns:
        Updated rule dict as returned by the API.
    """
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")

    if action is not None and action not in _VALID_ACTIONS:
        raise ValueError(
            f"Invalid action. Must be one of: {_VALID_ACTIONS}. "
            "JUMP_TO_APPLICATION requires the parent policy's category to be "
            f"Environment — run get_dfw_policy on '{policy_id}' to check. "
            f"Got: '{action}'"
        )

    body: dict[str, Any] = {}
    if display_name is not None:
        body["display_name"] = sanitize(display_name)
    if action is not None:
        body["action"] = action
    if sources is not None:
        body["source_groups"] = sources
    if destinations is not None:
        body["destination_groups"] = destinations
    if services is not None:
        body["services"] = services
    if logged is not None:
        body["logged"] = logged
    if disabled is not None:
        body["disabled"] = disabled
    if sequence_number is not None:
        body["sequence_number"] = sequence_number
    if description is not None:
        body["description"] = sanitize(description)

    if not body:
        raise ValueError(
            "No fields provided. This is a PATCH — specify at least one of: "
            "display_name, action, sources, destinations, services, logged, "
            "disabled, sequence_number, description. Run list_dfw_rules to "
            f"see current values. Rule: '{rule_id}'"
        )

    result = client.patch(f"{_DFW_BASE}/{policy_id}/rules/{rule_id}", body)
    _log.info("Updated DFW rule: %s in policy %s", rule_id, policy_id)
    return result


def delete_dfw_rule(client: NsxClient, policy_id: str, rule_id: str) -> dict[str, str]:
    """Delete a DFW rule from the given policy.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Parent policy ID.
        rule_id: ID of the rule to delete.

    Returns:
        Dict with 'status' and 'message' keys on success.
    """
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")

    client.delete(f"{_DFW_BASE}/{policy_id}/rules/{rule_id}")
    _log.info("Deleted DFW rule: %s from policy %s", rule_id, policy_id)
    return {
        "status": "deleted",
        "message": f"DFW rule '{rule_id}' deleted from policy '{policy_id}'.",
    }


# ---------------------------------------------------------------------------
# Rule statistics
# ---------------------------------------------------------------------------


def get_dfw_rule_stats(client: NsxClient, policy_id: str, rule_id: str) -> dict:
    """Get hit-count statistics for a DFW rule.

    Returns packet and byte counters showing how many times the rule
    has been matched by traffic.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Parent policy ID.
        rule_id: ID of the rule to query statistics for.

    Returns:
        Statistics dict with packet_count, byte_count, session_count,
        hit_count, and popularity_index (real RuleStatistics fields).
    """
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")

    stats = client.get(
        f"{_DFW_BASE}/{policy_id}/rules/{rule_id}/statistics"
    )
    # NSX returns an array of per-enforcement-point stats; sum them up
    results = stats.get("results", [stats])
    total_packets = sum(r.get("packet_count", 0) for r in results)
    total_bytes = sum(r.get("byte_count", 0) for r in results)
    total_sessions = sum(r.get("session_count", 0) for r in results)
    total_hits = sum(r.get("hit_count", 0) for r in results)
    popularity = max((r.get("popularity_index", 0) for r in results), default=0)

    return {
        "policy_id": policy_id,
        "rule_id": rule_id,
        "packet_count": total_packets,
        "byte_count": total_bytes,
        "session_count": total_sessions,
        "hit_count": total_hits,
        "popularity_index": popularity,
        "raw": results,
    }
