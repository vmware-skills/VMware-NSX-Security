"""Security group (NSX Group) CRUD operations.

Covers the NSX Policy Groups API:
  GET/PUT/DELETE /policy/api/v1/infra/domains/default/groups/...

Groups can be defined by VM tags, segment membership, IP addresses,
or combinations thereof (AND/OR expressions).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from vmware_policy import paginated, sanitize

from vmware_nsx_security.ops._paginate import (
    DEFAULT_LIMIT,
    known_total,
    paginate,
)
from vmware_nsx_security.ops._search import search_by_name
from vmware_nsx_security.ops._validate import validate_id as _validate_id

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.security_group")

_GROUPS_BASE = "/policy/api/v1/infra/domains/default/groups"


# ---------------------------------------------------------------------------
# Group list / get
# ---------------------------------------------------------------------------


def list_groups(
    client: NsxClient,
    name_filter: str | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict:
    """List security groups in the default domain.

    Args:
        client: Authenticated NsxClient instance.
        name_filter: Optional substring/glob match on display_name.
        limit: Max groups to return (default 50). Avoids flooding agent
            context on large estates.
        offset: Number of matched groups to skip (pagination).

    Returns:
        The family list envelope; ``items`` holds group summary dicts with
        id, display_name, expression type counts, and member count.
        ``total`` is the real group count on the unfiltered path when the
        scan stayed under the ``get_all`` cap, and ``None`` otherwise —
        ``search_by_name`` returns only its matches, so a filtered listing
        has no trustworthy total to report.

    Note:
        A ``name_filter`` is resolved server-side via the Policy Search API
        so a match ranked past the ``get_all`` safety cap on a large estate
        is still found — a plain client-side filter would silently miss it.
    """
    if name_filter:
        items = search_by_name(client, "Group", _GROUPS_BASE, name_filter)
        total = None
    else:
        items = client.get_all(_GROUPS_BASE)
        total = known_total(items)
    rows = [
        {
            "id": sanitize(g.get("id", "")),
            "display_name": sanitize(g.get("display_name", "")),
            "description": sanitize(g.get("description", "")),
            "expression_count": len(g.get("expression", [])),
            "tags": g.get("tags", []),
            "path": sanitize(g.get("path", "")),
        }
        for g in paginate(items, limit, offset)
    ]
    return paginated(rows, limit=limit, total=total)


def get_group(client: NsxClient, group_id: str) -> dict:
    """Get details of a security group including its membership criteria.

    Args:
        client: Authenticated NsxClient instance.
        group_id: Group identifier (e.g. 'web-tier-vms').

    Returns:
        Group detail dict with id, display_name, expression rules,
        and member paths (up to 50 effective members).
    """
    _validate_id(group_id, "group_id")
    g = client.get(f"{_GROUPS_BASE}/{group_id}")

    # Try to get effective members. A failed fetch must NOT masquerade as
    # an empty group: member_count becomes None and members_error explains
    # why, so callers can tell "0 members" apart from "could not check".
    members: list[dict] = []
    member_count: int | None = 0
    members_error: str | None = None
    try:
        member_data = client.get(
            f"{_GROUPS_BASE}/{group_id}/members/virtual-machines"
        )
        members = [
            {
                "id": sanitize(m.get("external_id", "")),
                "display_name": sanitize(m.get("display_name", "")),
                "type": "VirtualMachine",
            }
            for m in member_data.get("results", [])[:50]
        ]
        member_count = len(members)
    except Exception as exc:
        _log.warning("Could not fetch members for group %s: %s", group_id, exc)
        member_count = None
        members_error = sanitize(str(exc))

    result: dict[str, Any] = {
        "id": sanitize(g.get("id", "")),
        "display_name": sanitize(g.get("display_name", "")),
        "description": sanitize(g.get("description", "")),
        "expression": g.get("expression", []),
        "tags": g.get("tags", []),
        "path": sanitize(g.get("path", "")),
        "member_count": member_count,
        "members": members,
        "_revision": g.get("_revision"),
    }
    if members_error is not None:
        result["members_error"] = members_error
    return result


# ---------------------------------------------------------------------------
# Group create / delete
# ---------------------------------------------------------------------------


def create_group(
    client: NsxClient,
    group_id: str,
    display_name: str,
    description: str = "",
    tag_scope: str | None = None,
    tag_value: str | None = None,
    ip_addresses: list[str] | None = None,
    segment_paths: list[str] | None = None,
) -> dict:
    """Create a security group with optional membership criteria.

    Membership criteria are applied in order:
    1. If ``tag_scope`` and/or ``tag_value`` provided — VM tag condition
       (Policy Condition with pipe-delimited ``value`` of "scope|tag").
    2. If ``ip_addresses`` provided — IPAddressExpression.
    3. If ``segment_paths`` provided — PathExpression for segments.

    Multiple criteria are joined with OR ``ConjunctionOperator`` entries:
    NSX only permits AND between Conditions of the same member type, so
    heterogeneous expression types (Condition vs IPAddressExpression vs
    PathExpression) must be ORed.

    Args:
        client: Authenticated NsxClient instance.
        group_id: Unique group identifier (alphanumeric + hyphens).
        display_name: Human-readable group name.
        description: Optional description.
        tag_scope: NSX tag scope for VM membership (e.g. 'env').
        tag_value: NSX tag value for VM membership (e.g. 'production').
        ip_addresses: List of IP addresses/CIDRs for IP-based membership.
        segment_paths: List of NSX segment policy paths for segment membership.

    Returns:
        Created group dict as returned by the API.
    """
    _validate_id(group_id, "group_id")

    expressions: list[dict[str, Any]] = []

    if tag_scope or tag_value:
        # Policy Condition tag matching uses a single pipe-delimited
        # "scope|tag" value string; empty scope → "|tag".
        tag_expr: dict[str, Any] = {
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
            "value": f"{sanitize(tag_scope) if tag_scope else ''}|{sanitize(tag_value or '')}",
        }
        if tag_scope:
            tag_expr["scope_operator"] = "EQUALS"
        expressions.append(tag_expr)

    # NSX only allows AND between same-member-type Conditions. The
    # criteria below are different expression types, so join with OR.
    if ip_addresses:
        if expressions:
            expressions.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
        expressions.append({
            "resource_type": "IPAddressExpression",
            "ip_addresses": ip_addresses,
        })

    if segment_paths:
        if expressions:
            expressions.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
        expressions.append({
            "resource_type": "PathExpression",
            "paths": segment_paths,
        })

    body: dict[str, Any] = {
        "display_name": sanitize(display_name),
        "expression": expressions,
    }
    if description:
        body["description"] = sanitize(description)

    result = client.put(f"{_GROUPS_BASE}/{group_id}", body)
    _log.info("Created security group: %s", group_id)
    return result


def delete_group(client: NsxClient, group_id: str) -> dict[str, str]:
    """Delete a security group after checking every entity that references it.

    Uses NSX's own dependency API,
    ``GET .../groups/<id>/group-associations``, which reports *all*
    entities that reference the group regardless of reference class — DFW
    rules/policies, gateway-firewall policies, nested groups (another
    group's PathExpression/Condition), service-insertion and IDS/IPS
    policies, and load-balancer/VPN configs. This is both more complete
    and far cheaper than hand-walking every policy's rule list: the old
    DFW-only scan could pass while NSX still 409'd on delete, or could
    succeed and orphan a nested-group reference.

    Fails safe: if the association check itself errors (API unreachable),
    deletion is aborted rather than proceeding blind.

    Args:
        client: Authenticated NsxClient instance.
        group_id: ID of the group to delete.

    Returns:
        Dict with 'status' and 'message' keys on success.

    Raises:
        ValueError: If the group is referenced by any entity, or if the
            association check could not be completed.
    """
    _validate_id(group_id, "group_id")

    # Ask NSX which entities reference this group. The group-associations
    # endpoint returns one entry per referencing entity (target_type names
    # the reference class: SecurityPolicy, GatewayPolicy, Group, etc.), so
    # nested-group and gateway-firewall references are covered without a
    # per-policy rule walk.
    try:
        associations = client.get_all(
            f"{_GROUPS_BASE}/{group_id}/group-associations"
        )
    except Exception as exc:
        raise ValueError(
            f"Cannot delete group '{group_id}': the reference (group-"
            f"associations) check failed ({exc}). Refusing to delete a "
            "group that may still be in use. Verify NSX connectivity (run "
            "'vmware-nsx-security doctor') and retry."
        ) from exc

    if associations:
        refs = [
            f"{sanitize(a.get('target_type', 'Unknown'))}:"
            f"{sanitize(a.get('target_display_name') or a.get('path', 'unknown'))}"
            for a in associations
        ]
        raise ValueError(
            f"Cannot delete group '{group_id}': referenced by {len(refs)} "
            f"entity/entities (nested groups, DFW/gateway firewall, "
            f"service-insertion, etc.): {refs}. Remove the references first."
        )

    client.delete(f"{_GROUPS_BASE}/{group_id}")
    _log.info("Deleted security group: %s", group_id)
    return {"status": "deleted", "message": f"Security group '{group_id}' deleted."}
