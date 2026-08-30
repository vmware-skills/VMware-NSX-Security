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
    page_envelope,
    paginate,
    validate_page_args,
)
from vmware_nsx_security.ops._search import search_by_name
from vmware_nsx_security.ops._validate import validate_id as _validate_id
from vmware_nsx_security.ops.exclusion import ExclusionIndex, exclusion_index

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.security_group")

_GROUPS_BASE = "/policy/api/v1/infra/domains/default/groups"

# How many effective members ``get_group`` returns. A production group can hold
# thousands; the sample keeps one group's detail from filling agent context.
_MEMBER_SAMPLE = 50


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
        limit: Page size — an integer from 1 to 1000 (default 50). Avoids
            flooding agent context on large estates. ``0`` and negatives are
            rejected, not read as "everything".
        offset: Number of matched groups to skip. 0 or more; pass the previous
            response's ``next_offset`` to walk the collection.

    Returns:
        The family list envelope plus ``next_offset`` — the offset of the next
        page, or ``None`` when this page ends the collection. Stop a paging
        loop on ``next_offset is None``, never on ``truncated``: ``truncated``
        says this page is not the whole collection, which stays true on the
        last page of a paged walk.

        ``items`` holds group summary dicts with
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
    validate_page_args(limit, offset)
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
    return page_envelope(rows, limit=limit, offset=offset, total=total)


def get_group(client: NsxClient, group_id: str) -> dict:
    """Get details of a security group including its membership criteria.

    Args:
        client: Authenticated NsxClient instance.
        group_id: Group identifier (e.g. 'web-tier-vms').

    Returns:
        Group detail dict with id, display_name and expression rules.
        ``member_count`` is the group's real size; ``members`` is the family
        envelope around a sample of at most ``_MEMBER_SAMPLE`` of them, so a
        withheld remainder is stated rather than left to be inferred.
    """
    _validate_id(group_id, "group_id")
    g = client.get(f"{_GROUPS_BASE}/{group_id}")

    # A group's members are who the DFW rules naming it reach — unless the
    # group, or the member, is on the DFW exclusion list, in which case the
    # rules reach nobody. Reporting membership without that is reporting
    # protection that does not exist.
    index = exclusion_index(client)

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
        fetched = member_data.get("results", []) or []
        # Size the group BEFORE sampling it. Counting the sample reported 50
        # for a 500-member group — not a missing total but a wrong one, and a
        # plausible-looking one, so nothing about the answer invited a second
        # look. The wire's ListResult carries the collection's real size, and
        # the page just fetched already holds it (the ``total_sink`` idea in
        # vmware_nsx/connection.py, without the round trip ``get_count``
        # would add). Builds that omit the field leave the fetched page
        # length as the honest stand-in — still measured before the slice.
        wire_count = member_data.get("result_count")
        member_count = wire_count if isinstance(wire_count, int) else len(fetched)
        members = [
            {
                # RealizedVirtualMachine (the type this endpoint returns) has no
                # ``external_id`` — that field belongs to the Manager API's
                # VirtualMachine. Reading it alone produced an empty id for every
                # member on NSX 9.x; ``id`` is the documented identity here.
                "id": sanitize(m.get("external_id") or m.get("id", "")),
                "display_name": sanitize(m.get("display_name", "")),
                "type": "VirtualMachine",
                "dfw_excluded": index.covers(m.get("display_name"), m.get("id")),
            }
            for m in fetched[:_MEMBER_SAMPLE]
        ]
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
        "members": paginated(members, limit=_MEMBER_SAMPLE, total=member_count),
        "dfw_excluded": _group_excluded(g, index),
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
            f"Cannot delete group '{group_id}': the group-associations check "
            "failed, so it may still be in use. Verify NSX connectivity (run "
            f"'vmware-nsx-security doctor') and retry. Detail: {exc}"
        ) from exc

    if associations:
        refs = [
            f"{sanitize(a.get('target_type', 'Unknown'))}:"
            f"{sanitize(a.get('target_display_name') or a.get('path', 'unknown'))}"
            for a in associations
        ]
        # The reference list comes from NSX and is unbounded: six references at
        # ~40 characters each pushed this message to 574, so ``sanitize``'s
        # 300-char cap deleted the closing "and retry" *and* the whole list the
        # remedy pointed at ("each SecurityPolicy below"). Bound the list, and
        # put every interpolation after the remedy so overflow costs context
        # rather than the instruction.
        shown = ", ".join(refs[:3])
        more = f" (+{len(refs) - 3} more)" if len(refs) > 3 else ""
        raise ValueError(
            f"Cannot delete this security group: {len(refs)} entity/entities "
            "still reference it. Run list_dfw_rules on each referencing "
            "SecurityPolicy, then use update_dfw_rule to drop the group from "
            "that rule's sources or destinations (or delete_dfw_rule), and "
            f"retry. Group: '{group_id}'. Referenced by: {shown}{more}"
        )

    client.delete(f"{_GROUPS_BASE}/{group_id}")
    _log.info("Deleted security group: %s", group_id)
    return {"status": "deleted", "message": f"Security group '{group_id}' deleted."}


def _group_excluded(group: dict, index: ExclusionIndex) -> bool | None:
    """Whether this group itself sits on the DFW exclusion list.

    ``None`` when the list could not be read. A group that is not on the list
    can still hold members excluded through another group, which is why the
    members carry their own flag rather than inheriting this one.
    """
    if index.error and not index.group_paths:
        return None
    return group.get("path") in index.group_paths
