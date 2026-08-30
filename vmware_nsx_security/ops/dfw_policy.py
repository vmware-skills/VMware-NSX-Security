"""DFW policy CRUD operations.

Covers NSX Distributed Firewall security policies via the Policy API:
  GET/PUT/PATCH/DELETE /policy/api/v1/infra/domains/default/security-policies/...
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from vmware_policy import sanitize

from vmware_nsx_security.ops._paginate import (
    DEFAULT_LIMIT,
    known_total,
    page_envelope,
    paginate,
    validate_page_args,
)
from vmware_nsx_security.ops._search import search_by_name
from vmware_nsx_security.ops._validate import validate_id as _validate_id
from vmware_nsx_security.ops.exclusion import policy_exclusion_note

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.dfw_policy")

_DFW_BASE = "/policy/api/v1/infra/domains/default/security-policies"

# DFW evaluation order: Ethernet → Emergency → Infrastructure →
# Environment → Application
_VALID_CATEGORIES = {"Ethernet", "Emergency", "Infrastructure", "Environment", "Application"}

# ``SecurityPolicy.rule_count`` exists but is not filled in for free: the NSX
# API reference says of this parameter that "by default, rule_count will not
# be populated". Asking rides on the listing we already make, where counting
# the rules ourselves would cost one round trip per policy (踩坑 #31).
_COUNT_PARAMS = {"include_rule_count": "true"}


def _rule_count(policy: dict) -> int | None:
    """The policy's rule count, or ``None`` when the manager reported none.

    Absent is not zero. A listing that did not ask for the count, and every
    listing resolved through the Search API, comes back without the field —
    and defaulting it to 0 turns "not answered" into "nothing enforced". That
    reading is what stops an operator going to look for the DROP rules that
    are in fact there, so the unknown has to stay visible as an unknown.
    """
    count = policy.get("rule_count")
    if isinstance(count, bool) or not isinstance(count, int):
        return None
    return count


# ---------------------------------------------------------------------------
# Policy list / get
# ---------------------------------------------------------------------------


def list_dfw_policies(
    client: NsxClient,
    name_filter: str | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict:
    """List DFW security policies in the default domain.

    Args:
        client: Authenticated NsxClient instance.
        name_filter: Optional substring/glob match on display_name.
        limit: Page size — an integer from 1 to 1000 (default 50). Avoids
            flooding agent context on large estates. ``0`` and negatives are
            rejected, not read as "everything".
        offset: Number of matched policies to skip. 0 or more; pass the
            previous response's ``next_offset`` to walk the collection.

    Returns:
        The family list envelope plus ``next_offset`` — the offset of the next
        page, or ``None`` when this page ends the collection. Stop a paging
        loop on ``next_offset is None``, never on ``truncated``: ``truncated``
        says this page is not the whole collection, which stays true on the
        last page of a paged walk.

        ``items`` holds policy summary dicts with
        id, display_name, category, sequence_number, and rule count.
        ``total`` is the real policy count on the unfiltered path when the
        scan stayed under the ``get_all`` cap, and ``None`` otherwise —
        ``search_by_name`` returns only its matches, so a filtered listing
        has no trustworthy total to report.

        ``rule_count`` is an int where NSX reported one and ``None`` where it
        did not; ``None`` means "not retrieved", never "no rules". When any
        row is ``None`` the envelope carries a ``rule_count_note`` saying so
        and pointing at ``list_dfw_rules``.

    Note:
        A ``name_filter`` is resolved server-side via the Policy Search API
        so a match ranked past the ``get_all`` safety cap on a large estate
        is still found — a plain client-side filter would silently miss it.
        The trade is the rule counts: the Search API serves indexed objects
        and takes no ``include_rule_count``, so a filtered listing reports
        every count as unknown rather than fetching each policy's rules to
        count them.
    """
    validate_page_args(limit, offset)
    if name_filter:
        items = search_by_name(client, "SecurityPolicy", _DFW_BASE, name_filter)
        total = None
    else:
        items = client.get_all(_DFW_BASE, params=dict(_COUNT_PARAMS))
        total = known_total(items)
    rows = [
        {
            "id": sanitize(p.get("id", "")),
            "display_name": sanitize(p.get("display_name", "")),
            "category": sanitize(p.get("category", "")),
            "sequence_number": p.get("sequence_number", 0),
            "stateful": p.get("stateful", True),
            "tcp_strict": p.get("tcp_strict", False),
            "rule_count": _rule_count(p),
            "path": sanitize(p.get("path", "")),
        }
        for p in paginate(items, limit, offset)
    ]
    extra: dict[str, Any] = {}
    # A correct listing of policies is what an operator reads as "the fabric is
    # segmented". It is not, for any member on the DFW exclusion list. One GET,
    # no member resolution — naming the VMs is list_dfw_exclusions's job.
    note = policy_exclusion_note(client)
    if note:
        extra["exclusion_note"] = note
    if any(row["rule_count"] is None for row in rows):
        extra["rule_count_note"] = (
            "rule_count is null for one or more policies: this NSX Manager "
            "did not report a count, and null is not zero — those policies "
            "may well be enforcing rules. Run list_dfw_rules on each such "
            "policy id to see what it holds. A name_filter always reads null: "
            "the Policy Search API that resolves it carries no rule counts."
        )
    return page_envelope(rows, limit=limit, offset=offset, total=total, **extra)


def get_dfw_policy(client: NsxClient, policy_id: str) -> dict:
    """Get details of a single DFW security policy.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Policy identifier (e.g. 'app-tier-policy').

    Returns:
        Policy detail dict including metadata and rule summary.
    """
    _validate_id(policy_id, "policy_id")
    p = client.get(f"{_DFW_BASE}/{policy_id}")
    return {
        "id": sanitize(p.get("id", "")),
        "display_name": sanitize(p.get("display_name", "")),
        "description": sanitize(p.get("description", "")),
        "category": sanitize(p.get("category", "")),
        "sequence_number": p.get("sequence_number", 0),
        "stateful": p.get("stateful", True),
        "tcp_strict": p.get("tcp_strict", False),
        "locked": p.get("locked", False),
        "scope": p.get("scope", []),
        "tags": p.get("tags", []),
        "path": sanitize(p.get("path", "")),
        "_revision": p.get("_revision"),
    }


# ---------------------------------------------------------------------------
# Policy create / update / delete
# ---------------------------------------------------------------------------


def create_dfw_policy(
    client: NsxClient,
    policy_id: str,
    display_name: str,
    category: str = "Application",
    sequence_number: int = 10,
    stateful: bool = True,
    description: str = "",
) -> dict:
    """Create a new DFW security policy via PUT.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Unique policy ID (alphanumeric + hyphens).
        display_name: Human-readable policy name.
        category: Policy category — one of Ethernet, Emergency,
            Infrastructure, Environment, Application (default: Application).
        sequence_number: Priority order (lower = higher priority).
        stateful: Whether the firewall tracks connection state (default True).
        description: Optional description string.

    Returns:
        Created policy dict as returned by the API.

    Raises:
        ValueError: If policy_id or category is invalid.
    """
    _validate_id(policy_id, "policy_id")
    if category not in _VALID_CATEGORIES:
        raise ValueError(
            "Invalid category. Must be one of: Ethernet, Emergency, "
            "Infrastructure, Environment, Application. Category sets DFW "
            "evaluation order (Ethernet first, Application last); most app "
            "rules belong in Application. Run list_dfw_policies to see which "
            f"categories this manager already uses. Got: '{category}'"
        )
    body: dict[str, Any] = {
        "display_name": sanitize(display_name),
        "category": category,
        "sequence_number": sequence_number,
        "stateful": stateful,
    }
    if description:
        body["description"] = sanitize(description)

    result = client.put(f"{_DFW_BASE}/{policy_id}", body)
    _log.info("Created DFW policy: %s (%s)", policy_id, category)
    return result


def update_dfw_policy(
    client: NsxClient,
    policy_id: str,
    display_name: str | None = None,
    description: str | None = None,
    sequence_number: int | None = None,
    stateful: bool | None = None,
) -> dict:
    """Partially update a DFW security policy via PATCH.

    Only the fields explicitly passed will be modified.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: ID of the policy to update.
        display_name: New display name (optional).
        description: New description (optional).
        sequence_number: New sequence number (optional).
        stateful: New stateful flag value (optional).

    Returns:
        Updated policy dict as returned by the API.
    """
    _validate_id(policy_id, "policy_id")
    body: dict[str, Any] = {}
    if display_name is not None:
        body["display_name"] = sanitize(display_name)
    if description is not None:
        body["description"] = sanitize(description)
    if sequence_number is not None:
        body["sequence_number"] = sequence_number
    if stateful is not None:
        body["stateful"] = stateful

    if not body:
        raise ValueError(
            f"No fields provided to update policy '{policy_id}'. This is a "
            "PATCH — specify at least one of: display_name, description, "
            "sequence_number, stateful. Run get_dfw_policy to see the "
            "policy's current values, then pass only the ones to change."
        )

    result = client.patch(f"{_DFW_BASE}/{policy_id}", body)
    _log.info("Updated DFW policy: %s", policy_id)
    return result


def delete_dfw_policy(client: NsxClient, policy_id: str) -> dict[str, str]:
    """Delete a DFW security policy after checking for active rules.

    Refuses deletion if the policy contains any rules, to prevent
    accidental removal of active security posture.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: ID of the policy to delete.

    Returns:
        Dict with 'status' and 'message' keys on success.

    Raises:
        ValueError: If the policy still contains active rules.
    """
    _validate_id(policy_id, "policy_id")
    # Existence probe only — fetch a single rule instead of draining every
    # rule of a (potentially thousands-strong) Application policy.
    # ``items`` — not the envelope itself, which is always truthy.
    if list_dfw_rules(client, policy_id, limit=1)["items"]:
        raise ValueError(
            f"Cannot delete policy '{policy_id}': it still contains firewall "
            "rule(s). Delete the rules first — run list_dfw_rules to review "
            "them, then remove each before deleting the policy."
        )

    client.delete(f"{_DFW_BASE}/{policy_id}")
    _log.info("Deleted DFW policy: %s", policy_id)
    return {"status": "deleted", "message": f"DFW policy '{policy_id}' deleted."}


# ---------------------------------------------------------------------------
# Rules list
# ---------------------------------------------------------------------------


def list_dfw_rules(
    client: NsxClient,
    policy_id: str,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict:
    """List rules under a DFW security policy.

    Args:
        client: Authenticated NsxClient instance.
        policy_id: Policy ID whose rules to list.
        limit: Page size — an integer from 1 to 1000 (default 50). Large
            Application policies can hold hundreds-to-thousands of rules, so
            the fetch is bounded server-side rather than draining every rule
            into agent context. ``0`` and negatives are rejected.
        offset: Number of rules to skip. 0 or more; pass the previous
            response's ``next_offset`` to walk the policy.

    Returns:
        The family list envelope plus ``next_offset`` — the offset of the next
        page, or ``None`` when this page ends the rule set. Stop a paging loop
        on ``next_offset is None``, never on ``truncated``.

        ``items`` holds rule summary dicts with id,
        display_name, action, sources, destinations, services, scope, and
        hit-count fields. ``total`` is always ``None`` here: the fetch is
        deliberately bounded to the requested window, so the rule count behind
        it was never retrieved and must not be guessed. A full page therefore
        reports ``truncated: true`` and carries a ``next_offset``; the walk
        ends on the first short or empty page.
    """
    _validate_id(policy_id, "policy_id")
    validate_page_args(limit, offset)
    # Fetch only up to the requested window (offset + limit) rather than the
    # whole rule set.
    fetch_cap = offset + limit
    items = client.get_all(f"{_DFW_BASE}/{policy_id}/rules", limit=fetch_cap)
    items = paginate(items, limit, offset)
    rows = [
        {
            "id": sanitize(r.get("id", "")),
            "display_name": sanitize(r.get("display_name", "")),
            "action": r.get("action", "ALLOW"),
            "sources": r.get("source_groups", []),
            "destinations": r.get("destination_groups", []),
            "services": r.get("services", []),
            "scope": r.get("scope", []),
            "direction": r.get("direction", "IN_OUT"),
            "ip_protocol": r.get("ip_protocol", "IPV4_IPV6"),
            "disabled": r.get("disabled", False),
            "logged": r.get("logged", False),
            "sequence_number": r.get("sequence_number", 0),
            "path": sanitize(r.get("path", "")),
        }
        for r in items
    ]
    return page_envelope(rows, limit=limit, offset=offset, total=None)
