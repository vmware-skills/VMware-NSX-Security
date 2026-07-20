"""DFW policy CRUD operations.

Covers NSX Distributed Firewall security policies via the Policy API:
  GET/PUT/PATCH/DELETE /policy/api/v1/infra/domains/default/security-policies/...
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

_log = logging.getLogger("vmware-nsx-security.dfw_policy")

_DFW_BASE = "/policy/api/v1/infra/domains/default/security-policies"

# DFW evaluation order: Ethernet → Emergency → Infrastructure →
# Environment → Application
_VALID_CATEGORIES = {"Ethernet", "Emergency", "Infrastructure", "Environment", "Application"}


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
        limit: Max policies to return (default 50). Avoids flooding
            agent context on large estates.
        offset: Number of matched policies to skip (pagination).

    Returns:
        The family list envelope; ``items`` holds policy summary dicts with
        id, display_name, category, sequence_number, and rule count.
        ``total`` is the real policy count on the unfiltered path when the
        scan stayed under the ``get_all`` cap, and ``None`` otherwise —
        ``search_by_name`` returns only its matches, so a filtered listing
        has no trustworthy total to report.

    Note:
        A ``name_filter`` is resolved server-side via the Policy Search API
        so a match ranked past the ``get_all`` safety cap on a large estate
        is still found — a plain client-side filter would silently miss it.
    """
    if name_filter:
        items = search_by_name(client, "SecurityPolicy", _DFW_BASE, name_filter)
        total = None
    else:
        items = client.get_all(_DFW_BASE)
        total = known_total(items)
    rows = [
        {
            "id": sanitize(p.get("id", "")),
            "display_name": sanitize(p.get("display_name", "")),
            "category": sanitize(p.get("category", "")),
            "sequence_number": p.get("sequence_number", 0),
            "stateful": p.get("stateful", True),
            "tcp_strict": p.get("tcp_strict", False),
            "rule_count": p.get("rule_count", 0),
            "path": sanitize(p.get("path", "")),
        }
        for p in paginate(items, limit, offset)
    ]
    return paginated(rows, limit=limit, total=total)


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
        limit: Max rules to return (default 50). Large Application policies
            can hold hundreds-to-thousands of rules, so the fetch is bounded
            server-side rather than draining every rule into agent context.
        offset: Number of rules to skip (pagination).

    Returns:
        The family list envelope; ``items`` holds rule summary dicts with id,
        display_name, action, sources, destinations, services, scope, and
        hit-count fields. ``total`` is always ``None`` here: the fetch is
        deliberately bounded to the requested window, so the rule count behind
        it was never retrieved and must not be guessed. A full page therefore
        reports ``truncated: true`` — page with ``offset`` to confirm.
    """
    _validate_id(policy_id, "policy_id")
    # Fetch only up to the requested window (offset + limit) rather than the
    # whole rule set; a non-positive limit yields an empty window (paginate
    # returns []), so bound the fetch to 1 instead of the default backstop.
    fetch_cap = offset + limit if limit > 0 else 1
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
    return paginated(rows, limit=limit)
