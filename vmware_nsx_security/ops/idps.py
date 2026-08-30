"""IDPS (Intrusion Detection and Prevention System) query operations.

NSX IDPS provides network-layer intrusion detection with optional inline
prevention mode. This module provides read-only access to IDPS profiles,
signature status, and global IDS settings.

APIs used:
  GET /policy/api/v1/infra/settings/firewall/security/intrusion-services/profiles
  GET /policy/api/v1/infra/settings/firewall/security/intrusion-services/signatures/status
  GET /policy/api/v1/infra/settings/firewall/security/intrusion-services
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from vmware_policy import paginated, sanitize

from vmware_nsx_security.ops._paginate import (
    DEFAULT_LIMIT,
    filter_by_name,
    known_total,
    next_offset,
    paginate,
    validate_page_args,
)

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.idps")

_IDPS_BASE = "/policy/api/v1/infra/settings/firewall/security/intrusion-services"


# ---------------------------------------------------------------------------
# IDPS Profiles
# ---------------------------------------------------------------------------


def list_idps_profiles(
    client: NsxClient,
    name_filter: str | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict:
    """List IDPS profiles configured in NSX.

    IDPS profiles define which signature sets and actions (detect/prevent)
    are active. Each profile can be applied to one or more DFW policies.

    Profile ``criteria`` is polymorphic: ``IdsProfileFilterCriteria`` items
    (``filter_name`` of ATTACK_TYPE / ATTACK_TARGET / CVSS /
    PRODUCT_AFFECTED with a ``filter_value`` list) interleaved with
    ``IdsProfileConjunctionOperator`` entries. Conjunction entries are
    always AND and are skipped in the parsed output.

    Args:
        client: Authenticated NsxClient instance.
        name_filter: Optional substring/glob match on display_name.
        limit: Page size — an integer from 1 to 1000 (default 50). Avoids
            flooding agent context on large estates. ``0`` and negatives are
            rejected, not read as "everything".
        offset: Number of matched profiles to skip. 0 or more; pass the
            previous response's ``next_offset`` to walk the collection.

    Returns:
        The family list envelope plus ``next_offset`` — the offset of the next
        page, or ``None`` when this page ends the collection. Stop a paging
        loop on ``next_offset is None``, never on ``truncated``: ``truncated``
        says this page is not the whole collection, which stays true on the
        last page of a paged walk.

        ``items`` holds IDPS profile summary dicts
        with id, display_name, criteria (filter_name/filter_value pairs),
        profile_severity (comma-joined), and overridden_signature_count.
        ``total`` is the real profile count on the unfiltered path when the
        scan stayed under the ``get_all`` cap, and ``None`` otherwise — the
        cap is measured on the raw fetch, before the client-side name filter,
        since a filter can shrink a capped scan and disguise the gap.
    """
    validate_page_args(limit, offset)
    fetched = client.get_all(f"{_IDPS_BASE}/profiles")
    total = None if name_filter else known_total(fetched)
    items = filter_by_name(fetched, name_filter)
    profiles: list[dict] = []
    for p in paginate(items, limit, offset):
        criteria: list[dict] = []
        for c in p.get("criteria", []):
            if c.get("resource_type") == "IdsProfileConjunctionOperator":
                continue  # implicit AND between filter criteria
            criteria.append(
                {
                    "filter_name": sanitize(c.get("filter_name", "")),
                    "filter_value": c.get("filter_value", []),
                }
            )

        # profile_severity is an ARRAY in the API (e.g. ["HIGH", "CRITICAL"])
        severity = p.get("profile_severity", [])
        if isinstance(severity, str):
            severity = [severity]

        overridden = p.get("overridden_signatures")
        overridden_count = len(overridden) if isinstance(overridden, list) else 0

        profiles.append(
            {
                "id": sanitize(p.get("id", "")),
                "display_name": sanitize(p.get("display_name", "")),
                "description": sanitize(p.get("description", "")),
                "criteria": criteria,
                "profile_severity": sanitize(",".join(severity)),
                "overridden_signature_count": overridden_count,
                "path": sanitize(p.get("path", "")),
            }
        )
    return paginated(
        profiles,
        limit=limit,
        total=total,
        next_offset=next_offset(len(profiles), limit, offset, total),
    )


# ---------------------------------------------------------------------------
# IDPS Signature Status + Settings
# ---------------------------------------------------------------------------


def get_idps_status(client: NsxClient) -> dict:
    """Get IDPS signature status and global IDS settings.

    Reads two real Policy API resources:

    * ``GET .../intrusion-services/signatures/status`` — signature bundle
      version / download / update status. Field names vary across NSX
      releases, so all scalar fields are passed through defensively
      (sanitized, stringified) rather than parsing an assumed schema.
    * ``GET .../intrusion-services`` — IdsSettings: ``auto_update``
      (automatic signature updates) and ``ids_events_to_syslog``.

    Errors are NOT swallowed here — they propagate so the MCP/CLI layer
    can surface the standard {"error", "hint"} payload.

    Args:
        client: Authenticated NsxClient instance.

    Returns:
        Dict with 'signature_status' (scalar fields of the signature
        status resource) and 'settings' (auto_update,
        ids_events_to_syslog).
    """
    sig_status_raw = client.get(f"{_IDPS_BASE}/signatures/status")
    settings_raw = client.get(_IDPS_BASE)

    # Defensive parse: keep scalar fields only, sanitized. Exact field
    # names (e.g. signature version / update state) differ across NSX
    # versions and are not all documented, so we pass them through
    # instead of inventing a fixed schema.
    signature_status = {
        k: sanitize(str(v))
        for k, v in sig_status_raw.items()
        if isinstance(v, (str, int, float, bool)) and not k.startswith("_")
    }

    return {
        "signature_status": signature_status,
        "settings": {
            "auto_update": bool(settings_raw.get("auto_update", False)),
            "ids_events_to_syslog": bool(settings_raw.get("ids_events_to_syslog", False)),
        },
    }
