"""Server-side name search via the NSX Policy Search API.

The Policy collection endpoints (groups, security-policies) do NOT accept a
``display_name`` query parameter, so a purely client-side name filter over
``get_all`` can silently MISS a match ranked past the ``get_all`` safety cap
on a large estate — a wrong-answer bug, not merely a slow one. The Policy
Search API (``GET /policy/api/v1/search/query``) filters server-side across
the whole inventory, so matches beyond the cap are still found.

We query the Search API for a *superset* of what ``filter_by_name`` matches,
then re-apply ``filter_by_name`` locally so the substring / glob /
case-insensitive semantics stay identical to the non-search path. If the
Search API is unavailable, we fall back to a bounded collection scan and
refuse to report a truncated empty result as "not found".
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from vmware_policy import sanitize

from vmware_nsx_security.connection import NsxApiError
from vmware_nsx_security.ops._paginate import filter_by_name

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.search")

_SEARCH_PATH = "/policy/api/v1/search/query"

# Cap for search / fallback collection scans. Matches the connection-layer
# backstop; a name search rarely gets close since it is already narrowed
# server-side.
_SEARCH_CAP = 1000


def _search_wildcard(name_filter: str) -> str:
    """Build a superset wildcard term for the Policy Search API.

    ``filter_by_name`` matches on substring OR fnmatch glob, so the search
    term must be a *superset* (it must never miss a match) — the caller then
    re-applies ``filter_by_name`` locally for exact semantics. Wrapping the
    filter in ``*`` guarantees the substring case is covered; any existing
    ``*`` / ``?`` glob wildcards are preserved (NSX search honours both).
    """
    term = name_filter
    if not term.startswith("*"):
        term = "*" + term
    if not term.endswith("*"):
        term = term + "*"
    return term


def search_by_name(
    client: NsxClient,
    resource_type: str,
    collection_path: str,
    name_filter: str,
    cap: int = _SEARCH_CAP,
) -> list[dict]:
    """Return ``resource_type`` objects whose display_name matches the filter.

    Queries the Policy Search API server-side (finding matches beyond the
    ``get_all`` cap), then re-applies ``filter_by_name`` so substring / glob /
    case semantics exactly match the non-search path.

    Args:
        client: Authenticated NsxClient instance.
        resource_type: NSX Policy resource_type (e.g. ``Group``,
            ``SecurityPolicy``).
        collection_path: Collection endpoint used for the fallback scan.
        name_filter: The user's name filter (substring or glob).
        cap: Max objects to collect before stopping.

    Returns:
        Matching objects (already narrowed by ``filter_by_name``).

    Raises:
        NsxApiError: If the Search API is unavailable *and* the fallback scan
            found no match but hit the ``cap`` — the match may exist beyond
            the cap, so we refuse to report a silent empty "not found".
    """
    safe = sanitize(name_filter, max_len=200)
    query = f"resource_type:{resource_type} AND display_name:{_search_wildcard(safe)}"
    try:
        results = client.get_all(_SEARCH_PATH, params={"query": query}, limit=cap)
        return filter_by_name(results, name_filter)
    except NsxApiError as exc:
        _log.warning(
            "Search API query for %s '%s' failed (%s); falling back to a "
            "client-side scan of %s.",
            resource_type,
            name_filter,
            exc,
            collection_path,
        )
        items = client.get_all(collection_path, limit=cap)
        matched = filter_by_name(items, name_filter)
        if not matched and len(items) >= cap:
            raise NsxApiError(
                f"Name search for '{name_filter}' scanned the first {cap} "
                f"{resource_type} objects without a match, and the collection "
                f"hit the {cap}-item cap — a match may exist beyond it. The "
                "Policy Search API (which searches server-side) was "
                "unavailable, so this is NOT a confirmed 'not found'. Narrow "
                "the filter or query NSX Search directly and retry."
            ) from exc
        return matched
