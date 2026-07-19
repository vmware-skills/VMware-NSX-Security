"""Shared name-filter + limit/offset helpers for list ops.

Enforces the family "default limit=50, support filter" rule so list ops
don't flood agent context on large estates. The connection layer's
``get_all`` safety cap stays intact; this trims the result before it is
returned to the caller.
"""

from __future__ import annotations

import fnmatch

from vmware_nsx_security.connection import _MAX_ITEMS

DEFAULT_LIMIT = 50


def filter_by_name(items: list[dict], name_filter: str | None) -> list[dict]:
    """Narrow ``items`` to those whose ``display_name`` matches ``name_filter``.

    Matching is case-insensitive and supports both substring and glob
    (``*``/``?``) patterns. A None/empty filter returns ``items`` unchanged.
    """
    if not name_filter:
        return items
    needle = name_filter.lower()
    matched: list[dict] = []
    for item in items:
        name = str(item.get("display_name", "")).lower()
        if needle in name or fnmatch.fnmatch(name, needle):
            matched.append(item)
    return matched


def known_total(fetched: list[dict]) -> int | None:
    """The collection's real size, or ``None`` when the scan cannot prove one.

    ``get_all`` drains the NSX cursor but stops at a safety cap, and it does
    not surface the wire's ``result_count``. A scan that came back *under* the
    cap therefore consumed every page, so its length is the true size. One
    that stopped *at* the cap proves nothing about what sits behind it, and an
    invented total is worse than no total — the envelope's ``None`` says "not
    known", while a wrong number reads as fact.

    Pass the raw fetch, before any client-side name filtering: a filter can
    shrink a capped scan below the cap and turn "unknown" into a confident lie.
    """
    return len(fetched) if len(fetched) < _MAX_ITEMS else None


def paginate(items: list[dict], limit: int, offset: int) -> list[dict]:
    """Return the ``limit``-sized window of ``items`` starting at ``offset``.

    Negative offsets are clamped to 0; a non-positive limit yields an empty
    list.
    """
    start = max(offset, 0)
    if limit <= 0:
        return []
    return items[start : start + limit]
