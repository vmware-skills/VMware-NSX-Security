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

#: Largest page a caller may ask for. Matches the connection layer's own
#: ``get_all`` backstop: a limit above it could never be satisfied anyway, so
#: accepting one would promise a page size this client cannot deliver.
MAX_LIMIT = _MAX_ITEMS


def validate_page_args(limit: int, offset: int) -> None:
    """Reject a page window that cannot mean what it says.

    ``limit`` is a page size: an integer from 1 to :data:`MAX_LIMIT`. It is
    never a synonym for "unlimited", "none" or "the default" — across this
    family ``limit=0`` had picked up all four readings, so a caller passing it
    could not know which tool did what. Here it is simply out of range.

    A *negative* limit is worse than ambiguous. ``items[offset:offset + limit]``
    is legal Python that quietly returns a shorter page than asked for, so the
    caller is handed a truncated answer with no indication anything was
    dropped.

    ``offset`` is a count of rows to skip: an integer from 0 up. A negative
    offset used to be clamped to 0, which answers a different question from
    the one asked and says nothing about the substitution.

    Raises:
        ValueError: If either value is outside its range. The message names
            the accepted range and points at ``offset`` for reaching the rest,
            since "limit too large" and "I need more rows" arrive together.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > MAX_LIMIT:
        raise ValueError(
            f"Invalid limit {limit!r}: it is a page size and must be an "
            f"integer from 1 to {MAX_LIMIT}. It is not a way to ask for "
            f"everything — 0 and negatives are rejected rather than guessed "
            f"at. To read more than one page, keep limit within range and "
            f"pass the response's 'next_offset' back as 'offset' until it is "
            f"null."
        )
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError(
            f"Invalid offset {offset!r}: it is the number of rows to skip and "
            f"must be an integer of 0 or more. Start at 0 and pass the "
            f"response's 'next_offset' back as 'offset' for each following "
            f"page, stopping when it is null."
        )


def next_offset(returned: int, limit: int, offset: int, total: int | None) -> int | None:
    """The ``offset`` for the next page, or ``None`` when this page is the last.

    This — not ``truncated`` — is what a paging loop terminates on. The
    envelope's ``truncated`` answers "is ``items`` the whole collection?", so
    on the last page of a paged walk it is still true: that page holds three
    rows of ten. Reading it as "there is more to fetch" is what makes a loop
    run for ever.

    With a ``total`` the answer is exact: there is a next page when rows remain
    behind the window this one consumed. Without one, a page filled exactly to
    the limit cannot be told apart from a page that was cut short, so it is
    reported as having a successor. The cost of being wrong is one more call
    that returns nothing and ends the walk; the cost of the opposite is rows
    the caller never learns exist.

    Args:
        returned: Rows in this page.
        limit: The validated page size that produced it.
        offset: The validated offset this page started at.
        total: The collection size when it is known, else ``None``.

    Returns:
        The next offset, or ``None`` if this page ends the collection.
    """
    if returned <= 0:
        return None
    consumed = offset + returned
    if total is not None:
        return consumed if consumed < total else None
    return consumed if returned >= limit else None


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
