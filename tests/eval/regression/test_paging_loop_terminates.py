"""A paging loop over the list tools must stop, and must see every row once.

Real-hardware finding, 2026-08-30. Four tools here take an ``offset``, so an
agent can walk a collection a page at a time — but nothing in the response says
when to stop. The envelope's ``truncated`` was the only candidate, and under a
known ``total`` it is computed as ``returned < total``: on the *last* page of a
ten-row collection read three at a time, ``returned`` is 1 and ``total`` is 10,
so it reports ``true`` for ever. A loop driven by it never terminates, and the
page past the end (``returned == 0``) reports ``true`` as well.

``truncated`` was never a next-page signal. It answers "is ``items`` the whole
collection?", and on page three of three the honest answer is still no — that
page holds one row out of ten. Making it ``false`` there would trade a loop that
does not stop for the failure the envelope exists to prevent (VMware-AIops issue
 #31: a page reported as the complete answer).

So the termination signal is a separate key, ``next_offset``: the value to pass
back as ``offset``, or ``None`` when this page ends the collection. These tests
drive each tool by its own ``next_offset`` until it says stop.

The collection sizes here are deliberately *not* multiples of the page size.
A partial last page is where the arithmetic goes wrong; ten rows read three at
a time gives pages of 3/3/3/1, and it is the 1 that the old rule mis-reported.
"""

from __future__ import annotations

import importlib

import pytest
from unittest.mock import MagicMock

from vmware_nsx_security.ops._paginate import MAX_LIMIT, paginate

# The three collection list ops share the name_filter / limit / offset contract.
COLLECTION_OPS = [
    ("vmware_nsx_security.ops.dfw_policy", "list_dfw_policies"),
    ("vmware_nsx_security.ops.security_group", "list_groups"),
    ("vmware_nsx_security.ops.idps", "list_idps_profiles"),
]

ALL_LIST_OPS = COLLECTION_OPS + [
    ("vmware_nsx_security.ops.dfw_policy", "list_dfw_rules"),
]


def _op(import_path: str, fn_name: str):
    return getattr(importlib.import_module(import_path), fn_name)


def _rows(n: int) -> list[dict]:
    return [{"id": f"item-{i}", "display_name": f"item-{i}"} for i in range(n)]


def _client(rows: list[dict]) -> MagicMock:
    """A client whose ``get_all`` honours the ``limit`` its caller passes.

    ``list_dfw_rules`` bounds its fetch to ``offset + limit`` and trusts the
    client to respect it. A mock that ignores ``limit`` hands back the whole
    collection every time, which hides any error in that bound — the fetch
    would look correct because the slice afterwards cleaned up after it.
    """
    client = MagicMock()
    client.get.return_value = {}
    client.get_all.side_effect = lambda *a, limit=None, **kw: (
        list(rows) if limit is None else list(rows)[:limit]
    )
    return client


def _call(fn, fn_name, client, **kwargs):
    if fn_name == "list_dfw_rules":
        return fn(client, "app-policy", **kwargs)
    return fn(client, **kwargs)


def _walk(fn, fn_name, client, page_size: int, max_calls: int = 20):
    """Follow the tool's own ``next_offset`` until it stops. Returns ids+calls.

    ``max_calls`` is the guard that turns "never terminates" into a failed
    assertion rather than a hung test run.
    """
    seen: list[str] = []
    offset = 0
    calls = 0
    while True:
        calls += 1
        assert calls <= max_calls, (
            f"{fn_name} paging did not terminate within {max_calls} calls "
            f"(page_size={page_size}, last offset={offset})"
        )
        page = _call(fn, fn_name, client, limit=page_size, offset=offset)
        assert "next_offset" in page, (
            f"{fn_name} returned no next_offset — an agent has nothing to page by"
        )
        seen.extend(row["id"] for row in page["items"])
        nxt = page["next_offset"]
        if nxt is None:
            return seen, calls
        assert isinstance(nxt, int) and nxt > offset, (
            f"{fn_name} next_offset {nxt!r} does not advance past {offset}"
        )
        offset = nxt


# ---------------------------------------------------------------------------
# The load-bearing test: the loop stops, and sees every row exactly once
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("import_path", "fn_name"), ALL_LIST_OPS)
def test_paging_loop_terminates_and_sees_every_row_once(import_path, fn_name) -> None:
    fn = _op(import_path, fn_name)
    rows = _rows(10)  # 10 is not a multiple of 3 — the last page is partial
    seen, calls = _walk(fn, fn_name, _client(rows), page_size=3)

    assert seen == [r["id"] for r in rows], (
        f"{fn_name} paging lost, duplicated or reordered rows: {seen}"
    )
    assert calls == 4, f"{fn_name} took {calls} calls to read 10 rows in pages of 3"


@pytest.mark.parametrize(("import_path", "fn_name"), ALL_LIST_OPS)
def test_last_partial_page_ends_the_walk(import_path, fn_name) -> None:
    """offset 9 of 10 rows returns one row and no next page."""
    fn = _op(import_path, fn_name)
    page = _call(fn, fn_name, _client(_rows(10)), limit=3, offset=9)
    assert page["returned"] == 1
    assert page["next_offset"] is None, (
        "the page that reaches the end must not point at another one"
    )


@pytest.mark.parametrize(("import_path", "fn_name"), ALL_LIST_OPS)
def test_exactly_full_last_page_ends_the_walk(import_path, fn_name) -> None:
    """The boundary case: the collection *is* a multiple of the page size.

    Nine rows in pages of three ends on a full page. With a known total the
    walk must still stop; without one, one extra empty call is the honest
    cost of not knowing, and it must be the last.
    """
    fn = _op(import_path, fn_name)
    seen, calls = _walk(fn, fn_name, _client(_rows(9)), page_size=3)
    assert seen == [f"item-{i}" for i in range(9)]
    assert calls <= 4, f"{fn_name} made {calls} calls for 9 rows in pages of 3"


# ---------------------------------------------------------------------------
# Controls — a tool that always says "stop" would pass the tests above
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("import_path", "fn_name"), ALL_LIST_OPS)
def test_a_short_collection_needs_no_second_call(import_path, fn_name) -> None:
    """Two rows under a limit of fifty is the whole answer, stated as such."""
    fn = _op(import_path, fn_name)
    page = _call(fn, fn_name, _client(_rows(2)), limit=50, offset=0)
    assert page["returned"] == 2
    assert page["truncated"] is False
    assert page["next_offset"] is None


@pytest.mark.parametrize(("import_path", "fn_name"), COLLECTION_OPS)
def test_a_partial_first_page_still_reports_truncated(import_path, fn_name) -> None:
    """The control against "return truncated: false and next_offset: None".

    That would terminate every loop and pass every test above while telling an
    agent three rows are all ten. ``truncated`` keeps its family meaning —
    ``items`` is not the whole collection — and stays true here.
    """
    fn = _op(import_path, fn_name)
    page = _call(fn, fn_name, _client(_rows(10)), limit=3, offset=0)
    assert page["truncated"] is True
    assert page["total"] == 10
    assert page["next_offset"] == 3


@pytest.mark.parametrize(("import_path", "fn_name"), COLLECTION_OPS)
def test_truncated_stays_true_on_the_last_page(import_path, fn_name) -> None:
    """Pinning the decision, so it is not quietly reversed later.

    The last page holds one row of ten, so ``truncated`` is true there — and
    that is exactly why it cannot be the loop's stop signal. ``next_offset``
    is, and it is None.
    """
    fn = _op(import_path, fn_name)
    page = _call(fn, fn_name, _client(_rows(10)), limit=3, offset=9)
    assert page["truncated"] is True
    assert page["next_offset"] is None


@pytest.mark.parametrize(("import_path", "fn_name"), ALL_LIST_OPS)
def test_offset_past_the_end_is_empty_and_final(import_path, fn_name) -> None:
    fn = _op(import_path, fn_name)
    page = _call(fn, fn_name, _client(_rows(10)), limit=3, offset=30)
    assert page["items"] == []
    assert page["next_offset"] is None


# ---------------------------------------------------------------------------
# limit=0 and negative limit — rejected, never silently reinterpreted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("import_path", "fn_name"), ALL_LIST_OPS)
@pytest.mark.parametrize("bad_limit", [0, -1, -50, MAX_LIMIT + 1])
def test_out_of_range_limit_is_rejected(import_path, fn_name, bad_limit) -> None:
    """A limit outside 1..MAX_LIMIT raises rather than guessing what was meant.

    ``0`` has meant "unlimited", "none", "the default" and "an error" in
    different tools of this family; here it means none of them. A negative
    limit is worse than ambiguous — ``items[offset:offset + limit]`` is legal
    Python that quietly drops rows off the end of the page.
    """
    fn = _op(import_path, fn_name)
    with pytest.raises(ValueError, match="limit"):
        _call(fn, fn_name, _client(_rows(10)), limit=bad_limit, offset=0)


@pytest.mark.parametrize(("import_path", "fn_name"), ALL_LIST_OPS)
def test_negative_offset_is_rejected(import_path, fn_name) -> None:
    """Clamping -5 to 0 answers a question the caller did not ask."""
    fn = _op(import_path, fn_name)
    with pytest.raises(ValueError, match="offset"):
        _call(fn, fn_name, _client(_rows(10)), limit=3, offset=-5)


def test_paginate_itself_never_reaches_python_negative_slicing() -> None:
    """The helper's own guard, tested directly rather than through a caller.

    ``validate_page_args`` now rejects a negative limit before ``paginate``
    can see one, so every test that goes through a list op passes whether this
    guard is intact or not — mutating it away survived the whole suite. It is
    the last thing standing between ``items[0:-1]`` and a page that quietly
    lost its final row, which is the shape the family-wide audit found at 26
    call sites, so it is worth a test that can actually fail.
    """
    rows = _rows(10)
    for bad_limit in (-1, -3, -9):
        window = paginate(rows, bad_limit, 0)
        # rows[0:-1] is nine rows, and nine rows is what a fallthrough returns.
        # Comparing against it is the assertion that fails when the guard goes;
        # `== []` alone would also be satisfied by limit=0, which slices to []
        # legitimately and so proves nothing about the negative case.
        assert window != rows[0:bad_limit], (
            f"limit={bad_limit} fell through to Python negative slicing"
        )
        assert window == [], f"limit={bad_limit} produced a page: {window}"
    assert paginate(rows, 0, 0) == []


def test_the_rejection_says_what_to_pass_instead() -> None:
    """Teaching error, not just a refusal (family error-message rule)."""
    fn = _op("vmware_nsx_security.ops.security_group", "list_groups")
    with pytest.raises(ValueError) as exc:
        fn(_client(_rows(10)), limit=0)
    message = str(exc.value)
    assert "1" in message and str(MAX_LIMIT) in message
    assert "offset" in message, "tell the caller how to reach the rest"
