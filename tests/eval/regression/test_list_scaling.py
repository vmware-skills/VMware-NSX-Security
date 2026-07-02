"""Regression evals for list scaling + the name-search correctness bug.

Before this fix, ``list_groups`` / ``list_dfw_policies`` did
``filter_by_name(client.get_all(BASE), name_filter)`` — ``get_all`` follows
the cursor only up to a 1000-item safety cap, THEN the name filter is applied
client-side. On an estate with >1000 objects, a search for an object ranked
#1001+ returned an empty list: a silent WRONG ANSWER ("not found" for
something that exists), not merely slow.

The fix routes name-filtered queries through the Policy Search API
(server-side ``display_name`` filtering), so matches beyond the cap are
found. ``list_dfw_rules`` likewise now bounds its fetch (limit/offset) instead
of draining every rule of a large Application policy.

Test (a) LOCKS IN the correctness fix: it FAILS against the old
client-side-slice behavior and PASSES after the Search-API routing.
"""

from __future__ import annotations

from typing import Any

import pytest

from vmware_nsx_security.connection import NsxApiError
from vmware_nsx_security.ops._paginate import filter_by_name
from vmware_nsx_security.ops.dfw_policy import (
    delete_dfw_policy,
    list_dfw_rules,
)
from vmware_nsx_security.ops.security_group import list_groups

_GROUPS_BASE = "/policy/api/v1/infra/domains/default/groups"
_SEARCH_PATH = "/policy/api/v1/search/query"
_CAP = 1000


class _FakeClient:
    """Minimal stand-in for NsxClient.get_all with faithful cap semantics.

    Collection paths return the dataset truncated to the effective cap (this
    reproduces the 1000-item truncation that caused the silent-miss bug).
    The Search path filters the FULL dataset server-side by the display_name
    term, so a match past the cap is still returned. Every get_all call is
    recorded for assertions.
    """

    def __init__(self, groups: list[dict] | None = None, rules: list[dict] | None = None) -> None:
        self._groups = groups or []
        self._rules = rules or []
        self.search_disabled = False
        self.calls: list[dict[str, Any]] = []

    def get_all(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        max_items: int = _CAP,
        *,
        page_size: int | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        self.calls.append({"path": path, "params": params, "limit": limit})
        cap = limit if limit is not None else max_items

        if path == _SEARCH_PATH:
            if self.search_disabled:
                raise NsxApiError("Search API unavailable", status_code=404)
            query = (params or {}).get("query", "")
            term = query.split("display_name:", 1)[1].strip().strip("*").lower()
            matched = [g for g in self._groups if term in g.get("display_name", "").lower()]
            return matched[:cap]

        if path == _GROUPS_BASE:
            return list(self._groups)[:cap]
        if path.endswith("/rules"):
            return list(self._rules)[:cap]
        return []


def _make_groups(n: int, needle_at: int, needle_name: str) -> list[dict]:
    groups = [
        {"id": f"group-{i:05d}", "display_name": f"filler-group-{i:05d}"}
        for i in range(n)
    ]
    groups[needle_at] = {"id": "needle-group", "display_name": needle_name}
    return groups


# ── (a) correctness: name search must not miss past the 1000 cap ──────────


def test_list_groups_name_search_finds_match_past_1000_cap() -> None:
    """A group ranked #1001 must still be found by name search.

    LOCK-IN: the old code sliced client-side after a 1000-item get_all, so
    this returned [] (silent "not found"). Routing through the Search API
    finds it server-side.
    """
    needle = "prod-database-tier"
    groups = _make_groups(1005, needle_at=1004, needle_name=needle)
    client = _FakeClient(groups=groups)

    # Document the bug the fix closes: the needle is NOT in the first 1000
    # objects a client-side collection scan would have seen.
    truncated = filter_by_name(client.get_all(_GROUPS_BASE), needle)
    assert truncated == [], "precondition: needle is past the get_all cap"

    result = list_groups(client, name_filter=needle)  # type: ignore[arg-type]

    assert len(result) == 1
    assert result[0]["display_name"] == needle
    # Confirm the match was resolved server-side via the Search API, not a
    # client-side slice of the (capped) collection.
    assert any(c["path"] == _SEARCH_PATH for c in client.calls)


def test_list_groups_no_filter_uses_collection_not_search() -> None:
    """Without a name filter there is nothing to search — use the collection."""
    client = _FakeClient(groups=_make_groups(3, needle_at=0, needle_name="a"))
    list_groups(client)  # type: ignore[arg-type]
    assert any(c["path"] == _GROUPS_BASE for c in client.calls)
    assert not any(c["path"] == _SEARCH_PATH for c in client.calls)


def test_name_search_never_reports_truncated_empty_as_not_found() -> None:
    """If Search is unavailable AND the fallback scan hits the cap empty,
    raise a teaching error rather than silently returning [] ('not found')."""
    # 1000 filler groups, no match; search disabled forces the fallback scan,
    # which hits the cap without a match -> must raise, not return [].
    groups = [
        {"id": f"g-{i:05d}", "display_name": f"filler-{i:05d}"} for i in range(_CAP)
    ]
    client = _FakeClient(groups=groups)
    client.search_disabled = True

    with pytest.raises(NsxApiError) as exc:
        list_groups(client, name_filter="does-not-exist-in-first-1000")  # type: ignore[arg-type]
    assert "beyond" in str(exc.value).lower()


# ── (b) list_dfw_rules bounds its fetch server-side ───────────────────────


def test_list_dfw_rules_passes_limit_server_side() -> None:
    """list_dfw_rules must bound get_all to offset+limit, not drain all rules."""
    rules = [{"id": f"rule-{i}", "display_name": f"rule-{i}"} for i in range(200)]
    client = _FakeClient(rules=rules)

    result = list_dfw_rules(client, "app-policy", limit=5, offset=10)  # type: ignore[arg-type]

    rule_calls = [c for c in client.calls if c["path"].endswith("/rules")]
    assert rule_calls, "expected a get_all on the rules endpoint"
    assert rule_calls[0]["limit"] == 15  # offset(10) + limit(5)
    assert len(result) == 5


def test_delete_dfw_policy_precheck_uses_bounded_probe() -> None:
    """The delete pre-check needs existence only — it must fetch a single
    rule, not the whole (possibly thousands-strong) rule set."""
    rules = [{"id": f"rule-{i}", "display_name": f"rule-{i}"} for i in range(500)]
    client = _FakeClient(rules=rules)

    with pytest.raises(ValueError) as exc:
        delete_dfw_policy(client, "app-policy")  # type: ignore[arg-type]

    assert "rule" in str(exc.value).lower()
    rule_calls = [c for c in client.calls if c["path"].endswith("/rules")]
    assert rule_calls[0]["limit"] == 1  # existence probe only
