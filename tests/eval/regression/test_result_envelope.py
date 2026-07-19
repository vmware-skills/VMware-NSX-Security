"""List tools state their own completeness instead of leaving it inferred.

Source: VMware-AIops issue #31. Running the family against a local Llama 3.3
70B, the operator reported that "with long tool responses, it may omit existing
information or incorrectly state that no data was returned." A bare
``list[dict]`` gives a model no way to tell a whole answer from page one, so it
guesses — and a guess that reads "no data" looks like a finding.

The four read list tools here return the family envelope. What this file
mostly pins is the honesty of ``total``: NSX's ``get_all`` drains the cursor
but stops at a 1000-item safety cap and never surfaces the wire's
``result_count``, so a total is reported only where the scan proved one. A
capped scan, a Search-API-resolved filter, and the deliberately bounded rule
fetch all report ``total: None`` rather than passing off a fetch length as the
collection size.
"""

from __future__ import annotations

import importlib

import pytest
from unittest.mock import MagicMock

from vmware_nsx_security.connection import _MAX_ITEMS
from vmware_nsx_security.ops.dfw_policy import (
    delete_dfw_policy,
    list_dfw_policies,
    list_dfw_rules,
)
from vmware_nsx_security.ops.idps import list_idps_profiles
from vmware_nsx_security.ops.security_group import list_groups

ENVELOPE_KEYS = {"items", "returned", "limit", "total", "truncated", "hint"}

# The three collection list ops share a name_filter / limit / offset contract.
COLLECTION_OPS = [
    ("vmware_nsx_security.ops.dfw_policy", "list_dfw_policies"),
    ("vmware_nsx_security.ops.security_group", "list_groups"),
    ("vmware_nsx_security.ops.idps", "list_idps_profiles"),
]


def _mock_client() -> MagicMock:
    client = MagicMock()
    client.get.return_value = {}
    client.get_all.return_value = []
    return client


def _items(n: int, prefix: str = "item") -> list[dict]:
    return [{"id": f"{prefix}-{i}", "display_name": f"{prefix}-{i}"} for i in range(n)]


def _op(import_path: str, fn_name: str):
    return getattr(importlib.import_module(import_path), fn_name)


# ---------------------------------------------------------------------------
# Shape — the six keys are the contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("import_path", "fn_name"), COLLECTION_OPS)
def test_every_envelope_key_is_present(import_path, fn_name) -> None:
    """Explicit nulls, never missing keys — a missing key invites invention."""
    client = _mock_client()
    client.get_all.return_value = _items(3)
    assert ENVELOPE_KEYS <= set(_op(import_path, fn_name)(client))


def test_list_dfw_rules_carries_every_envelope_key() -> None:
    client = _mock_client()
    client.get_all.return_value = _items(3, "rule")
    assert ENVELOPE_KEYS <= set(list_dfw_rules(client, "app-policy"))


@pytest.mark.parametrize(("import_path", "fn_name"), COLLECTION_OPS)
def test_empty_collection_is_an_explicit_zero(import_path, fn_name) -> None:
    """"No groups exist" must not read the same as "the call failed"."""
    client = _mock_client()
    client.get_all.return_value = []
    result = _op(import_path, fn_name)(client)
    assert result["items"] == []
    assert result["returned"] == 0
    assert result["total"] == 0
    assert result["truncated"] is False


# ---------------------------------------------------------------------------
# Truncation — a full page says so, a short page says it is complete
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("import_path", "fn_name"), COLLECTION_OPS)
def test_full_page_is_flagged_truncated_with_a_hint(import_path, fn_name) -> None:
    """200 objects behind a limit of 50 — the agent must be told 150 remain."""
    client = _mock_client()
    client.get_all.return_value = _items(200)
    result = _op(import_path, fn_name)(client, limit=50)
    assert result["returned"] == 50
    assert result["total"] == 200
    assert result["truncated"] is True
    assert result["hint"] and "200" in result["hint"]


@pytest.mark.parametrize(("import_path", "fn_name"), COLLECTION_OPS)
def test_short_page_is_complete_with_no_hint(import_path, fn_name) -> None:
    client = _mock_client()
    client.get_all.return_value = _items(3)
    result = _op(import_path, fn_name)(client, limit=50)
    assert result["returned"] == 3
    assert result["total"] == 3
    assert result["truncated"] is False
    assert result["hint"] is None


@pytest.mark.parametrize(("import_path", "fn_name"), COLLECTION_OPS)
def test_page_exactly_filling_a_known_total_is_not_truncated(
    import_path, fn_name
) -> None:
    """A known total is what lets a full page be recognised as complete."""
    client = _mock_client()
    client.get_all.return_value = _items(50)
    result = _op(import_path, fn_name)(client, limit=50)
    assert result["returned"] == 50
    assert result["total"] == 50
    assert result["truncated"] is False


# ---------------------------------------------------------------------------
# ``total`` is stated only where the scan proved it — never estimated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("import_path", "fn_name"), COLLECTION_OPS)
def test_capped_scan_reports_no_total(import_path, fn_name) -> None:
    """A scan that stopped at the safety cap proves nothing about the size.

    ``get_all`` returns exactly ``_MAX_ITEMS`` rows here, which is
    indistinguishable from an estate holding ten times that. Reporting 1000
    as the total would read as fact; ``None`` reads as "not known", and
    ``truncated`` still warns that more may exist.
    """
    client = _mock_client()
    client.get_all.return_value = _items(_MAX_ITEMS)
    result = _op(import_path, fn_name)(client, limit=50)
    assert result["total"] is None
    assert result["truncated"] is True
    assert "may be more" in result["hint"].lower()


def test_name_filtered_listing_reports_no_total() -> None:
    """A Search-API-resolved filter returns matches only, not a countable set.

    ``search_by_name`` hands back the matches it found; the raw hit count it
    scanned is not visible here, so no total can be proved.
    """
    client = _mock_client()
    client.get_all.return_value = _items(3, "web")
    for fn in (list_dfw_policies, list_groups):
        result = fn(client, name_filter="web")
        assert result["total"] is None, fn.__name__


def test_idps_name_filter_reports_no_total() -> None:
    """IDPS filters client-side, but the cap check happens on the raw fetch.

    A filter can shrink a capped scan below the cap; measuring after it would
    turn "unknown" into a confident lie, so a filtered listing states none.
    """
    client = _mock_client()
    client.get_all.return_value = _items(3, "web")
    assert list_idps_profiles(client, name_filter="web")["total"] is None


def test_list_dfw_rules_never_reports_a_total() -> None:
    """The rule fetch is bounded to the window, so the rule count is unknown.

    ``list_dfw_rules`` deliberately asks for only ``offset + limit`` rules so a
    thousand-rule Application policy cannot drain agent context. That means the
    real count was never retrieved — and must not be guessed from what came
    back.
    """
    client = _mock_client()
    client.get_all.return_value = _items(200, "rule")
    result = list_dfw_rules(client, "app-policy", limit=50)
    assert result["total"] is None
    assert result["returned"] == 50
    assert result["truncated"] is True
    assert "may be more" in result["hint"].lower()


def test_list_dfw_rules_short_page_is_complete() -> None:
    client = _mock_client()
    client.get_all.return_value = _items(4, "rule")
    result = list_dfw_rules(client, "app-policy", limit=50)
    assert result["returned"] == 4
    assert result["truncated"] is False
    assert result["hint"] is None


# ---------------------------------------------------------------------------
# Internal callers must read ``items``, not the envelope's truthiness
# ---------------------------------------------------------------------------


def test_empty_rule_probe_does_not_block_policy_delete() -> None:
    """An empty envelope is still a truthy dict — the probe must read ``items``.

    ``delete_dfw_policy`` refuses when the policy still holds rules, and it
    decides that from a ``limit=1`` probe. Testing the probe's *result* rather
    than its ``items`` makes every delete fail with "it still contains
    firewall rule(s)", because ``{...}`` is always truthy — including when the
    policy is empty. The suite previously covered only the has-rules branch,
    so this pins the branch that would silently invert.
    """
    client = _mock_client()
    client.get_all.return_value = []

    result = delete_dfw_policy(client, "empty-policy")

    assert result["status"] == "deleted"
    client.delete.assert_called_once()
