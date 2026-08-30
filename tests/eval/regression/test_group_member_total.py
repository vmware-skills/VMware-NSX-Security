"""A group's member count states the group's size, not the sample's size.

``get_group`` fetches a page of effective members, keeps the first 50 so a
large group cannot drain agent context, and reports ``member_count``. That
count used to be computed *after* the slice, so a 500-member group reported
``member_count: 50``.

That is a worse failure than silent truncation. Truncation omits; this
asserted. An agent asking "is this group scoped too broadly?" was told 50 with
no signal that anything was withheld — and 50 is a plausible answer, so there
was nothing to notice. Deciding a DFW rule's blast radius from that number
means deciding it from a wrong one.

The fix is the one VMware-NSX already uses (踩坑 #21 — the fix landed in one
sibling and not the other): read the collection's real size from the wire's
``ListResult.result_count``, which the page we already fetched carries, and
report the sample through the family envelope so the withholding is stated
rather than inferred. ``vmware_nsx/connection.py`` calls this the
``total_sink`` — a count taken from pages already in hand, avoiding the extra
round trip its ``get_count`` would cost.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from vmware_nsx_security.ops.security_group import _MEMBER_SAMPLE, get_group

ENVELOPE_KEYS = {"items", "returned", "limit", "total", "truncated", "hint"}


def _client(member_page: dict) -> MagicMock:
    """A client whose members endpoint returns ``member_page``."""
    client = MagicMock()

    def _get(path, params=None):
        if path.endswith("/members/virtual-machines"):
            return member_page
        return {"id": "g1", "display_name": "G1", "expression": []}

    client.get.side_effect = _get
    return client


def _vms(n: int) -> list[dict]:
    return [{"external_id": f"vm-{i}", "display_name": f"host-{i}"} for i in range(n)]


# ---------------------------------------------------------------------------
# The defect: a count taken after the slice
# ---------------------------------------------------------------------------


def test_large_group_reports_its_real_size_not_the_sample_size() -> None:
    """500 members behind a 50-row sample must report 500."""
    result = get_group(_client({"results": _vms(500), "result_count": 500}), "g1")
    assert result["member_count"] == 500


def test_sample_is_still_capped() -> None:
    """Reporting the true total must not mean returning every member."""
    result = get_group(_client({"results": _vms(500), "result_count": 500}), "g1")
    assert result["members"]["returned"] == _MEMBER_SAMPLE
    assert len(result["members"]["items"]) == _MEMBER_SAMPLE


def test_withholding_is_stated_in_the_envelope() -> None:
    """The agent is told what it did not get, rather than left to infer it."""
    members = get_group(_client({"results": _vms(500), "result_count": 500}), "g1")["members"]
    assert ENVELOPE_KEYS <= set(members)
    assert members["total"] == 500
    assert members["truncated"] is True
    assert members["hint"] and "500" in members["hint"]


def test_member_rows_keep_their_shape_and_are_sanitized() -> None:
    """Wrapping the list must not change what a row looks like.

    ``dfw_excluded`` joined the row when the DFW exclusion list became visible:
    a member the distributed firewall does not see is not protected by the
    rules that name this group, and the row that lists the member is where that
    has to be said. ``False`` here because this fixture's exclusion list is
    empty — never absent, so an agent cannot read a missing key as "fine".
    """
    page = {
        "results": [{"external_id": "vm-1", "display_name": "web\x1b[31m-01"}],
        "result_count": 1,
    }
    row = get_group(_client(page), "g1")["members"]["items"][0]
    assert row == {
        "id": "vm-1",
        "display_name": "web[31m-01",
        "type": "VirtualMachine",
        "dfw_excluded": False,
    }


# ---------------------------------------------------------------------------
# Small groups: a complete answer must not read as a truncated one
# ---------------------------------------------------------------------------


def test_small_group_is_complete_and_says_so() -> None:
    result = get_group(_client({"results": _vms(3), "result_count": 3}), "g1")
    assert result["member_count"] == 3
    assert result["members"]["truncated"] is False
    assert result["members"]["hint"] is None


def test_group_full_to_the_sample_boundary_is_not_flagged_truncated() -> None:
    """Exactly 50 members is a complete answer — a known total proves it.

    This is the case a bare "did we fill the page?" check gets wrong, and the
    reason a real total is worth reading off the wire.
    """
    n = _MEMBER_SAMPLE
    result = get_group(_client({"results": _vms(n), "result_count": n}), "g1")
    assert result["member_count"] == n
    assert result["members"]["returned"] == n
    assert result["members"]["truncated"] is False


def test_empty_group_is_an_explicit_zero() -> None:
    """"No members" must not read the same as "the call failed"."""
    result = get_group(_client({"results": [], "result_count": 0}), "g1")
    assert result["member_count"] == 0
    assert result["members"]["items"] == []
    assert result["members"]["truncated"] is False
    assert "members_error" not in result


# ---------------------------------------------------------------------------
# Fallback and failure — the count must never be invented
# ---------------------------------------------------------------------------


def test_total_comes_from_the_wire_not_from_the_page_length() -> None:
    """A member collection can span pages: 100 fetched, 500 in the group.

    This is what makes reading ``result_count`` worth doing rather than just
    moving the ``len()`` above the slice. Sizing the group from the page in
    hand would report 100 — better than the 50 this bug produced, and still
    wrong. Only the wire's own count is the group's size.
    """
    result = get_group(_client({"results": _vms(100), "result_count": 500}), "g1")
    assert result["member_count"] == 500
    assert result["members"]["total"] == 500
    assert result["members"]["truncated"] is True


def test_total_falls_back_to_the_fetched_page_when_the_api_omits_result_count() -> None:
    """Older/odd builds omit ``result_count``; the page length is the honest
    stand-in, and it is measured before the slice, not after it."""
    result = get_group(_client({"results": _vms(120)}), "g1")
    assert result["member_count"] == 120
    assert result["members"]["returned"] == _MEMBER_SAMPLE
    assert result["members"]["truncated"] is True


def test_a_failed_member_fetch_still_reports_unknown_not_zero() -> None:
    """The pre-existing "could not check" contract survives the envelope.

    ``member_count is None`` is the signal that the number is unavailable; an
    envelope reporting a confident ``total: 0`` in its place would reintroduce
    exactly the failure-as-empty-result bug this repo already fixed once.
    """
    client = MagicMock()

    def _get(path, params=None):
        if path.endswith("/members/virtual-machines"):
            raise RuntimeError("API timeout fetching members")
        return {"id": "g1", "display_name": "G1", "expression": []}

    client.get.side_effect = _get

    result = get_group(client, "g1")
    assert result["member_count"] is None
    assert result["members"]["total"] is None
    assert "timeout" in result["members_error"].lower()
