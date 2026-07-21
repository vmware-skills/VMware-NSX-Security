"""Regression — the v1.8.0 envelope renamed ``tags`` to ``items`` in silence.

Source: the v1.8.6 audit of the v1.8.0 envelope conversion.

v1.8.0 wrapped every ``[READ]`` list tool in the family envelope. For the 51
tools that had returned a bare ``list[dict]`` that broke loudly: ``result[0]``
raises on a dict, so the caller finds out on the first run.

``list_vm_tags`` was not one of those 51. It already returned a keyed dict --
``{vm_id, display_name, power_state, tags}`` -- so the conversion changed only
the name of the key holding the rows. A pre-v1.8.0 caller written as::

    if not result.get("tags", []):
        report_untagged(vm)

kept running and started reporting *every* VM as untagged. That failure mode is
worse here than elsewhere in the family: an untagged VM is precisely what a
microsegmentation audit is hunting for, so the silent break does not look like
missing data, it looks like a finding.

The fix is a compatibility alias, not a revert: ``items`` remains the primary
key, ``tags`` points at the *same list object*, and it goes away in 2.0.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from vmware_nsx_security.ops.tags import list_vm_tags

ENVELOPE_KEYS = ("items", "returned", "limit", "total", "truncated", "hint")


def _vm_client(tags: list[dict]) -> MagicMock:
    client = MagicMock()
    client.get.return_value = {
        "results": [
            {
                "external_id": "vm-uuid-1",
                "display_name": "web-01",
                "power_state": "ON",
                "tags": tags,
            }
        ]
    }
    return client


def _tagged(n: int) -> dict:
    return list_vm_tags(
        _vm_client([{"scope": "env", "tag": f"t{i}"} for i in range(n)]), "web-01"
    )


# ---------------------------------------------------------------------------
# The bug, stated as the caller experienced it
# ---------------------------------------------------------------------------


def test_pre_1_8_0_caller_still_sees_the_tags() -> None:
    """``result.get("tags", [])`` must not answer "untagged" on a tagged VM.

    The regression verbatim. The default in ``.get`` is what made the break
    silent, so the assertion is written with the default in place.
    """
    assert len(_tagged(3).get("tags", [])) == 3


def test_a_tagged_vm_is_never_reported_untagged() -> None:
    """The consequence, spelled out: the audit verdict must not invert.

    Asserting the truthiness test a caller actually writes, rather than only
    the length, keeps this pinned to the behaviour that mattered.
    """
    result = _tagged(2)
    assert result.get("tags", []), "a VM with two tags read as untagged"


def test_tags_is_the_same_object_as_items() -> None:
    """Identity, not equality — a copy would let the two drift apart."""
    result = _tagged(3)
    assert result["tags"] is result["items"]


def test_alias_tracks_items_through_mutation() -> None:
    """Proves the identity above is real rather than incidentally equal."""
    result = _tagged(2)
    result["items"].append({"scope": "env", "tag": "late"})
    assert result["tags"][-1] == {"scope": "env", "tag": "late"}
    assert len(result["tags"]) == 3


# ---------------------------------------------------------------------------
# The alias is additive — the envelope stays the primary shape
# ---------------------------------------------------------------------------


def test_genuinely_untagged_vm_is_an_explicit_empty_list() -> None:
    """A real untagged VM and a dropped key must stay distinguishable.

    Both read as ``[]`` through ``.get("tags", [])`` before the alias existed,
    which is what let a broken read pass for a finding.
    """
    result = list_vm_tags(_vm_client([]), "web-01")
    assert "tags" in result
    assert result["tags"] == []
    assert result["returned"] == 0
    assert result["total"] == 0


def test_envelope_and_vm_identity_remain_intact() -> None:
    """The alias must not disturb the envelope or the extras beside it.

    ``vm_id`` is what apply_vm_tag and remove_vm_tag consume, so losing it to a
    careless merge would break the write path as well as the read path.
    """
    result = _tagged(3)
    assert set(ENVELOPE_KEYS) <= set(result)
    assert result["items"] == result["tags"]
    assert result["returned"] == 3
    assert result["total"] == 3
    assert result["limit"] is None
    assert result["truncated"] is False
    assert result["hint"] is None
    assert result["vm_id"] == "vm-uuid-1"
    assert result["display_name"] == "web-01"
    assert result["power_state"] == "ON"
