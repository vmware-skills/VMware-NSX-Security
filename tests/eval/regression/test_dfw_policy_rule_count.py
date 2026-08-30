"""A policy's rule count is asked for, or reported as unknown — never guessed.

Against a real NSX 9.1.0.0200 estate, ``list_dfw_policies`` reported
``rule_count: 0`` for every policy. One of them held six rules, two of them
DROP. The listing said, in effect, that nothing was enforced anywhere.

The cause is a field that has to be requested. NSX's ``SecurityPolicy`` does
carry ``rule_count`` (readonly int, "The count of rules in the policy"), but
the collection endpoint only fills it in when the caller passes
``include_rule_count`` — the API reference is explicit that "by default,
rule_count will not be populated". We never passed it, so the key was absent
from every row, and ``p.get("rule_count", 0)`` turned "the manager did not
answer" into "the answer is none". That is 形态 #1 with the sharpest possible
blast radius: an operator reading a firewall inventory needs "no rules here"
and "I did not find out" to look different, because only one of them is a
reason to stop looking for the DROP rules.

Two paths, two honest answers. The unfiltered listing hits the collection
endpoint, so it asks for the count and reports it. A ``name_filter`` is
resolved through the Policy Search API, which serves indexed objects and has
no such parameter — there the count is genuinely unavailable, and the rows say
``None`` with the envelope stating why. What neither path may do is fetch the
rules per policy to count them: 15 policies would mean 15 extra round trips
(踩坑 #31), and the family's list tools batch.

The control below is the test that matters most. A policy that really has zero
rules must still report ``0``, distinguishably — a fix that answered "unknown"
everywhere would satisfy a careless reading of this bug while destroying the
tool.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from vmware_nsx_security.ops.dfw_policy import list_dfw_policies

# The NSX query parameter that populates SecurityPolicy.rule_count.
_PARAM = "include_rule_count"


def _client(policies: list[dict]) -> MagicMock:
    """A client whose collection endpoint returns ``policies``.

    ``get_all`` is the only call the unfiltered path makes; the mock records
    the params it was handed so a test can assert the count was asked for.
    """
    client = MagicMock()
    client.get_all.return_value = policies
    return client


def _policy(pid: str, **extra: object) -> dict:
    return {"id": pid, "display_name": pid.upper(), "category": "Application", **extra}


# ---------------------------------------------------------------------------
# The defect: a count that was never requested, reported as zero
# ---------------------------------------------------------------------------


def test_the_count_is_requested_from_the_collection_endpoint() -> None:
    """Without include_rule_count the manager omits the field entirely."""
    client = _client([_policy("p1", rule_count=6)])
    list_dfw_policies(client)

    _, kwargs = client.get_all.call_args
    assert kwargs.get("params", {}).get(_PARAM) == "true", (
        "list_dfw_policies must pass include_rule_count=true; NSX does not "
        "populate rule_count on the collection endpoint by default."
    )


def test_a_policy_with_rules_reports_them() -> None:
    """The tester's estate: six rules, two of them DROP."""
    rows = list_dfw_policies(_client([_policy("app-tier", rule_count=6)]))["items"]
    assert rows[0]["rule_count"] == 6


def test_an_unpopulated_count_is_unknown_not_zero() -> None:
    """An older manager (or one that ignored the parameter) omits the key.

    Reporting 0 here is the original bug. ``None`` is the only honest answer.
    """
    rows = list_dfw_policies(_client([_policy("app-tier")]))["items"]
    assert rows[0]["rule_count"] is None


def test_unknown_counts_are_explained_in_the_envelope() -> None:
    """A null needs a reason attached, or the reader supplies their own."""
    result = list_dfw_policies(_client([_policy("app-tier")]))
    note = result.get("rule_count_note")
    assert note, "a null rule_count must come with a stated reason"
    assert "list_dfw_rules" in note, "the note must name the way to find out"


def test_a_non_integer_count_is_not_trusted() -> None:
    """Whatever a null-ish or string value means, it is not a rule count."""
    rows = list_dfw_policies(_client([_policy("p1", rule_count=None)]))["items"]
    assert rows[0]["rule_count"] is None


# ---------------------------------------------------------------------------
# Control: an empty policy is still an explicit, distinguishable zero
# ---------------------------------------------------------------------------


def test_a_genuinely_empty_policy_reports_zero() -> None:
    """The control. "No rules" must survive the fix as a confident 0.

    A fix that reported "unknown" for everything would pass a test that only
    checked "we no longer say 0", and would leave the tool unable to say the
    one thing an operator most wants confirmed: this policy enforces nothing.
    """
    rows = list_dfw_policies(_client([_policy("empty-policy", rule_count=0)]))["items"]
    assert rows[0]["rule_count"] == 0
    assert rows[0]["rule_count"] is not None


def test_a_page_of_known_counts_carries_no_note() -> None:
    """The explanation appears only when something actually went unanswered."""
    policies = [_policy("p1", rule_count=0), _policy("p2", rule_count=6)]
    assert "rule_count_note" not in list_dfw_policies(_client(policies))


def test_zero_and_unknown_are_distinguishable_in_one_page() -> None:
    """The whole point, in a single assertion: these are different answers."""
    policies = [_policy("empty", rule_count=0), _policy("unasked")]
    rows = list_dfw_policies(_client(policies))["items"]
    assert [r["rule_count"] for r in rows] == [0, None]


# ---------------------------------------------------------------------------
# The filtered path: the Search API cannot answer, and says so
# ---------------------------------------------------------------------------


def test_search_path_rows_are_unknown_and_explained(monkeypatch) -> None:
    """The Policy Search API serves indexed objects with no rule_count.

    It also takes no include_rule_count parameter, so this path has no way to
    ask. Unknown is the truth; the old 0 was not.
    """
    monkeypatch.setattr(
        "vmware_nsx_security.ops.dfw_policy.search_by_name",
        lambda *a, **k: [_policy("app-tier")],
    )
    result = list_dfw_policies(MagicMock(), name_filter="app*")
    assert result["items"][0]["rule_count"] is None
    assert result["rule_count_note"]


def test_search_path_does_not_fetch_rules_per_policy(monkeypatch) -> None:
    """No N+1: a filtered listing of 15 policies is still one search call.

    Counting by draining each policy's rules would be accurate and would also
    be the pattern this family removed everywhere else (踩坑 #31).
    """
    monkeypatch.setattr(
        "vmware_nsx_security.ops.dfw_policy.search_by_name",
        lambda *a, **k: [_policy(f"p{i}") for i in range(15)],
    )
    client = MagicMock()
    list_dfw_policies(client, name_filter="p*")
    assert client.get.call_count == 0
    assert client.get_all.call_count == 0


def test_unfiltered_listing_is_one_call_regardless_of_policy_count() -> None:
    """Same guarantee on the unfiltered path: one request, not one per row."""
    client = _client([_policy(f"p{i}", rule_count=i) for i in range(15)])
    list_dfw_policies(client)
    assert client.get_all.call_count == 1
    assert client.get.call_count == 0


# ---------------------------------------------------------------------------
# The fix must not disturb the rest of the row or the envelope
# ---------------------------------------------------------------------------


def test_the_other_columns_are_unchanged() -> None:
    policy = _policy(
        "p1",
        rule_count=2,
        sequence_number=10,
        stateful=False,
        tcp_strict=True,
        path="/infra/domains/default/security-policies/p1",
    )
    row = list_dfw_policies(_client([policy]))["items"][0]
    assert row == {
        "id": "p1",
        "display_name": "P1",
        "category": "Application",
        "sequence_number": 10,
        "stateful": False,
        "tcp_strict": True,
        "rule_count": 2,
        "path": "/infra/domains/default/security-policies/p1",
    }


def test_the_envelope_still_reports_a_total() -> None:
    result = list_dfw_policies(_client([_policy("p1", rule_count=1)]))
    assert result["total"] == 1
    assert result["returned"] == 1
    assert result["truncated"] is False


# ---------------------------------------------------------------------------
# The CLI must not throw the distinction away one layer up
# ---------------------------------------------------------------------------


def _cli_policy_list(policies: list[dict]) -> str:
    """Run ``policy list`` against a manager returning ``policies``."""
    from typer.testing import CliRunner

    from vmware_nsx_security import cli

    client = _client(policies)
    with patch.object(cli, "_get_connection", return_value=(client, "nsx1")):
        result = CliRunner().invoke(cli.app, ["policy", "list"])
    assert result.exit_code == 0, result.output
    return result.output


def _row_for(output: str, policy_id: str) -> str:
    """The one table line for ``policy_id``.

    Asserting against the whole output is what let a first draft of this test
    pass a renderer that still printed "0": the explanatory line below the
    table also contains a "?", so a substring check over everything was
    answered by the wrong text. The cell has to be read where it lives.
    """
    rows = [line for line in output.splitlines() if policy_id in line]
    assert len(rows) == 1, f"expected one row for {policy_id}, got {rows}"
    return rows[0]


def test_cli_renders_an_unknown_count_as_a_question_mark() -> None:
    """"0" in the Rules column would recreate the bug at the last layer.

    The ops layer defending correctly and the renderer flattening it back to a
    number is its own family failure; this is the assertion that stops it.
    ``sequence_number`` is set away from 0 so the only digit that could appear
    in this row is a fabricated rule count.
    """
    out = _cli_policy_list([_policy("app-tier", sequence_number=7)])
    row = _row_for(out, "app-tier")
    assert "?" in row
    assert "0" not in row


def test_cli_prints_the_reason_alongside_the_table() -> None:
    """A "?" in a column no one has seen before needs its meaning printed."""
    out = _cli_policy_list([_policy("app-tier")])
    assert "not retrieved" in out


def test_cli_still_prints_a_real_zero_as_zero() -> None:
    """Control, at the CLI layer: an empty policy reads as empty."""
    out = _cli_policy_list([_policy("empty-policy", rule_count=0, sequence_number=7)])
    row = _row_for(out, "empty-policy")
    assert "0" in row
    assert "?" not in row
    assert "not retrieved" not in out
