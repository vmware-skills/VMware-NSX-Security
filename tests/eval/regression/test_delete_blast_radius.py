"""The three DFW deletes preview by default and state their blast radius (HLD §7, 2026-09-16).

* L1 — every response carries ``blast_radius``: what the delete removes, with
  counts, identifiers, ``blockers`` and ``unmeasured``.
* L2 — a bare call (``confirm`` left at its default ``False``) makes no DELETE.
* L3 — ``confirm=True`` is refused when there is a blocker (rules left in a
  policy, entities referencing a group) or when a read the radius depends on
  failed. "Could not look" is never "nothing there".

Every case drives the real gate and the real ops executor through a fake NSX
client that answers by exact path and records every DELETE, so a refusal is
asserted as "no DELETE was made", not as a message.
"""

from __future__ import annotations

import asyncio
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

import pytest

from vmware_nsx_security.connection import NsxApiError

POLICIES = "/policy/api/v1/infra/domains/default/security-policies"
POL = f"{POLICIES}/app-pol"
RULES = f"{POL}/rules"
GROUPS = "/policy/api/v1/infra/domains/default/groups"
GRP = f"{GROUPS}/web-vms"
GROUP_PATH = "/infra/domains/default/groups/web-vms"
# NSX's real endpoint (SDK: "policy groups for which the given object is a member").
ASSOC = f"/policy/api/v1/infra/group-associations?intent_path={GROUP_PATH}"
GW_POLICIES = "/policy/api/v1/infra/domains/default/gateway-policies"

_TOOL_MODULES = ("dfw_policy", "dfw_rules", "groups")


def _err(path: str, status: int) -> NsxApiError:
    return NsxApiError(f"GET {path} returned HTTP {status}.", status_code=status, method="GET", path=path)


class FakeNsx:
    """Answers GETs by exact path; an unseeded object is a 404, an unseeded collection empty."""

    def __init__(self, objects=None, collections=None) -> None:
        self.objects: dict[str, dict] = dict(objects or {})
        self.collections: dict[str, list[dict]] = dict(collections or {})
        self.fail: dict[str, Exception] = {}
        self.deleted: list[str] = []

    def get(self, path: str, *_: Any, **__: Any) -> dict:
        if path in self.fail:
            raise self.fail[path]
        if path in self.objects:
            return self.objects[path]
        raise _err(path, 404)

    def get_all(self, path: str, params: dict | None = None, **k: Any) -> list[dict]:
        if params:
            path = path + "?" + "&".join(f"{key}={val}" for key, val in sorted(params.items()))
        if path in self.fail:
            raise self.fail[path]
        rows = list(self.collections.get(path, []))
        return rows[: k["limit"]] if k.get("limit") else rows

    def delete(self, path: str) -> None:
        self.deleted.append(path)

    def put(self, *a: Any, **k: Any) -> dict:  # pragma: no cover - a delete must never write
        raise AssertionError("a delete must not PUT")

    patch = post = put


@pytest.fixture
def policy_rows(monkeypatch):
    rows: list[dict] = []

    class _Recorder:
        def log(self, **kw):
            rows.append(kw)

    monkeypatch.setattr("vmware_policy.guard.get_engine", lambda: _Recorder())
    return rows


@pytest.fixture
def skill_log(monkeypatch):
    rows: list[dict] = []

    class _Recorder:
        def log(self, **kw):
            rows.append(kw)

    monkeypatch.setattr("vmware_nsx_security.mcp_server._write_audit._audit", _Recorder())
    return rows


def _call(client, tool: str, **kwargs):
    import vmware_nsx_security.mcp_server.server as srv

    with ExitStack() as stack:
        for mod in _TOOL_MODULES:
            stack.enter_context(patch(
                f"vmware_nsx_security.mcp_server.tools.{mod}._get_connection", return_value=client))
        return getattr(srv, tool)(**kwargs)


_POLICY = {"id": "app-pol", "display_name": "App policy", "category": "Application",
           "sequence_number": 10, "stateful": True, "path": "/infra/domains/default/security-policies/app-pol"}
_RULE = {"id": "allow-web", "display_name": "allow web", "action": "ALLOW",
         "source_groups": ["/infra/domains/default/groups/lb"],
         "destination_groups": ["/infra/domains/default/groups/web-vms"],
         "services": ["/infra/services/HTTPS"], "scope": ["ANY"], "direction": "IN_OUT",
         "disabled": False, "sequence_number": 5}


def _policy(rules=()):
    return FakeNsx(objects={POL: _POLICY}, collections={RULES: [{"id": r} for r in rules]})


def _rule():
    return FakeNsx(objects={POL: _POLICY}, collections={RULES: [{"id": "other"}, _RULE]})


def _group(refs=(), collections=None):
    """``refs`` are parent groups that contain web-vms (what group-associations reports)."""
    return FakeNsx(
        objects={GRP: {"id": "web-vms", "display_name": "Web VMs", "path": GROUP_PATH,
                       "expression": [{"resource_type": "Condition"}]}},
        collections={ASSOC: [{"target_type": "Group", "target_display_name": r} for r in refs],
                     **(collections or {})},
    )


def _group_used_by_rules():
    """web-vms is in no parent group, but a DFW rule and a gateway rule name it."""
    return _group(collections={
        POLICIES: [{"id": "app-pol", "display_name": "App policy"},
                   {"id": "other-pol", "display_name": "Other"}],
        RULES: [_RULE],
        f"{POLICIES}/other-pol/rules": [{"id": "r", "display_name": "unrelated",
                                         "source_groups": ["ANY"], "destination_groups": ["ANY"]}],
        GW_POLICIES: [{"id": "gw-pol", "display_name": "Edge policy"}],
        f"{GW_POLICIES}/gw-pol/rules": [{"id": "g", "display_name": "edge allow",
                                         "source_groups": ["ANY"], "destination_groups": ["ANY"],
                                         "scope": [GROUP_PATH]}],
    })


CLEAN = [
    ("delete_dfw_policy", {"policy_id": "app-pol"}, lambda: _policy(), [POL]),
    ("delete_dfw_rule", {"policy_id": "app-pol", "rule_id": "allow-web"}, _rule, [f"{RULES}/allow-web"]),
    ("delete_group", {"group_id": "web-vms"}, lambda: _group(), [GRP]),
]
IDS = [c[0] for c in CLEAN]


# ── L2: a bare call deletes nothing ─────────────────────────────────────


@pytest.mark.parametrize(("tool", "kwargs", "make", "_paths"), CLEAN, ids=IDS)
def test_bare_call_previews_and_deletes_nothing(tool, kwargs, make, _paths, skill_log):
    client = make()
    out = _call(client, tool, **kwargs)
    assert out["action"] == "preview", out
    assert client.deleted == []
    assert out["blast_radius"]["blockers"] == [] and out["blast_radius"]["unmeasured"] == []
    assert [r["result"] for r in skill_log] == ["preview"], "a preview must not be logged as a delete"


@pytest.mark.parametrize(("tool", "kwargs", "make", "_paths"), CLEAN, ids=IDS)
def test_a_truthy_non_true_confirm_previews(tool, kwargs, make, _paths):
    """Only True acts: a positional target landing in confirm must not delete."""
    client = make()
    assert _call(client, tool, confirm="nsx-dc2", **kwargs)["action"] == "preview"
    assert client.deleted == []


# ── acting: confirm=True deletes once and says what ─────────────────────


@pytest.mark.parametrize(("tool", "kwargs", "make", "paths"), CLEAN, ids=IDS)
def test_confirm_deletes_once_and_returns_the_blast_radius(tool, kwargs, make, paths, policy_rows, skill_log):
    client = make()
    out = _call(client, tool, confirm=True, **kwargs)
    assert out["action"] == "deleted" and out["status"] == "deleted", out
    assert client.deleted == paths
    assert out["blast_radius"]["blockers"] == []
    assert [r["status"] for r in policy_rows] == ["ok"]
    assert [r["result"] for r in skill_log] == ["ok"]


# ── L1: measured values ─────────────────────────────────────────────────


def test_policy_preview_measures_identity_and_rules():
    br = _call(_policy(rules=("r1", "r2", "r3")), "delete_dfw_policy", policy_id="app-pol")["blast_radius"]
    assert (br["display_name"], br["category"], br["sequence_number"]) == ("App policy", "Application", 10)
    assert br["rule_count"] == 3
    assert br["rule_ids"] == ["r1", "r2", "r3"]


def test_policy_rule_count_is_not_capped_by_the_listing():
    from vmware_nsx_security.ops.delete_gate import MAX_LISTED

    n = MAX_LISTED + 5
    br = _call(_policy(rules=[f"r{i}" for i in range(n)]), "delete_dfw_policy", policy_id="app-pol")["blast_radius"]
    assert br["rule_count"] == n and len(br["rule_ids"]) == MAX_LISTED


def test_rule_preview_measures_parent_and_match():
    br = _call(_rule(), "delete_dfw_rule", policy_id="app-pol", rule_id="allow-web")["blast_radius"]
    assert br["policy_display_name"] == "App policy" and br["policy_category"] == "Application"
    assert br["action"] == "ALLOW"
    assert br["sources"] == ["/infra/domains/default/groups/lb"]
    assert br["destinations"] == ["/infra/domains/default/groups/web-vms"]
    assert br["services"] == ["/infra/services/HTTPS"]
    assert (br["direction"], br["disabled"], br["sequence_number"]) == ("IN_OUT", False, 5)


def test_group_preview_measures_identity_and_references():
    br = _call(_group(refs=("app-pol", "db-pol")), "delete_group", group_id="web-vms")["blast_radius"]
    assert br["display_name"] == "Web VMs" and br["expression_count"] == 1
    assert br["reference_count"] == 2
    assert br["references"] == ["Group:app-pol", "Group:db-pol"]


def test_group_reference_check_reads_the_real_group_associations_endpoint():
    """The old per-group ``.../groups/{id}/group-associations`` is not in NSX's API."""
    client = _group(refs=("parent",))
    seen: list[tuple[str, dict | None]] = []
    real = client.get_all

    def spy(path, params=None, **k):
        seen.append((path, params))
        return real(path, params, **k)

    client.get_all = spy
    _call(client, "delete_group", group_id="web-vms")
    assert ("/policy/api/v1/infra/group-associations", {"intent_path": GROUP_PATH}) in seen
    assert not any(p.endswith("/web-vms/group-associations") for p, _ in seen)


def test_group_named_by_dfw_and_gateway_rules_is_blocked():
    """group-associations only reports parent groups; rule references come from the rule walk."""
    client = _group_used_by_rules()
    br = _call(client, "delete_group", group_id="web-vms")["blast_radius"]
    assert br["references"] == ["SecurityPolicy:App policy/allow web", "GatewayPolicy:Edge policy/edge allow"]
    assert br["reference_count"] == 2 and br["blockers"]
    out = _call(client, "delete_group", group_id="web-vms", confirm=True)
    assert "error" in out and client.deleted == []


def test_group_in_a_policy_applied_to_scope_is_blocked():
    client = _group(collections={POLICIES: [{"id": "app-pol", "display_name": "App policy",
                                             "scope": [GROUP_PATH]}]})
    br = _call(client, "delete_group", group_id="web-vms")["blast_radius"]
    assert br["references"] == ["SecurityPolicy:App policy (applied-to)"]


# ── L3: blockers refuse with the existing message ───────────────────────


def _assert_refused(out, client, policy_rows, skill_log, *needles):
    assert "error" in out, out
    assert client.deleted == [], "a refusal made a DELETE"
    for n in needles:
        assert n in out["error"], (n, out["error"])
    assert "blast_radius" in out, "the refusal must show what it measured"
    assert [r["status"] for r in policy_rows] == ["error"]
    assert [r["result"] for r in skill_log] == ["error"]


def test_policy_with_rules_is_refused(policy_rows, skill_log):
    client = _policy(rules=("r1",))
    assert _call(client, "delete_dfw_policy", policy_id="app-pol")["blast_radius"]["blockers"]
    policy_rows.clear()
    skill_log.clear()
    out = _call(client, "delete_dfw_policy", policy_id="app-pol", confirm=True)
    _assert_refused(out, client, policy_rows, skill_log, "still contains firewall rule(s)", "list_dfw_rules")


def test_referenced_group_is_refused_and_the_list_survives(policy_rows, skill_log):
    # Long enough that the sanitizer's usual 300-char cap would cut the tail off.
    refs = [f"policy-{i}-" + "x" * 80 for i in range(8)]
    client = _group(refs=refs)
    assert _call(client, "delete_group", group_id="web-vms")["blast_radius"]["blockers"]
    policy_rows.clear()
    skill_log.clear()
    out = _call(client, "delete_group", group_id="web-vms", confirm=True)
    assert len(out["error"]) > 300
    _assert_refused(out, client, policy_rows, skill_log,
                    "8 entity/entities", "update_dfw_rule", "(+5 more)")


# ── L3: an unreadable field refuses ─────────────────────────────────────


UNREADABLE = [
    ("delete_dfw_policy", {"policy_id": "app-pol"}, lambda: _policy(), RULES, "rules"),
    ("delete_dfw_policy", {"policy_id": "app-pol"}, lambda: _policy(), POL, "policy"),
    ("delete_dfw_rule", {"policy_id": "app-pol", "rule_id": "allow-web"}, _rule, RULES, "rule"),
    ("delete_dfw_rule", {"policy_id": "app-pol", "rule_id": "allow-web"}, _rule, POL, "policy"),
    ("delete_group", {"group_id": "web-vms"}, lambda: _group(), ASSOC, "references"),
    ("delete_group", {"group_id": "web-vms"}, lambda: _group(), POLICIES, "references"),
    ("delete_group", {"group_id": "web-vms"}, lambda: _group(), GW_POLICIES, "references"),
    ("delete_group", {"group_id": "web-vms"}, _group_used_by_rules, RULES, "references"),
    ("delete_group", {"group_id": "web-vms"}, lambda: _group(), GRP, "group"),
]


@pytest.mark.parametrize(("tool", "kwargs", "make", "path", "field"), UNREADABLE,
                         ids=[f"{u[0]}-{u[4]}" for u in UNREADABLE])
def test_an_unreadable_field_is_unmeasured_and_refuses(tool, kwargs, make, path, field, policy_rows, skill_log):
    client = make()
    client.fail[path] = _err(path, 500)
    preview = _call(client, tool, **kwargs)
    assert preview["action"] == "preview"
    assert field in preview["blast_radius"]["unmeasured"]
    policy_rows.clear()
    skill_log.clear()
    out = _call(client, tool, confirm=True, **kwargs)
    _assert_refused(out, client, policy_rows, skill_log, f"could not read {field}", "Nothing was deleted")


# ── not found is an error, not a preview of nothing ─────────────────────


@pytest.mark.parametrize(("tool", "kwargs", "make", "needle"), [
    ("delete_dfw_rule", {"policy_id": "app-pol", "rule_id": "nope"}, _rule, "list_dfw_rules"),
    ("delete_dfw_policy", {"policy_id": "nope"}, lambda: _policy(), "404"),
    ("delete_group", {"group_id": "nope"}, lambda: _group(), "404"),
])
def test_a_missing_object_is_an_error_and_deletes_nothing(tool, kwargs, make, needle):
    client = make()
    for confirm in (False, True):
        out = _call(client, tool, confirm=confirm, **kwargs)
        assert needle in out["error"], out
    assert client.deleted == []


# ── the schema advertises the gate ──────────────────────────────────────


@pytest.mark.parametrize("tool", IDS)
def test_schema_defaults_confirm_to_false(tool):
    from vmware_nsx_security.mcp_server.server import mcp

    t = next(t for t in asyncio.run(mcp.list_tools()) if t.name == tool)
    props = t.inputSchema["properties"]
    assert props["confirm"]["default"] is False
    assert "confirm" not in (t.inputSchema.get("required") or [])
    assert props["confirm"]["description"] == (
        "False (default) returns the blast radius and changes nothing. True applies it.")
    desc = " ".join(t.description.split())
    assert "Do not set confirm=True on your own" in desc
    assert t.description.startswith("[WRITE]")
