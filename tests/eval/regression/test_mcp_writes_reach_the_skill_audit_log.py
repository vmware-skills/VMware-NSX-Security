"""Every MCP write tool must land in this skill's own audit log, structurally.

This repo already wrote ``~/.vmware-nsx-security/audit.log`` from its MCP write
tools — VMware-NSX did not, and closing that gap is what brought this test here
(踩坑 #21: the two repos share their design and a fix in one is half a fix).

It was written per tool. Every write body called ``_audit.log(...)`` on the
success path and ``_write_error`` on the failure path, which works exactly until
someone adds a write tool and forgets. **``run_traceflow`` had already forgotten**
— declared ``readOnlyHint: False``, creating a traceflow object on the manager,
and contributing nothing to the log an operator reads. Ten of eleven write tools
audited, and nothing anywhere said which one did not.

That is CLAUDE.md 形态 #7 in its purest form, and the family's own answer to it
is not "remember harder": credential redaction lives in the shared decorator
rather than in per-tool declarations for the same reason. So the audit is
derived from what the tool already declares to the client — ``readOnlyHint is
False`` — and applied by a sweep over the registry at registration time. A
twelfth write tool is audited before anyone has thought about it.

The write set here is derived the same way, so the twelfth also fails this suite
if the sweep ever stops covering it. A test naming today's eleven would pass for
ever while the surface grew past it. Because both the fix and the test read the
same annotation, ``test_the_write_set_is_derived_not_inherited`` cross-checks
against an independent derivation — the verb the tool's name starts with — so a
write tool mislabelled read-only cannot slip out of the set they share.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from unittest.mock import MagicMock, patch

import pytest

from vmware_nsx_security.connection import NsxApiError
from vmware_nsx_security.mcp_server import server as srv

#: Value handed to every required parameter. It must satisfy the ops layer's
#: ``_validate_id`` (alphanumerics, hyphens, underscores) or every tool would
#: take its validation-error path and the success branch would go untested.
PROBE = "probe-id"

_PLACEHOLDER: dict[object, object] = {str: PROBE, int: 1, float: 1.0, bool: False}


def _tool_names(read_only: bool) -> frozenset[str]:
    return frozenset(
        t.name
        for t in asyncio.run(srv.mcp.list_tools())
        if getattr(getattr(t, "annotations", None), "readOnlyHint", None) is read_only
    )


WRITE_TOOLS = _tool_names(read_only=False)
READ_TOOLS = _tool_names(read_only=True)

# 形态 #1: an empty derivation reads as "nothing to check" and reports green.
assert WRITE_TOOLS, "no write tools derived from the MCP annotations — this suite would check nothing"
assert READ_TOOLS, "no read tools derived from the MCP annotations — the control would check nothing"


def _minimal_args(fn) -> dict:
    args = {}
    for name, param in inspect.signature(fn).parameters.items():
        if param.default is not inspect.Parameter.empty:
            continue
        args[name] = _PLACEHOLDER.get(param.annotation, PROBE)
    return args


def _module_of(fn):
    """The tool module, which is where ``_get_connection`` must be patched."""
    return inspect.getmodule(getattr(fn, "__wrapped__", fn))


@pytest.fixture(autouse=True)
def _no_real_waiting(monkeypatch):
    """``run_traceflow`` polls the manager for a result and sleeps between tries.

    Against a mock the trace never completes, so the generic sweep below spent
    twenty seconds waiting for a MagicMock. Nothing in this file is testing the
    poll; what it tests is what lands in the audit log either way.
    """
    monkeypatch.setattr("time.sleep", lambda _seconds: None)


@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    from vmware_nsx_security.mcp_server import _write_audit
    from vmware_nsx_security.notify.audit import AuditLogger

    path = tmp_path / "audit.log"
    monkeypatch.setattr(_write_audit, "_audit", AuditLogger(log_file=str(path)))

    def entries() -> list[dict]:
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    return entries


# ---------------------------------------------------------------------------
# The property
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
def test_every_mcp_write_tool_records_to_the_skill_audit_log(name, audit_log):
    fn = getattr(srv, name)
    with patch.object(_module_of(fn), "_get_connection", return_value=MagicMock()):
        fn(**_minimal_args(fn))

    rows = [r for r in audit_log() if r["operation"] == name]
    assert len(rows) == 1, (
        f"{name} wrote {len(rows)} entries to ~/.vmware-nsx-security/audit.log, expected 1"
    )
    row = rows[0]
    assert row["resource"] == PROBE, f"{name} audited resource={row['resource']!r}, expected the id it acted on"
    assert row["target"] == "default", f"{name} audited target={row['target']!r} for an omitted target"
    assert row["skill"] == "nsx-security"
    assert row["result"] in {"ok", "error"}, f"{name} audited an unexpected result {row['result']!r}"


def test_the_registered_tool_and_the_module_attribute_are_one_object():
    """No split brain: the audited callable is the one both surfaces reach.

    ``server.py`` re-exports every tool into its own namespace and much of this
    repo calls it there. If the wrapper were installed only on the FastMCP
    registry, that re-exported name would be the unaudited function.
    """
    for name in sorted(WRITE_TOOLS):
        assert srv.mcp._tool_manager._tools[name].fn is getattr(srv, name), (
            f"{name}: the registry and vmware_nsx_security.mcp_server.server disagree "
            "on which callable it is"
        )


def test_a_successful_write_is_recorded_as_ok(audit_log):
    from vmware_nsx_security.mcp_server.tools import dfw_policy as tool

    with patch.object(tool, "_get_connection", return_value=MagicMock()), patch(
        "vmware_nsx_security.ops.dfw_policy.create_dfw_policy", return_value={"id": "pol-1"}
    ):
        srv.create_dfw_policy("pol-1", "App tier")
    rows = audit_log()
    assert [r["result"] for r in rows] == ["ok"]
    assert rows[0]["parameters"]["display_name"] == "App tier"


def test_a_write_that_returns_an_error_envelope_is_recorded_as_error(audit_log):
    """The writes catch and return ``{"error", "hint"}``; they never raise.

    An audit that only noticed exceptions would file a create that did not
    happen as a success — the affirmatively wrong row that is worse than a
    missing one.
    """
    from vmware_nsx_security.mcp_server.tools import dfw_policy as tool

    with patch.object(tool, "_get_connection", side_effect=NsxApiError("boom", status_code=400)):
        result = srv.create_dfw_policy("pol-1", "App tier")
    assert "error" in result
    assert [r["result"] for r in audit_log()] == ["error"]


def test_the_declared_target_is_audited(audit_log):
    from vmware_nsx_security.mcp_server.tools import dfw_policy as tool

    with patch.object(tool, "_get_connection", return_value=MagicMock()), patch(
        "vmware_nsx_security.ops.dfw_policy.delete_dfw_policy", return_value={"status": "deleted"}
    ):
        srv.delete_dfw_policy("pol-1", target="nsx-dc2")
    assert [r["target"] for r in audit_log()] == ["nsx-dc2"]


def test_the_audited_subject_is_the_object_never_the_manager():
    """``target`` names the NSX manager, not the thing that changed.

    No tool on today's surface takes ``target`` first, so removing that guard
    changes nothing any tool call can observe — the mutation survives the whole
    suite above. A guard only a future caller can exercise still needs an
    assertion that can fail.
    """
    from vmware_nsx_security.mcp_server import _write_audit

    def target_first(target=None, group_id=None):  # pragma: no cover - a signature, not a call
        ...

    signature = inspect.signature(target_first)
    subject = _write_audit._subject(signature, {"target": "nsx-dc2", "group_id": "web-tier"})
    assert subject == "web-tier", f"audited the manager name {subject!r} as the changed object"


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def test_read_tools_write_no_audit_entry(audit_log):
    """A read must not start writing rows.

    An audit log that also records every list call is not a stricter audit log;
    it is one nobody reads, and the writes disappear into it.
    """
    for name in sorted(READ_TOOLS):
        fn = getattr(srv, name)
        with patch.object(_module_of(fn), "_get_connection", return_value=MagicMock()):
            fn(**_minimal_args(fn))
    assert audit_log() == [], "a read-only tool wrote to the write audit log"


def test_the_write_set_is_derived_not_inherited():
    """Two independent derivations of "this tool writes" must agree."""
    verbs = ("create_", "update_", "delete_", "apply_", "remove_", "run_", "set_")
    by_name = frozenset(
        t.name for t in asyncio.run(srv.mcp.list_tools()) if t.name.startswith(verbs)
    )
    assert by_name == WRITE_TOOLS, (
        "the annotation-derived write set and the name-derived one disagree: "
        f"annotation-only={sorted(WRITE_TOOLS - by_name)}, name-only={sorted(by_name - WRITE_TOOLS)}"
    )


def test_a_broken_audit_sink_does_not_break_the_write(monkeypatch):
    """Audit failure degrades to a warning; it never fails the operation."""
    from vmware_nsx_security.mcp_server import _write_audit
    from vmware_nsx_security.mcp_server.tools import dfw_policy as tool

    exploding = MagicMock()
    exploding.log.side_effect = RuntimeError("disk full")
    monkeypatch.setattr(_write_audit, "_audit", exploding)

    with patch.object(tool, "_get_connection", return_value=MagicMock()), patch(
        "vmware_nsx_security.ops.dfw_policy.delete_dfw_policy", return_value={"status": "deleted"}
    ):
        assert srv.delete_dfw_policy("pol-1") == {"status": "deleted"}
    assert exploding.log.called


def test_no_write_tool_still_audits_from_its_own_body():
    """The per-tool calls are gone, not merely supplemented.

    Leaving them beside the sweep would file every write twice, which is a
    different way of making the log untrustworthy.
    """
    import pathlib

    tools_dir = pathlib.Path(srv.__file__).resolve().parent / "tools"
    sources = sorted(tools_dir.glob("*.py"))
    assert sources, f"no tool modules under {tools_dir} — this check would find nothing"
    offenders = [p.name for p in sources if "_audit.log(" in p.read_text()]
    assert not offenders, f"{offenders} still audit from the tool body; entries would be doubled"
