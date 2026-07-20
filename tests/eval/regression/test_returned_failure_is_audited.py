"""A tool that *returns* its failure must be audited as a failure.

``@vmware_tool`` records a call as failed when an exception reaches it, or when
the returned payload is a dict (or one-element list) carrying a truthy
``error`` key — the family's documented envelope. Every tool in this skill
catches its exception and returns that envelope, so the wrapper sees the
failure without any help. Three things depended on it and were silently wrong
wherever a skill returned a shape the wrapper could not read:

1. the audit row said ``status=ok`` for an operation that failed — in a family
   whose stated purpose is a trustworthy audit trail, an affirmatively wrong
   row is worse than a missing one;
2. ``_record_undo`` wrote an undo token for a change that never landed;
3. the circuit breaker was told ``success=True``, so repeated failures could
   never trip it.

Strings are the shape the wrapper cannot read, and it does not sniff them on
purpose: a skill that hands back console text can legitimately emit output
beginning with "Error:" as data. Those tools must call ``report_tool_failure``
explicitly — VMware-NSX's five delete tools do. **This skill has none**, and
:func:`test_no_tool_returns_a_bare_string` is what keeps that true: the day a
``-> str`` tool is added, the envelope detection stops covering it and the
signal has to be wired by hand.

Assertions are on the **audited status**, never on the returned payload. The
payload was always right; reading it back would re-test the thing that never
broke.
"""

from __future__ import annotations

import asyncio
import inspect
import typing
from unittest.mock import patch

import pytest

from vmware_nsx_security.connection import NsxApiError


def _live_tools() -> list[str]:
    """Tool names from the live FastMCP registry, not from a hand-kept list."""
    from vmware_nsx_security.mcp_server.server import mcp

    names = sorted(t.name for t in asyncio.run(mcp.list_tools()))
    assert names, "no tools registered — every check below would be vacuous"
    return names


TOOL_NAMES = _live_tools()


def _dummy_args(fn) -> dict:
    """Minimal keyword arguments: one value per parameter without a default."""
    values = {str: "x", int: 1, bool: False, float: 1.0}
    args = {}
    for name, param in inspect.signature(getattr(fn, "__wrapped__", fn)).parameters.items():
        if param.default is not inspect.Parameter.empty:
            continue
        args[name] = values.get(param.annotation, "x")
    return args


@pytest.fixture
def audited(monkeypatch):
    """Capture audit rows without touching ~/.vmware/audit.db or the CLI log."""
    rows: list[dict] = []

    class _Recorder:
        def log(self, **kw):
            rows.append(kw)

    monkeypatch.setattr("vmware_policy.decorators.get_engine", lambda: _Recorder())
    monkeypatch.setattr("vmware_nsx_security.mcp_server._shared._audit", _Recorder())
    return rows


@pytest.mark.parametrize("tool_name", TOOL_NAMES)
def test_caught_failure_is_audited_as_a_failure(audited, tool_name) -> None:
    import vmware_nsx_security.mcp_server.server as srv

    fn = getattr(srv, tool_name)
    # Each tool module binds _get_connection at import, so patch it where the
    # tool actually looks it up rather than on _shared.
    module = inspect.getmodule(getattr(fn, "__wrapped__", fn))
    failure = NsxApiError("NSX GET /x returned HTTP 404.", status_code=404)

    with patch.object(module, "_get_connection", side_effect=failure):
        result = fn(**_dummy_args(fn))

    assert isinstance(result, dict) and result.get("error"), (
        f"{tool_name} did not return the {{'error': ...}} envelope — if it now "
        "returns some other shape, @vmware_tool cannot detect the failure and "
        "the tool must call report_tool_failure() before returning"
    )
    statuses = [r["status"] for r in audited if "status" in r]
    assert statuses == ["error"], f"{tool_name} audited as {statuses}, expected ['error']"


def test_no_tool_returns_a_bare_string() -> None:
    """The guard that keeps the docstring above true.

    A ``-> str`` tool's failure is invisible to ``@vmware_tool`` — it would be
    audited ``ok`` and reported to the circuit breaker as a success. VMware-NSX
    has five such tools and calls ``report_tool_failure`` in each; this skill
    has none, and adding one without that call reintroduces the defect silently.
    """
    import vmware_nsx_security.mcp_server.server as srv

    string_returning = []
    checked = 0
    for name in TOOL_NAMES:
        fn = getattr(srv, name)
        checked += 1
        hints = typing.get_type_hints(getattr(fn, "__wrapped__", fn))
        if hints.get("return") is str:
            string_returning.append(name)

    assert checked == len(TOOL_NAMES), "scan skipped tools — it would be vacuous"
    assert not string_returning, (
        f"these tools return a bare string: {string_returning}. @vmware_tool "
        "cannot see a failure in a string, so each one needs a "
        "report_tool_failure(msg) call in its except block (see VMware-NSX's "
        "delete tools) — then add it to the exemption list here."
    )
