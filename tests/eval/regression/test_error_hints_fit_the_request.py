"""A request error must not send the agent to ``vmware-nsx-security doctor``.

Same shape as VMware-Monitor 2.4.1 (real hardware, 2026-10-17): every MCP error
carried "Run 'vmware-nsx-security doctor' to verify connectivity." -- also for
an unknown target name, a rejected argument, a 404 on a policy id that does not
exist, a 400 the Manager answered with, and a delete the gate refused because
the policy still holds rules. Connectivity is fine in all of those, doctor
reports green, and the hint buries the remedy the message already carries.

The doctor hint stays where doctor can tell the caller something: transport
failures, session creation, 401/403, 5xx, a body that was not JSON (a reverse
proxy answering HTML), and anything unplanned.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vmware_nsx_security.config import ConfigError
from vmware_nsx_security.connection import NsxApiError
from vmware_nsx_security.mcp_server import _shared
from vmware_nsx_security.mcp_server.tools import dfw_policy
from vmware_nsx_security.ops.delete_gate import DeleteRefusedError

REPO_ROOT = Path(__file__).resolve().parents[3]

REQUEST_ERRORS = [
    ValueError("Target 'x' not found. Available: lab"),
    ValueError("limit must be 1-1000"),
    DeleteRefusedError("Policy 'p' still holds 3 rules.", {"blockers": ["x"], "unmeasured": []}),
    NsxApiError("HTTP 404", status_code=404, method="GET", path="/policy/api/v1/infra/domains/default/security-policies/x"),
    NsxApiError("HTTP 400", status_code=400, method="PATCH", path="/policy/api/v1/infra/domains/default/groups/x"),
    NsxApiError("HTTP 409", status_code=409, method="PATCH", path="/policy/api/v1/infra/domains/default/groups/x"),
]

DOCTOR_ERRORS = [
    NsxApiError("could not connect", method="GET", path="/policy/api/v1/infra"),
    NsxApiError("HTTP 400 on login", status_code=400, method="POST", path="/api/session/create"),
    NsxApiError("HTTP 401", status_code=401, method="GET", path="/policy/api/v1/infra"),
    NsxApiError("HTTP 403", status_code=403, method="GET", path="/policy/api/v1/infra"),
    NsxApiError("HTTP 500", status_code=500, method="GET", path="/policy/api/v1/infra"),
    NsxApiError("HTTP 503", status_code=503, method="GET", path="/policy/api/v1/infra"),
    ConnectionError("no X-XSRF-TOKEN"),
    TimeoutError("slow"),
    ConfigError("password missing"),
    json.JSONDecodeError("Expecting value", "<html>", 0),
    UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    KeyError("results"),
    RuntimeError("?"),
]



def _not_doctor_first(hint: str, exc: BaseException, module) -> None:
    """A request error is not sent to doctor; a plain ValueError only conditionally.

    A generic ValueError may come from parsing the server's answer, so its hint
    must not claim connectivity is fine (review 2026-10-18); it offers doctor
    only if the message names no fix.
    """
    assert hint != module._DOCTOR_HINT
    if type(exc) is ValueError:
        assert hint == module._CHECK_MESSAGE_HINT

@pytest.mark.parametrize("exc", REQUEST_ERRORS, ids=repr)
def test_a_request_error_does_not_send_the_agent_to_doctor(exc) -> None:
    _not_doctor_first(_shared._hint_for(exc), exc, _shared)


@pytest.mark.parametrize("exc", DOCTOR_ERRORS, ids=repr)
def test_connectivity_parse_and_unplanned_errors_keep_the_doctor_hint(exc) -> None:
    assert _shared._hint_for(exc) == _shared._DOCTOR_HINT


# -- through real tools -----------------------------------------------------


def test_an_unknown_target_through_a_read_tool_gets_no_doctor_hint() -> None:
    failure = ValueError("Target 'x' not found. Available: lab")
    with patch.object(dfw_policy, "_get_connection", side_effect=failure):
        result = dfw_policy.list_dfw_policies(target="x")
    assert "not found" in result["error"]
    assert result["hint"] == _shared._CHECK_MESSAGE_HINT


def test_a_transport_failure_through_a_read_tool_keeps_the_doctor_hint() -> None:
    failure = NsxApiError("NSX could not connect.", method="GET", path="/x")
    with patch.object(dfw_policy, "_get_connection", side_effect=failure):
        result = dfw_policy.list_dfw_policies(target="lab")
    assert result["hint"] == _shared._DOCTOR_HINT


def test_a_refused_delete_gets_no_doctor_hint() -> None:
    radius = {"blockers": ["Policy 'p' still holds 3 rules."], "unmeasured": []}
    with patch.object(dfw_policy, "_get_connection", return_value=MagicMock()), patch(
        "vmware_nsx_security.ops.delete_gate.dfw_policy_delete_blast_radius", return_value=radius
    ):
        result = dfw_policy.delete_dfw_policy("p", confirm=True, target="lab")
    assert "still holds" in result["error"]
    assert "doctor" not in result["hint"]


def test_a_write_transport_failure_keeps_the_doctor_hint() -> None:
    failure = NsxApiError("NSX could not connect.", method="PATCH", path="/x")
    with patch.object(dfw_policy, "_get_connection", side_effect=failure):
        result = dfw_policy.delete_dfw_policy("p", confirm=True, target="lab")
    assert result["hint"] == _shared._DOCTOR_HINT


def test_no_tool_module_hands_out_the_doctor_hint_unconditionally() -> None:
    """New tools must route through ``_hint_for``, not paste the constant."""
    tools = sorted((REPO_ROOT / "vmware_nsx_security" / "mcp_server" / "tools").glob("*.py"))
    assert tools, "no tool modules found"
    offenders = [p.name for p in tools if '"hint": _DOCTOR_HINT' in p.read_text(encoding="utf-8")]
    assert not offenders, offenders
