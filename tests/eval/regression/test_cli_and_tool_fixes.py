"""Regression evals for the 2026-06 CLI/ops fix batch.

Covers:
* CLI shared error decorator — known errors become a red one-liner +
  exit code 1, not a raw traceback.
* `tag remove` CLI command (remove_vm_tag was implemented + tested but
  exposed nowhere while cli.py advertised "list, apply, remove").
* Traceflow cleanup semantics — IN_PROGRESS traceflows are not deleted,
  and the result reports cleaned_up.
* Traceflow poll budget — honor the requested timeout (old formula
  silently capped at 30s and could produce zero polls).
* get_group members fetch failure — member_count None + members_error
  instead of a silent 0.
* CLI write audit — failures are audited with result="error".
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from vmware_nsx_security.connection import NsxApiError


# ── CLI error decorator ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "exc",
    [
        NsxApiError("NSX GET /x returned HTTP 404. Nothing exists at /x.", status_code=404),
        FileNotFoundError("Config file not found: ~/.vmware-nsx-security/config.yaml"),
        KeyError("No virtual machine named 'web-99' exists in the NSX fabric inventory."),
        OSError("Permission denied: ~/.vmware-nsx-security/.env"),
    ],
)
def test_cli_known_errors_become_red_line_and_exit_1(exc: Exception) -> None:
    from vmware_nsx_security import cli

    with patch.object(cli, "_get_connection", side_effect=exc):
        result = CliRunner().invoke(cli.app, ["policy", "list"])

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "Traceback" not in result.output
    # The original message must reach the user (KeyError quotes unwrapped).
    expected = exc.args[0] if isinstance(exc, KeyError) else str(exc)
    assert expected.split(" ")[0] in result.output


def test_cli_unknown_errors_still_raise() -> None:
    from vmware_nsx_security import cli

    with patch.object(cli, "_get_connection", side_effect=RuntimeError("boom")):
        result = CliRunner().invoke(cli.app, ["policy", "list"])
    assert result.exit_code != 0
    assert isinstance(result.exception, RuntimeError)


# ── tag remove CLI command ───────────────────────────────────────────────


def test_cli_tag_remove_dry_run_advertises_real_endpoint() -> None:
    from vmware_nsx_security import cli

    result = CliRunner().invoke(
        cli.app,
        ["tag", "remove", "vm-1", "--scope", "env", "--value", "prod", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "remove_vm_tag" in result.output
    assert "action=remove_tags" in result.output


def test_cli_tag_remove_calls_ops_and_audits_ok() -> None:
    from vmware_nsx_security import cli

    client = MagicMock()
    audit = MagicMock()
    with patch.object(cli, "_get_connection", return_value=(client, MagicMock())), \
         patch.object(cli, "_audit", audit), \
         patch("vmware_nsx_security.ops.tags.remove_vm_tag") as op:
        op.return_value = {"status": "removed"}
        # Two prompts: removing a tag can take the VM out of a security group,
        # and its firewall policy changes with it.
        result = CliRunner().invoke(
            cli.app, ["tag", "remove", "vm-1", "--scope", "env", "--value", "prod"],
            input="y\ny\n",
        )
    assert result.exit_code == 0, result.output
    op.assert_called_once_with(client, "vm-1", "env", "prod")
    assert audit.log.call_args.kwargs["operation"] == "remove_vm_tag"
    assert audit.log.call_args.kwargs["result"] == "ok"


def test_cli_tag_remove_aborts_when_the_second_prompt_is_declined() -> None:
    """The guard is the abort, not the prompt.

    A confirmation that prints and then proceeds anyway is decoration. This
    declines at the second prompt and asserts the ops function was never
    reached — the half worth testing.
    """
    from vmware_nsx_security import cli

    client = MagicMock()
    with patch.object(cli, "_get_connection", return_value=(client, MagicMock())), \
         patch.object(cli, "_audit", MagicMock()), \
         patch("vmware_nsx_security.ops.tags.remove_vm_tag") as op:
        result = CliRunner().invoke(
            cli.app, ["tag", "remove", "vm-1", "--scope", "env", "--value", "prod"],
            input="y\nn\n",
        )
    assert result.exit_code != 0
    op.assert_not_called()


def test_cli_write_failure_audited_as_error() -> None:
    """Write audit was success-only — a failed write left no audit trail."""
    from vmware_nsx_security import cli

    audit = MagicMock()
    err = NsxApiError("NSX POST /x returned HTTP 503. Not ready.", status_code=503)
    with patch.object(cli, "_get_connection", return_value=(MagicMock(), MagicMock())), \
         patch.object(cli, "_audit", audit), \
         patch("vmware_nsx_security.ops.tags.apply_vm_tag", side_effect=err):
        result = CliRunner().invoke(
            cli.app, ["tag", "apply", "vm-1", "--scope", "env", "--value", "prod"]
        )
    assert result.exit_code == 1
    assert audit.log.call_args.kwargs["result"] == "error"
    assert audit.log.call_args.kwargs["operation"] == "apply_vm_tag"


# ── Traceflow cleanup + poll budget ──────────────────────────────────────


def _tf_client(state_sequence: list[str]) -> MagicMock:
    client = MagicMock()
    client.post.return_value = {"id": "tf-1"}
    states = iter(state_sequence)
    last = state_sequence[-1]

    def _get(path, params=None):
        if path == "/api/v1/traceflows/tf-1":
            return {"operation_state": next(states, last)}
        if path == "/api/v1/traceflows/tf-1/observations":
            return {"results": []}
        raise AssertionError(f"unexpected GET {path}")

    client.get.side_effect = _get
    return client


def test_finished_traceflow_is_cleaned_up() -> None:
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client = _tf_client(["FINISHED"])
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        result = run_traceflow(client, "lport-1", "10.0.0.1", "10.0.0.2")
    client.delete.assert_called_once_with("/api/v1/traceflows/tf-1")
    assert result["cleaned_up"] is True


def test_in_progress_traceflow_is_not_deleted() -> None:
    """Deleting an IN_PROGRESS traceflow 404s the later
    get_traceflow_result lookup the docstring tells users to make."""
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client = _tf_client(["IN_PROGRESS"])
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        result = run_traceflow(
            client, "lport-1", "10.0.0.1", "10.0.0.2", timeout_seconds=2
        )
    client.delete.assert_not_called()
    assert result["operation_state"] == "IN_PROGRESS"
    assert result["cleaned_up"] is False


def test_failed_cleanup_reported_as_not_cleaned_up() -> None:
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client = _tf_client(["FINISHED"])
    client.delete.side_effect = RuntimeError("409 conflict")
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        result = run_traceflow(client, "lport-1", "10.0.0.1", "10.0.0.2")
    assert result["cleaned_up"] is False


def test_poll_budget_honors_timeout_and_polls_at_least_once() -> None:
    from vmware_nsx_security.ops.traceflow import run_traceflow

    # timeout_seconds=1 → old formula gave 0 polls; must give at least 1.
    client = _tf_client(["FINISHED"])
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        run_traceflow(client, "lport-1", "10.0.0.1", "10.0.0.2", timeout_seconds=1)
    polls = [c for c in client.get.call_args_list if c.args[0] == "/api/v1/traceflows/tf-1"]
    assert len(polls) == 1

    # timeout_seconds=120 → old formula silently capped at 15 polls (30s);
    # must now honor the full requested window (60 polls at 2s interval).
    client = _tf_client(["IN_PROGRESS"])
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        run_traceflow(client, "lport-1", "10.0.0.1", "10.0.0.2", timeout_seconds=120)
    polls = [c for c in client.get.call_args_list if c.args[0] == "/api/v1/traceflows/tf-1"]
    assert len(polls) == 60


# ── get_group members fetch failure ──────────────────────────────────────


def test_get_group_member_fetch_failure_is_explicit_not_silent_zero() -> None:
    from vmware_nsx_security.ops.security_group import get_group

    client = MagicMock()

    def _get(path, params=None):
        if path.endswith("/members/virtual-machines"):
            raise RuntimeError("API timeout fetching members")
        return {"id": "g1", "display_name": "G1", "expression": []}

    client.get.side_effect = _get
    result = get_group(client, "g1")
    assert result["member_count"] is None, "failure must not masquerade as 0 members"
    assert "members_error" in result
    assert "timeout" in result["members_error"].lower()


def test_get_group_success_keeps_count_and_no_error_field() -> None:
    from vmware_nsx_security.ops.security_group import get_group

    client = MagicMock()

    def _get(path, params=None):
        if path.endswith("/members/virtual-machines"):
            return {"results": [{"external_id": "vm-1", "display_name": "web-01"}]}
        return {"id": "g1", "display_name": "G1", "expression": []}

    client.get.side_effect = _get
    result = get_group(client, "g1")
    assert result["member_count"] == 1
    assert "members_error" not in result


# ── shared _validate.py is the single source of truth ───────────────────


def test_validate_id_deduplicated_into_shared_module() -> None:
    from vmware_nsx_security.ops import _validate, dfw_policy, dfw_rules, security_group, traceflow

    assert dfw_policy._validate_id is _validate.validate_id
    assert dfw_rules._validate_id is _validate.validate_id
    assert security_group._validate_id is _validate.validate_id
    assert traceflow._validate_id is _validate.validate_id

    with pytest.raises(ValueError):
        _validate.validate_id("../etc/passwd", "policy_id")
