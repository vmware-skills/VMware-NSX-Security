"""A teaching message the agent never sees is not a teaching message.

``_safe_error`` reduces unrecognised exceptions to ``"<Class>: operation
failed."`` so raw NSX Manager text cannot leak. The allowlist it checks against
was an enumeration, and an enumeration drifts: ``OSError`` was missing from it,
so the one exception ``config.py`` raises — the missing-password error, this
family's most common first-run failure — reached an MCP agent as
``OSError: operation failed.``

That message's entire remedy is the env var name it carries, so redacting it
left the agent with a failure it could not act on and no way to discover the
fix. The defect was invisible from the CLI, which prints the message in full,
and invisible to the error-quality eval, which reads the message at the raise
site rather than what survives the wrapper.

So the rule is the inverse of an enumeration: every exception this skill raises
on purpose passes through, and only genuinely unplanned ones are reduced.
"""

from __future__ import annotations

import pytest

from vmware_nsx_security.connection import NsxApiError
from vmware_nsx_security.mcp_server._shared import _safe_error

TEACHING = "Policy 'web-dfw' has active rules. Run dfw_rule_list first, then delete each rule."

ENV_KEY = "VMWARE_NSX_SECURITY_PROD_PASSWORD"
MISSING_PASSWORD = f"Password not found. Set environment variable: {ENV_KEY}"


def test_missing_password_keeps_the_env_var_name():
    """The single OSError config.py raises — and the whole point of it is the name."""
    out = _safe_error(OSError(MISSING_PASSWORD), "dfw_policy_list")
    assert ENV_KEY in out
    assert "operation failed" not in out


def test_nsx_api_error_keeps_its_message():
    """The connection layer's teaching errors are the ones agents act on."""
    assert _safe_error(NsxApiError(TEACHING, status_code=404), "dfw_policy_get") == TEACHING


@pytest.mark.parametrize("exc_type", [ValueError, FileNotFoundError, KeyError, PermissionError])
def test_validation_errors_still_pass_through(exc_type):
    assert "web-dfw" in _safe_error(exc_type(TEACHING), "t")


def test_unplanned_exceptions_are_still_reduced():
    """The redaction this allowlist exists for has to keep working."""
    out = _safe_error(RuntimeError("https://admin:hunter2@nsx.internal/policy/api/v1/domains"), "t")
    assert out == "RuntimeError: operation failed."
    assert "hunter2" not in out


def test_message_is_still_truncated():
    """Length capping is the other half of the guard."""
    assert len(_safe_error(NsxApiError("x" * 900), "t")) <= 300
