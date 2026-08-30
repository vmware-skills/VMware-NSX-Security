"""Keep the suite out of the operator's own audit log.

``~/.vmware-nsx-security/audit.log`` is a real artefact on a real machine: it is
what an operator opens to see what changed on the NSX manager. A test run that
appends ``delete_dfw_policy x`` to it is writing a record of a deletion that
never happened into the file whose whole value is that its records are true.

Both sinks are redirected for the whole session — the CLI's, which has leaked
this way since before ``_write_audit`` existed, and the MCP one. A test that
wants to read entries back overrides only its own copy (``monkeypatch`` in a
function fixture is applied after this and restored before the next test).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True, scope="session")
def _skill_audit_log_stays_in_tmp(tmp_path_factory):
    from vmware_nsx_security import cli
    from vmware_nsx_security.mcp_server import _write_audit
    from vmware_nsx_security.notify.audit import AuditLogger

    sink = AuditLogger(log_file=str(tmp_path_factory.mktemp("skill-audit") / "audit.log"))
    saved = (_write_audit._audit, cli._audit)
    _write_audit._audit = sink
    cli._audit = sink
    yield sink
    _write_audit._audit, cli._audit = saved
