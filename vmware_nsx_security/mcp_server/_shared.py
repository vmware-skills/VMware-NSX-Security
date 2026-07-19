"""Shared MCP plumbing for the VMware NSX Security tool modules.

Holds the single ``FastMCP`` instance that every ``mcp_server/tools/*.py``
module registers onto, plus the connection helper, audit logger, and the
error-handling helpers (``_safe_error`` / ``_write_error``) reused by all
tool bodies. Splitting these out of ``server.py`` keeps each tool module a
thin, mechanical try/connect/delegate/audit wrapper and keeps the entry
module (``server.py``) under the 800-line cap (踩坑 #17).
"""


import logging
import os
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from vmware_policy import sanitize

from vmware_nsx_security.config import load_config
from vmware_nsx_security.connection import ConnectionManager, NsxApiError
from vmware_nsx_security.notify.audit import AuditLogger

logger = logging.getLogger(__name__)
_audit = AuditLogger()

_DOCTOR_HINT = "Run 'vmware-nsx-security doctor' to verify connectivity."


def _safe_error(exc: Exception, tool: str) -> str:
    """Return an agent-safe error string; log full detail server-side only.

    Raw exception text from NSX can carry response bodies, internal paths, or
    host:port pairs. We log the full traceback to stderr (operator-visible) and
    return only a control-char-stripped, length-capped message to the agent.
    ``ValueError`` is treated as an intentional, user-facing validation message
    (e.g. "policy has active rules"); the connection layer's teaching errors
    (``NsxApiError``) also pass through; other exceptions get a generic message.
    """
    logger.error("Tool %s failed", tool, exc_info=True)
    if isinstance(exc, (ValueError, FileNotFoundError, KeyError, NsxApiError)):
        return sanitize(str(exc), 300)
    return f"{type(exc).__name__}: operation failed."


def _write_error(
    exc: Exception,
    *,
    operation: str,
    resource: str,
    target: Optional[str],
    parameters: Optional[dict] = None,
) -> dict:
    """Audit a failed write operation and return the standard error payload.

    Write wrappers previously audited only successes, leaving failed writes
    invisible in the audit trail — every write tool's except branch must go
    through here so result="error" entries are recorded too.
    """
    _audit.log(
        target=target or "default",
        operation=operation,
        resource=resource,
        parameters=parameters,
        result="error",
    )
    return {"error": _safe_error(exc, "nsx-security"), "hint": _DOCTOR_HINT}


mcp = FastMCP(
    "vmware-nsx-security",
    instructions=(
        "VMware NSX DFW microsegmentation and security operations. "
        "Manage distributed firewall policies and rules, security groups, "
        "VM NSX tags, run traceflow packet traces, and query IDPS status. "
        "For NSX networking (segments, gateways, NAT, routing), use vmware-nsx. "
        "For VM lifecycle operations, use vmware-aiops. "
        "For vSphere monitoring, use vmware-monitor."
    ),
)

# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

_conn_mgr: Optional[ConnectionManager] = None


def _get_connection(target: Optional[str] = None) -> Any:
    """Return an NsxClient, lazily initialising the connection manager."""
    global _conn_mgr  # noqa: PLW0603
    if _conn_mgr is None:
        config_path_str = os.environ.get("VMWARE_NSX_SECURITY_CONFIG")
        config_path = Path(config_path_str) if config_path_str else None
        config = load_config(config_path)
        _conn_mgr = ConnectionManager(config)
    return _conn_mgr.connect(target)
