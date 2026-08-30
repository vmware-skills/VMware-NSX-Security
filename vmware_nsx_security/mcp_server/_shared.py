"""Shared MCP plumbing for the VMware NSX Security tool modules.

Holds the single ``FastMCP`` instance that every ``mcp_server/tools/*.py``
module registers onto, plus the connection helper, audit logger, and the
error-handling helpers (``_safe_error`` / ``_write_error``) reused by all
tool bodies. Splitting these out of ``server.py`` keeps each tool module a
thin, mechanical try/connect/delegate/audit wrapper and keeps the entry
module (``server.py``) under the 800-line cap (踩坑 #17).
"""


import logging
import ssl
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from vmware_policy import sanitize

from vmware_nsx_security.config import ConfigError, load_config
from vmware_nsx_security.connection import ConnectionManager, NsxApiError
from vmware_nsx_security import __version__

logger = logging.getLogger(__name__)

_DOCTOR_HINT = "Run 'vmware-nsx-security doctor' to verify connectivity."


def _safe_error(exc: Exception, tool: str) -> str:
    """Return an agent-safe error string; log full detail server-side only.

    Raw exception text from NSX can carry response bodies, internal paths, or
    host:port pairs. We log the full traceback to stderr (operator-visible) and
    return only a control-char-stripped, length-capped message to the agent.

    The rule is a property, not a list: every exception this skill raises on
    purpose passes through, and only genuinely unplanned ones are reduced. That
    covers ``ValueError`` as an intentional, user-facing validation message
    (e.g. "policy has active rules") and the connection layer's teaching errors
    (``NsxApiError``).

    The missing-password error — this family's most common first-run failure,
    whose entire remedy is the env var name it carries — arrives as
    ``ConfigError``, a narrow ``OSError`` subclass ``config.py`` raises on
    purpose. Bare ``OSError`` is deliberately *not* here: it would also admit
    ``socket.gaierror`` (the name that failed to resolve) and ``requests``-style
    connection errors (the full ``scheme://host:port/path``), neither of which
    is authored text. ``sanitize`` strips control characters and truncates; it
    redacts nothing, so breadth here is exposure.

    ``FileNotFoundError``, ``PermissionError``, ``TimeoutError`` and
    ``ConnectionError`` stay: each is narrow, each was already reachable through
    the ``OSError`` entry this replaces, and their text describes the operator's
    own environment rather than the manager's response. One is raised here
    deliberately — ``FileNotFoundError`` for a missing config file.

    ``ssl.SSLError`` is reduced *before* the allowlist is consulted, because an
    allowlist structurally cannot say "not this one":
    ``ssl.SSLCertVerificationError`` inherits from ``ValueError`` as well as
    ``OSError``, and ``ValueError`` has been allowed since long before any of
    this. Its message quotes the certificate subject and the hostname. Only
    ``ssl.SSLError`` is pre-checked — ``socket.gaierror`` and
    ``ConnectionRefusedError`` have ``OSError`` as their only base, so removing
    ``OSError`` already reduces them, and naming them here would make the guard
    promise more than it does.

    That pre-check cannot fire on this skill's own transport path, and saying so
    matters more than the guard does: httpx raises ``httpx.ConnectError`` for a
    TLS failure, which is not an ``ssl.SSLError`` subclass, and
    ``connection.py`` translates it into an allowlisted ``NsxApiError``. What
    keeps the certificate subject out of agent context here is that
    ``connection.py`` no longer interpolates the raw exception into that
    message. The pre-check is defence in depth for an ``ssl.SSLError`` arriving
    by some other route, and is verified against a constructed one.

    The rule and the allowlist are kept identical to VMware-NSX's: the two
    skills share this connection and config design, and a pattern fixed in one
    repo and not the other is this family's most-repeated defect (踩坑 #21).

    Anything else is reduced to its type — an unplanned exception's text was
    written for a developer reading a traceback, not for an agent choosing what
    to do next, and it is the one that can carry credentials.
    """
    logger.error("Tool %s failed", tool, exc_info=True)
    if isinstance(exc, ssl.SSLError):
        return f"{type(exc).__name__}: operation failed."
    _passthrough = (
        ValueError,
        FileNotFoundError,
        KeyError,
        PermissionError,
        TimeoutError,
        ConnectionError,
        ConfigError,
        NsxApiError,
    )
    if isinstance(exc, _passthrough):
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
    """Return the standard error payload for a failed write.

    It no longer audits. It used to, because the tool bodies audited their own
    successes and the failure path had to match — and that whole arrangement is
    what let ``run_traceflow`` be added as a write tool that audited neither.
    ``_write_audit.install_write_audit`` now records every write on both paths,
    from the ``readOnlyHint`` the tool already declares, so auditing here as
    well would file each failure twice.

    The ``operation`` / ``resource`` / ``parameters`` arguments are kept: the
    callers pass them, they cost nothing, and removing them from eleven call
    sites is a rename with no reader.
    """
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

# FastMCP takes no version argument and leaves the lowlevel server's at
# None, which makes `initialize` answer with the MCP SDK's version rather
# than ours. Set it so a client can tell which release it is talking to.
mcp._mcp_server.version = __version__

# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

_conn_mgr: Optional[ConnectionManager] = None


def _get_connection(target: Optional[str] = None) -> Any:
    """Return an NsxClient, lazily initialising the connection manager."""
    global _conn_mgr  # noqa: PLW0603
    if _conn_mgr is None:
        # No env-var read here: load_config resolves the path (explicit arg,
        # then the environment, then the default). This was a third copy of
        # that rule, and copies are how the doctor's copy drifted (形态 #6).
        config = load_config()
        _conn_mgr = ConnectionManager(config)
    return _conn_mgr.connect(target)
