"""Make the MCP write surface audit to the skill log by construction.

Two sinks exist and they are not redundant. ``~/.vmware/audit.db`` is the
family's shared SQLite trail that ``@vmware_tool`` writes for every tool call on
every skill; nothing here replaces or duplicates it. ``~/.vmware-nsx-security/audit.log``
is this skill's own JSON-Lines log — the one the CLI appends to on every write,
the one carrying before/after state that ``audit.db`` has no columns for, and
the one an operator opens on the box when asked what changed on the NSX
manager. Both surfaces write it; what this module changes is that a write tool
can no longer be added without it.

**Why a registration-time sweep and not the per-tool calls this repo had.**
Every write body used to call ``_audit.log(...)`` on the success path and
``_write_error`` on the failure path. That works until someone adds a write tool
and forgets, and ``run_traceflow`` already had: declared ``readOnlyHint: False``,
creating a traceflow object on the manager, and contributing nothing to the log.
CLAUDE.md 形态 #7 is exactly this — a marker every tool has to remember is a
marker some tool will forget — and the family's own answer is the shared
decorator, which is where credential redaction lives for the same reason. Here
the property is derived from what the tool already declares to the client
(``readOnlyHint: False``), so a new write tool is audited before anyone has
thought about it, whatever route it took to registration. The per-tool calls are
removed rather than left beside this: two writers would file every write twice,
which is its own way of making the log untrustworthy.

The sweep rebinds both the FastMCP registry entry and the attribute on the
module that defined the tool. Rebinding only the registry would leave
``vmware_nsx_security.mcp_server.server.delete_dfw_policy`` — which ``server.py``
re-exports and much of this repo calls directly — pointing at the unaudited
function.
"""

from __future__ import annotations

import functools
import inspect
import logging
import sys
from collections.abc import Callable
from typing import Any

from vmware_policy import PolicyDenied, sanitize

from vmware_nsx_security.notify.audit import AuditLogger

logger = logging.getLogger("vmware-nsx-security.write_audit")

_audit = AuditLogger()

#: Longest parameter value kept in an audit line. A policy path or a comma-joined
#: VLAN spec is short; an unbounded value would let one call dominate the file.
_MAX_VALUE = 300


def _bind(signature: inspect.Signature, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Full name→value mapping for the call, positional arguments included.

    Falls back to keywords alone when binding fails: the real call is about to
    raise its own ``TypeError`` and this should not mask it with a different one.
    """
    try:
        bound = signature.bind_partial(*args, **kwargs)
        bound.apply_defaults()
    except TypeError:
        return dict(kwargs)
    return dict(bound.arguments)


def _subject(signature: inspect.Signature, params: dict[str, Any]) -> str:
    """The id of the object the call acts on.

    Every write tool on this surface takes it as its first parameter
    (``policy_id``, ``group_id``, ``vm_id``, ``rule_id``). ``target`` names
    the *manager*, not the object, and is recorded in its own field, so it is
    skipped rather than allowed to stand in as the subject of a one-argument
    tool that has not been written yet.
    """
    for name in signature.parameters:
        if name == "target":
            continue
        value = params.get(name)
        if value is None:
            continue
        return sanitize(str(value), _MAX_VALUE)
    return ""


def _failed(result: Any) -> bool:
    """Whether a returned value says the write did not happen.

    Every tool on this surface returns the family envelope ``{"error", "hint"}``
    when it catches — the same key ``vmware_policy`` reads, and the shape
    ``test_no_tool_returns_a_bare_string`` already pins. The string branch is
    kept because the sibling repo's deletes do return a sentence and this module
    is deliberately identical in both (踩坑 #21); here it is inert.
    """
    if isinstance(result, dict):
        return bool(result.get("error"))
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict):
        return bool(result[0].get("error"))
    if isinstance(result, str):
        return result.startswith("Error:")
    return False


def _record(tool: str, signature: inspect.Signature, params: dict[str, Any], result: str) -> None:
    """Append one line, or warn. Audit failure must never fail the operation."""
    recorded = {
        name: sanitize(str(value), _MAX_VALUE) if isinstance(value, str) else value
        for name, value in params.items()
        if name != "target"
    }
    try:
        _audit.log(
            target=str(params.get("target") or "default"),
            operation=tool,
            resource=_subject(signature, params),
            parameters=recorded,
            result=result,
        )
    except Exception:  # degrade to a warning, exactly as audit.py does for OSError
        logger.warning("Could not audit %s to the skill log", tool, exc_info=True)


def _audited(fn: Callable) -> Callable:
    """Wrap ``fn`` so the call appears in the skill audit log either way."""
    signature = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        params = _bind(signature, args, kwargs)
        try:
            result = fn(*args, **kwargs)
        except PolicyDenied:
            # A deny rule or maintenance window refused the call. It is neither
            # an ok nor a transport error, and an operator reading the log for
            # "what did the agent try" needs the attempt to be visible.
            _record(fn.__name__, signature, params, "denied")
            raise
        except Exception:
            _record(fn.__name__, signature, params, "error")
            raise
        _record(fn.__name__, signature, params, "error" if _failed(result) else "ok")
        return result

    return wrapper


def install_write_audit(server: Any) -> list[str]:
    """Wrap every registered write tool so it records to the skill audit log.

    A tool is a write when it told the client so: ``readOnlyHint is False``.
    Tools that left the hint unset are not swept — an unstated hint is not a
    claim, and guessing from the name here would put the guess in the enforcement
    path instead of in the test that cross-checks it.

    Returns the names swept, so a caller (and the import-time binding in
    ``server.py``) has something to assert on rather than a silent no-op.
    """
    audited: list[str] = []
    for name, tool in server._tool_manager._tools.items():
        if getattr(getattr(tool, "annotations", None), "readOnlyHint", None) is not False:
            continue
        wrapped = _audited(tool.fn)
        tool.fn = wrapped
        # Keep the defining module's attribute pointing at the same object, so
        # ``server.py``'s re-export (which runs after this) hands out the audited
        # callable and there is exactly one function per tool in the process.
        owner = sys.modules.get(getattr(tool.fn, "__module__", ""))
        if owner is not None and getattr(owner, name, None) is not None:
            setattr(owner, name, wrapped)
        audited.append(name)
    return audited
