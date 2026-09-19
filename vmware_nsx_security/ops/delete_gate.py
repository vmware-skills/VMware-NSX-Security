"""The blast-radius gate in front of the three DFW deletes (HLD §7, revised 2026-09-16).

The ops delete functions (``delete_dfw_policy``, ``delete_dfw_rule``,
``delete_group``) stay the executors the CLI calls, with every refusal they
already had. This module is what the MCP tools put in front of them:

* ``*_delete_blast_radius`` reads what a delete would remove and what stands in
  its way (L1). A bare MCP call returns it and deletes nothing (L2).
* ``refuse_unless_clear`` raises :class:`DeleteRefusedError` when the radius has
  a blocker or a field that could not be read (L3). "Could not look" is never
  read as "nothing there".

Only endpoints the repo already calls are read: the policy and group GETs
(``get_dfw_policy`` / ``get_group``), the policy's rules collection
(``list_dfw_rules``), and for ``delete_group`` the reads of
``security_group.find_group_references`` (NSX's ``/infra/group-associations``
for parent groups, plus the DFW and gateway-firewall rule walk).
A rule is found by walking its policy's rules, not by a per-rule GET.

The object itself answering 404 is not an unmeasured field — it means there is
nothing to delete, and the ``NsxApiError`` (or a ``ValueError`` naming the list
tool) propagates as the teaching error it already is.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from vmware_policy import sanitize

from vmware_nsx_security.connection import NsxApiError
from vmware_nsx_security.ops._validate import validate_id as _validate_id
from vmware_nsx_security.ops.dfw_policy import policy_refusal_message
from vmware_nsx_security.ops.security_group import find_group_references, group_refusal_message

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

#: Identifiers listed individually in a blast radius; the counts cover the rest.
MAX_LISTED = 16

#: Walk a whole collection: a count read from a capped walk would be a guess.
_WALK_LIMIT = 1_000_000

_DFW_BASE = "/policy/api/v1/infra/domains/default/security-policies"
_GROUPS_BASE = "/policy/api/v1/infra/domains/default/groups"


class DeleteRefusedError(ValueError):
    """A confirmed delete refused: a blocker, or a blast radius that could not be read.

    A ``ValueError`` so ``_safe_error`` passes the teaching text through; it
    carries the radius so the refusal envelope can show what was measured.
    """

    def __init__(self, message: str, blast_radius: dict[str, Any]) -> None:
        super().__init__(message)
        self.blast_radius = blast_radius


class _Unmeasured:
    """Sentinel for a read that failed."""


_UNMEASURED = _Unmeasured()


def _read(fn: Callable[[], Any], *, missing_raises: bool = True) -> Any:
    """Run one measurement read.

    A 404 raises when ``missing_raises`` (the object itself is not there);
    any other API failure — and a 404 on a dependent read — is ``_UNMEASURED``.
    """
    try:
        return fn()
    except NsxApiError as exc:
        if missing_raises and exc.status_code == 404:
            raise
        return _UNMEASURED


def _s(value: Any, limit: int = 200) -> str:
    return sanitize(str(value), limit) if value not in (None, "") else ""


def _paths(values: Any) -> list[str]:
    return [_s(v) for v in (values or [])][:MAX_LISTED]


def _finish(radius: dict[str, Any], unmeasured: list[str], blockers: list[str]) -> dict[str, Any]:
    return {**radius, "blockers": blockers, "unmeasured": unmeasured}


def refuse_unless_clear(tool: str, radius: dict[str, Any]) -> None:
    """Raise :class:`DeleteRefusedError` unless the radius is fully measured and unblocked."""
    if radius["blockers"]:
        raise DeleteRefusedError(" ".join(radius["blockers"]), radius)
    if radius["unmeasured"]:
        raise DeleteRefusedError(
            f"{tool} refused: could not read {', '.join(radius['unmeasured'])}, so what "
            "the delete would remove is unknown. Nothing was deleted. Run "
            "'vmware-nsx-security doctor' to check connectivity and permissions, then "
            "preview again.",
            radius,
        )


def preview(radius: dict[str, Any]) -> dict[str, Any]:
    """The L2 response: the blast radius, and nothing changed."""
    if radius["blockers"] or radius["unmeasured"]:
        hint = ("Nothing was deleted. confirm=True will be refused until the blockers "
                "are cleared and every field is measured; show blast_radius to the user.")
    else:
        hint = ("Nothing was deleted. Show blast_radius to the user; to delete, call again "
                "with confirm=True once they have decided.")
    return {"action": "preview", "blast_radius": radius, "hint": hint}


def _policy_identity(client: NsxClient, policy_id: str, unmeasured: list[str]) -> dict:
    policy = _read(lambda: client.get(f"{_DFW_BASE}/{policy_id}"))
    if policy is _UNMEASURED:
        unmeasured.append("policy")
        return {}
    return policy


# ---------------------------------------------------------------------------
# DFW policy
# ---------------------------------------------------------------------------


def dfw_policy_delete_blast_radius(client: NsxClient, policy_id: str) -> dict[str, Any]:
    """The policy's identity and category, and every rule still in it."""
    _validate_id(policy_id, "policy_id")
    unmeasured: list[str] = []
    policy = _policy_identity(client, policy_id, unmeasured)
    rules = _read(lambda: client.get_all(f"{_DFW_BASE}/{policy_id}/rules", limit=_WALK_LIMIT),
                  missing_raises=False)
    if rules is _UNMEASURED:
        unmeasured.append("rules")
        rules = None
    radius = {
        "policy_id": policy_id,
        "display_name": _s(policy.get("display_name")),
        "path": _s(policy.get("path")),
        "category": _s(policy.get("category")) or None,
        "sequence_number": policy.get("sequence_number"),
        "stateful": policy.get("stateful"),
        "rule_count": None if rules is None else len(rules),
        "rule_ids": [] if rules is None else [_s(r.get("id")) for r in rules][:MAX_LISTED],
    }
    blockers = [policy_refusal_message(policy_id)] if rules else []
    return _finish(radius, unmeasured, blockers)


# ---------------------------------------------------------------------------
# DFW rule
# ---------------------------------------------------------------------------


def dfw_rule_delete_blast_radius(client: NsxClient, policy_id: str, rule_id: str) -> dict[str, Any]:
    """The rule's parent policy and what the rule matches and does."""
    _validate_id(policy_id, "policy_id")
    _validate_id(rule_id, "rule_id")
    unmeasured: list[str] = []
    policy = _policy_identity(client, policy_id, unmeasured)
    rules = _read(lambda: client.get_all(f"{_DFW_BASE}/{policy_id}/rules", limit=_WALK_LIMIT),
                  missing_raises=False)
    rule: dict = {}
    if rules is _UNMEASURED:
        unmeasured.append("rule")
    else:
        found = next((r for r in rules if r.get("id") == rule_id), None)
        if found is None:
            raise ValueError(
                f"DFW rule '{rule_id}' is not in policy '{policy_id}'. Nothing was deleted. "
                f"Run list_dfw_rules on '{policy_id}' for the exact rule_id."
            )
        rule = found
    radius = {
        "policy_id": policy_id,
        "policy_display_name": _s(policy.get("display_name")),
        "policy_category": _s(policy.get("category")) or None,
        "rule_id": rule_id,
        "display_name": _s(rule.get("display_name")),
        "path": _s(rule.get("path")),
        "action": _s(rule.get("action")) or None,
        "sources": _paths(rule.get("source_groups")),
        "destinations": _paths(rule.get("destination_groups")),
        "services": _paths(rule.get("services")),
        "scope": _paths(rule.get("scope")),
        "direction": _s(rule.get("direction")) or None,
        "disabled": rule.get("disabled") if rule else None,
        "sequence_number": rule.get("sequence_number") if rule else None,
    }
    return _finish(radius, unmeasured, [])


# ---------------------------------------------------------------------------
# Security group
# ---------------------------------------------------------------------------


def group_delete_blast_radius(client: NsxClient, group_id: str) -> dict[str, Any]:
    """The group's identity and criteria, and every entity that references it."""
    _validate_id(group_id, "group_id")
    unmeasured: list[str] = []
    group = _read(lambda: client.get(f"{_GROUPS_BASE}/{group_id}"))
    if group is _UNMEASURED:
        unmeasured.append("group")
        group = {}
    refs = _read(lambda: find_group_references(client, group_id), missing_raises=False)
    if refs is _UNMEASURED:
        unmeasured.append("references")
        refs = None
    expression = group.get("expression")
    radius = {
        "group_id": group_id,
        "display_name": _s(group.get("display_name")),
        "path": _s(group.get("path")),
        "expression_count": len(expression) if isinstance(expression, list) else None,
        "reference_count": None if refs is None else len(refs),
        "references": [] if refs is None else refs[:MAX_LISTED],
    }
    blockers = [group_refusal_message(group_id, refs)] if refs else []
    return _finish(radius, unmeasured, blockers)
