"""The DFW exclusion list: which members the distributed firewall does not see.

A VM on the NSX distributed-firewall exclusion list has no DFW in its datapath.
Rules that name it, groups that contain it, policies that scope to it — none of
them apply. On the 2026-08-30 test estate ten of twelve fabric VMs were on that
list, vCenter and VCF Operations and an NSX manager among them, and neither this
skill nor VMware-NSX could see the list at all. Every answer either gave about
those hosts being micro-segmented was confidently, exactly wrong.

API contract
------------
Verified against Broadcom's published NSX 9.1.0 API reference rather than
written from memory (踩坑 #36):

``GET /policy/api/v1/infra/settings/firewall/security/exclude-list``
    Returns ``PolicyExcludeList``. Its ``members`` is an **array of plain
    strings** — Group paths, at most 100. It is *not* a list of VM references,
    so nothing here can name a VM without resolving the groups.

``?system_owned=true`` (``GetInternalFirewallExcludeList``)
    The same object including NSX's own system-owned members. Those are the
    exclusions no operator wrote down, which on a VCF estate is precisely where
    the management VMs are. Asked for first, with a fallback to the plain GET
    for a manager that refuses the parameter — and the answer says which of the
    two replied, because "no system exclusions" and "never asked" must not look
    alike.

``GET /policy/api/v1/infra/domains/<domain>/groups/<group>/members/virtual-machines``
    ``RealizedVirtualMachineListResult`` — a paged ``results`` list. The element
    type carries ``id``, ``display_name``, ``power_state`` and ``compute_ids``;
    it has **no** ``external_id``, which is why identity here is matched on
    several keys rather than one.

``GET /api/v1/firewall/excludelist``
    The Manager API equivalent, whose members *are* VM references. It is on the
    **Removed Methods** page for NSX 9.1.0 and would 404 on the target platform.
    It is the obvious endpoint and it must not be used; a test enforces that.

Cost
----
There is no single call returning effective per-VM exclusion state. The
``?action=filter`` operation answers for one object per request, which is a
per-item round trip and exactly what 踩坑 #31 forbids. So the shape is one GET
for the list plus one paged member fetch **per excluded group** — bounded by the
exclusion list (≤100 groups), never by the number of VMs in the estate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from vmware_policy import sanitize

from vmware_nsx_security.ops._paginate import DEFAULT_LIMIT, page_envelope, paginate, validate_page_args

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.exclusion")

EXCLUDE_LIST_PATH = "/policy/api/v1/infra/settings/firewall/security/exclude-list"
_GROUPS_BASE = "/policy/api/v1/infra/domains/default/groups"

#: What a caller should be told to do about an exclusion, once one is found.
_REMEDY = (
    "Run list_dfw_exclusions to see the whole list and which groups put them there."
)


@dataclass(frozen=True)
class ExcludedGroups:
    """The exclusion list as the manager reported it.

    ``scope`` is ``"system_and_user"`` when the system-owned variant answered
    and ``"user"`` when only the plain GET did — an empty list means different
    things under the two, and collapsing them would hide every NSX-owned
    exclusion behind a confident "nothing is excluded".
    """

    paths: tuple[str, ...]
    scope: str
    error: str | None = None


@dataclass(frozen=True)
class ExclusionIndex:
    """Which VMs the DFW does not see, and whether that could be established.

    ``identifiers`` holds every lowercased handle by which an excluded VM might
    be named — ``display_name``, ``id``, ``external_id`` where a build supplies
    one, and the value half of each ``compute_ids`` entry (``uuid:...``,
    ``instanceUuid:...``). One key would not do: the fabric API that
    ``list_vm_tags`` queries returns an ``external_id`` the Policy realized-VM
    schema does not define, so the two views of the same VM overlap on
    ``display_name`` and on the compute identifiers, not on a single id.
    """

    identifiers: frozenset[str]
    group_paths: frozenset[str]
    scope: str
    error: str | None = None

    def covers(self, *candidates: str | None) -> bool | None:
        """``True`` if any candidate names an excluded VM, ``False`` if none
        does, ``None`` if that could not be established.

        ``None`` is not ``False``, and the distinction is the whole point. A
        lookup that failed and answered "not excluded" would be a confident
        wrong answer about whether a host is protected — the same defect this
        module exists to remove, arriving by a different route.
        """
        for candidate in candidates:
            if candidate and str(candidate).strip().lower() in self.identifiers:
                return True
        return None if self.error else False

    def note_for(self, excluded: bool | None) -> str | None:
        """The sentence to put beside a verdict, or ``None`` when there is none."""
        if excluded is True:
            return (
                "This VM is on the NSX distributed-firewall exclusion list: no DFW "
                "rule applies to it, whatever policies and groups name it. " + _REMEDY
            )
        if excluded is None:
            return (
                "DFW exclusion state is UNKNOWN, not false: the exclusion list could "
                f"not be read ({self.error}). Do not report this VM as protected by "
                "DFW policy until list_dfw_exclusions succeeds."
            )
        return None


def _group_id_from(path: str) -> tuple[str, str] | None:
    """``(domain, group_id)`` for a Policy group path, or ``None``.

    Members can name objects outside ``/infra/domains/<d>/groups/<g>`` — a
    ``/global-infra`` or project-scoped path, for instance. Returning ``None``
    lets the caller record the path without pretending it resolved it.
    """
    parts = [p for p in str(path).split("/") if p]
    if len(parts) >= 5 and parts[-4] == "domains" and parts[-2] == "groups":
        return parts[-3], parts[-1]
    return None


def excluded_groups(client: NsxClient) -> ExcludedGroups:
    """Read the exclusion list. One GET, system-owned members included."""
    try:
        payload = client.get(EXCLUDE_LIST_PATH, params={"system_owned": "true"})
        scope = "system_and_user"
    except Exception as exc:  # the parameter is refused by some managers
        _log.info("system_owned exclusion list unavailable (%s); falling back", exc)
        try:
            payload = client.get(EXCLUDE_LIST_PATH)
            scope = "user"
        except Exception as inner:
            return ExcludedGroups(paths=(), scope="unknown", error=sanitize(str(inner), 200))

    members = payload.get("members") or []
    # The schema says strings. Anything else is a manager this code has not
    # seen; keep what is string-shaped rather than crashing a read.
    paths = tuple(sanitize(m, 300) for m in members if isinstance(m, str))
    return ExcludedGroups(paths=paths, scope=scope)


def _vm_identifiers(vm: dict) -> set[str]:
    """Every lowercased handle by which ``vm`` might be named elsewhere."""
    handles: set[str] = set()
    for key in ("display_name", "id", "external_id"):
        value = vm.get(key)
        if value:
            handles.add(str(value).strip().lower())
    for compute_id in vm.get("compute_ids") or []:
        text = str(compute_id)
        # Documented format is 'id-type-key:value' (e.g. 'instanceUuid:xxxx').
        handles.add(text.split(":", 1)[-1].strip().lower())
    return handles


def _members_of(client: NsxClient, path: str) -> tuple[list[dict], str | None]:
    """The VMs in the group at ``path``, and why they could not be read."""
    resolved = _group_id_from(path)
    if resolved is None:
        return [], f"'{path}' is not a default-domain group path"
    domain, group_id = resolved
    try:
        members = client.get_all(
            f"/policy/api/v1/infra/domains/{domain}/groups/{group_id}/members/virtual-machines"
        )
    except Exception as exc:
        return [], sanitize(str(exc), 200)
    return [m for m in members if isinstance(m, dict)], None


def exclusion_index(client: NsxClient) -> ExclusionIndex:
    """Resolve the exclusion list to the VMs it covers.

    One GET plus one paged member fetch per excluded group. A group whose
    members cannot be read leaves ``error`` set, so a VM that was *not* matched
    reports unknown rather than "not excluded" — a partially resolved index can
    prove membership but never absence.
    """
    listed = excluded_groups(client)
    if listed.error:
        return ExclusionIndex(
            identifiers=frozenset(), group_paths=frozenset(), scope=listed.scope, error=listed.error
        )

    identifiers: set[str] = set()
    failures: list[str] = []
    for path in listed.paths:
        members, error = _members_of(client, path)
        if error:
            failures.append(error)
            continue
        for vm in members:
            identifiers |= _vm_identifiers(vm)

    return ExclusionIndex(
        identifiers=frozenset(identifiers),
        group_paths=frozenset(listed.paths),
        scope=listed.scope,
        error="; ".join(failures) if failures else None,
    )


def policy_exclusion_note(client: NsxClient) -> str | None:
    """One sentence for a DFW listing, or ``None`` when nothing is excluded.

    Costs the single exclusion-list GET and no member resolution: a listing of
    policies only has to say that an exclusion list exists and is not empty, and
    the group members behind it are ``list_dfw_exclusions``'s job. Silent when
    the list is empty, so the note stays a signal rather than boilerplate every
    listing carries.
    """
    listed = excluded_groups(client)
    if listed.error:
        return (
            "The DFW exclusion list could not be read "
            f"({listed.error}), so it is unknown whether these rules reach every "
            "member they name. Retry list_dfw_exclusions before reporting on "
            "segmentation coverage."
        )
    if not listed.paths:
        return None
    count = len(listed.paths)
    plural = "" if count == 1 else "s"
    return (
        f"{count} group{plural} sit on the NSX distributed-firewall exclusion list. "
        "These rules do not apply to their members, however they are named here — "
        "do not read this listing as proof those VMs are micro-segmented. " + _REMEDY
    )


def list_dfw_exclusions(
    client: NsxClient,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict:
    """List the DFW exclusion list, resolved to the VMs it takes out of the DFW.

    Args:
        client: Authenticated NsxClient instance.
        limit: Page size — an integer from 1 to 1000 (default 50). The list
            holds at most 100 groups, so one page is normally the whole thing.
        offset: Groups to skip. 0 or more; pass the previous response's
            ``next_offset``.

    Returns:
        The family list envelope plus ``next_offset`` and a ``scope`` extra.
        ``items`` holds one row per excluded member: its ``path``, the group
        ``id`` and ``display_name`` where the path resolves to a default-domain
        group, the ``virtual_machines`` in it, and ``vm_count``. A row whose
        members could not be read carries ``members_error`` and an empty
        ``virtual_machines`` — an unreadable group is not an empty one.

        ``scope`` is ``"system_and_user"`` when NSX's own exclusions are
        included and ``"user"`` when the manager refused that variant, so an
        empty list can be read for what it is.
    """
    validate_page_args(limit, offset)
    listed = excluded_groups(client)
    if listed.error:
        raise ConnectionError(
            f"Could not read the DFW exclusion list from {EXCLUDE_LIST_PATH}: "
            f"{listed.error}. Until it can be read, do not report any VM as "
            "protected by DFW policy — an excluded VM has no DFW in its datapath. "
            "Run 'vmware-nsx-security doctor' to check connectivity and that the "
            "account has the policy_dfw read permission."
        )

    names = _group_names(client)
    rows: list[dict[str, Any]] = []
    for path in paginate([{"path": p} for p in listed.paths], limit, offset):
        rows.append(_exclusion_row(client, path["path"], names))

    return page_envelope(
        rows,
        limit=limit,
        offset=offset,
        total=len(listed.paths),
        scope=listed.scope,
    )


def _group_names(client: NsxClient) -> dict[str, str]:
    """``path -> display_name`` for the default domain's groups.

    One listing rather than a GET per excluded group: the exclusion list is
    small but the rule against per-item fetches is not conditional on that.
    A failure here costs display names, not the answer, so it is swallowed.
    """
    try:
        return {
            sanitize(g.get("path", "")): sanitize(g.get("display_name", ""))
            for g in client.get_all(_GROUPS_BASE)
            if g.get("path")
        }
    except Exception as exc:
        _log.warning("Could not list groups to name exclusion members: %s", exc)
        return {}


def _exclusion_row(client: NsxClient, path: str, names: dict[str, str]) -> dict[str, Any]:
    resolved = _group_id_from(path)
    row: dict[str, Any] = {
        "path": path,
        "id": resolved[1] if resolved else None,
        "display_name": names.get(path) or None,
        "virtual_machines": [],
        "vm_count": None,
    }
    members, error = _members_of(client, path)
    if error:
        row["members_error"] = error
        return row
    row["virtual_machines"] = [
        {
            "id": sanitize(m.get("external_id") or m.get("id", "")),
            "display_name": sanitize(m.get("display_name", "")),
            "power_state": m.get("power_state", ""),
        }
        for m in members
    ]
    row["vm_count"] = len(members)
    return row
