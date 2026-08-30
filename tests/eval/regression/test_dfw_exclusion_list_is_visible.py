"""A VM on the DFW exclusion list is not protected by any DFW rule. Say so.

Real-hardware finding, 2026-08-30. On the test estate **ten of twelve fabric
VMs sat on the NSX distributed-firewall exclusion list** — vCenter, VCF
Operations and an NSX manager among them. Nothing in this skill, or in
VMware-NSX, could see that list at all.

The rules were real, the groups were real, and every answer this skill gave
about those ten hosts being micro-segmented was wrong. Not approximately wrong:
the DFW is not in their datapath. An operator auditing segmentation would have
read a correct listing of policies and drawn exactly the opposite conclusion
from the truth, for 83% of the fabric.

**The API contract here was verified against Broadcom's published NSX 9.1.0 API
reference, not written from memory** — 踩坑 #36 is what happened the last time
this family guessed at an API surface. Three things came out of that check and
all three shape the code:

* The Policy exclusion list is
  ``GET /policy/api/v1/infra/settings/firewall/security/exclude-list``, and its
  ``members`` is an **array of plain strings** — Group paths. It is not a list
  of VM references. Anything that wants VM names has to resolve the groups.
* ``?system_owned=true`` (``GetInternalFirewallExcludeList``) returns system
  *and* user members. Without it, NSX's own exclusions are invisible — and on
  a VCF estate the management VMs are exactly the interesting ones.
* The Manager API ``GET /api/v1/firewall/excludelist``, whose members *are* VM
  references, is on the **Removed Methods** page for NSX 9.1.0. It is the
  obvious endpoint and it does not exist on the target platform.

There is no single call that returns effective per-VM exclusion state; the
``?action=filter`` operation answers for one object per request. So the shape
used here is one GET for the list plus one paged member fetch per *excluded
group* — bounded by the size of the exclusion list (max 100 groups), never by
the number of VMs. 踩坑 #31 is a per-item request, and there is a test below
that fails if one appears.
"""

from __future__ import annotations

import ast
import pathlib
from unittest.mock import MagicMock

from vmware_nsx_security.ops import exclusion

_REPO = pathlib.Path(__file__).resolve().parents[3]
PKG = _REPO / "vmware_nsx_security"
assert PKG.is_dir(), f"package not found at {PKG} — the source scan would find nothing"

EXCLUDE_PATH = "/policy/api/v1/infra/settings/firewall/security/exclude-list"
GROUPS_BASE = "/policy/api/v1/infra/domains/default/groups"
MGMT_MEMBERS = f"{GROUPS_BASE}/mgmt-vms/members/virtual-machines"


def _client(
    *,
    members: list[str] | None = None,
    vms: dict[str, list[dict]] | None = None,
    groups: list[dict] | None = None,
    reject_system_owned: bool = False,
) -> MagicMock:
    """An NSX manager whose exclusion list holds ``members`` (group paths)."""
    members = ["/infra/domains/default/groups/mgmt-vms"] if members is None else members
    vms = {MGMT_MEMBERS: [{"id": "vm-1", "display_name": "vcenter-01"}]} if vms is None else vms
    if groups is None:
        groups = [{"id": "mgmt-vms", "display_name": "Management VMs", "path": p} for p in members]

    def get(path, params=None, **kwargs):
        if path == EXCLUDE_PATH:
            if params and params.get("system_owned") and reject_system_owned:
                raise ValueError("system_owned is not supported on this manager")
            return {"resource_type": "PolicyExcludeList", "members": list(members)}
        raise AssertionError(f"unexpected GET {path}")

    def get_all(path, params=None, **kwargs):
        if path == GROUPS_BASE:
            return list(groups)
        if path in vms:
            return list(vms[path])
        return []

    client = MagicMock()
    client.get.side_effect = get
    client.get_all.side_effect = get_all
    return client


# ---------------------------------------------------------------------------
# The list is visible at all
# ---------------------------------------------------------------------------


def test_the_exclusion_list_is_read_from_the_policy_endpoint():
    client = _client()
    result = exclusion.list_dfw_exclusions(client)

    called = [c.args[0] for c in client.get.call_args_list]
    assert EXCLUDE_PATH in called, f"the Policy exclusion endpoint was never called: {called}"
    assert result["items"], "the exclusion list came back empty for an estate that has one"
    row = result["items"][0]
    assert row["path"] == "/infra/domains/default/groups/mgmt-vms"
    assert row["display_name"] == "Management VMs"
    assert [vm["display_name"] for vm in row["virtual_machines"]] == ["vcenter-01"]


def test_system_owned_members_are_asked_for():
    """NSX's own exclusions are the ones an operator has not written down."""
    client = _client()
    exclusion.list_dfw_exclusions(client)
    params = [c.kwargs.get("params") or {} for c in client.get.call_args_list]
    assert any(p.get("system_owned") for p in params), (
        "system-owned members were never requested, so NSX's own exclusions stay invisible"
    )


def test_a_manager_that_rejects_system_owned_still_returns_the_user_list():
    """Degrade to the user-owned list and say which one answered."""
    client = _client(reject_system_owned=True)
    result = exclusion.list_dfw_exclusions(client)
    assert result["items"], "the fallback returned nothing"
    assert result["scope"] == "user", f"scope should say the narrower list answered, got {result['scope']!r}"


def test_the_result_is_the_family_envelope():
    from vmware_policy import ENVELOPE_KEYS

    result = exclusion.list_dfw_exclusions(_client())
    assert set(ENVELOPE_KEYS) <= set(result)
    assert result["next_offset"] is None
    assert result["truncated"] is False


def test_an_empty_exclusion_list_is_stated_not_implied():
    result = exclusion.list_dfw_exclusions(_client(members=[]))
    assert result["items"] == []
    assert result["total"] == 0
    assert result["truncated"] is False


# ---------------------------------------------------------------------------
# The index, and the N+1 the finding forbids
# ---------------------------------------------------------------------------


def test_resolving_the_index_costs_one_fetch_per_excluded_group_not_per_vm():
    """踩坑 #31. The cost must scale with the exclusion list, not the estate."""
    members = ["/infra/domains/default/groups/mgmt-vms"]
    many = [{"id": f"vm-{i}", "display_name": f"host-{i}"} for i in range(200)]
    client = _client(members=members, vms={MGMT_MEMBERS: many})

    index = exclusion.exclusion_index(client)

    member_fetches = [c.args[0] for c in client.get_all.call_args_list if "members/virtual-machines" in c.args[0]]
    assert len(member_fetches) == len(members), (
        f"{len(member_fetches)} member fetches for {len(members)} excluded group(s) "
        f"and 200 VMs — that is a per-item request"
    )
    assert index.covers("host-7") is True


def test_a_vm_is_matched_by_its_compute_id_when_the_names_differ():
    """The two views of a VM do not share an id, so several handles are matched.

    ``list_vm_tags`` reads the fabric API, whose VM carries an ``external_id``.
    The group-members endpoint returns ``RealizedVirtualMachine``, which has no
    such field — the vSphere identifier appears there inside ``compute_ids``
    (``instanceUuid:...``). Matching on ``display_name`` alone works right up
    until NSX's realized name is stale, and then it answers "not excluded" for
    a VM that is. Mutating the ``compute_ids`` branch away left every other
    test in this file green.
    """
    client = _client(
        vms={
            MGMT_MEMBERS: [
                {
                    "id": "vm-1",
                    "display_name": "stale-name-in-nsx",
                    "compute_ids": ["moIdOnHost:vm-11", "instanceUuid:uuid-web-01"],
                }
            ]
        }
    )
    index = exclusion.exclusion_index(client)

    assert index.covers("uuid-web-01") is True, "the compute id did not reach the index"
    assert index.covers("web-01") is False, "matching must not become a substring free-for-all"


def test_the_removed_manager_api_endpoint_is_not_used_anywhere():
    """``/api/v1/firewall/excludelist`` is on NSX 9.1.0's Removed Methods page.

    It is the endpoint whose members are VM references, so it is the one a
    reasonable person reaches for. It would 404 on the target platform.
    """
    sources = sorted(PKG.rglob("*.py"))
    assert sources, f"no sources under {PKG} — this gate would check nothing"
    offenders = [p for p in sources if "firewall/excludelist" in _code_strings(p)]
    assert not offenders, f"the removed Manager API exclusion endpoint is referenced in {offenders}"


def _code_strings(path: pathlib.Path) -> str:
    """Every string literal in the module except docstrings.

    A prose mention is not a call. ``exclusion.py``'s own module docstring says
    why this endpoint must not be used, and a gate that cannot tell that apart
    from a call would force the reason out of the code that needs it.
    """
    tree = ast.parse(path.read_text())
    docstrings = {
        node.body[0].value
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    return "\n".join(
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n not in docstrings
    )


# ---------------------------------------------------------------------------
# The tools that report protection state
# ---------------------------------------------------------------------------


def test_an_excluded_vm_is_reported_as_excluded_by_list_vm_tags():
    from vmware_nsx_security.ops import tags

    client = _client()
    client.get.side_effect = _fabric_and_exclusion(client, "vcenter-01", excluded_name="vcenter-01")
    result = tags.list_vm_tags(client, "vcenter-01")

    assert result["dfw_excluded"] is True
    assert "exclusion" in result["dfw_exclusion_note"].lower()


def test_a_vm_that_is_not_excluded_is_still_reported_as_covered():
    """The control. An honest report has to be able to say "no" as well."""
    from vmware_nsx_security.ops import tags

    client = _client()
    client.get.side_effect = _fabric_and_exclusion(client, "web-01", excluded_name="vcenter-01")
    result = tags.list_vm_tags(client, "web-01")

    assert result["dfw_excluded"] is False
    assert result["dfw_exclusion_note"] is None


def test_an_unreachable_exclusion_list_reports_unknown_never_not_excluded():
    """``None`` is not ``False``.

    A failed lookup that answers "not excluded" is the shape this whole finding
    is about, arriving by a different route: a confident wrong answer about
    whether a host is protected.
    """
    from vmware_nsx_security.ops import tags

    client = _client()
    client.get.side_effect = _fabric_and_exclusion(client, "web-01", exclusion_fails=True)
    result = tags.list_vm_tags(client, "web-01")

    assert result["dfw_excluded"] is None, "a lookup that failed must not answer False"
    assert result["dfw_exclusion_note"], "an unknown must say why it is unknown"


def test_a_group_whose_members_cannot_be_read_makes_the_index_partial():
    """A partially resolved index can prove membership but never absence.

    If one excluded group's members fail to fetch, a VM that was not matched
    might still be in that group. Answering ``False`` there is the same
    confident wrong answer about protection as never checking at all.
    """
    paths = [
        "/infra/domains/default/groups/mgmt-vms",
        "/infra/domains/default/groups/broken",
    ]
    client = _client(members=paths)

    def get_all(path, params=None, **kwargs):
        if path == GROUPS_BASE:
            return []
        if path == MGMT_MEMBERS:
            return [{"id": "vm-1", "display_name": "vcenter-01"}]
        raise ValueError("NSX GET returned HTTP 500.")

    client.get_all.side_effect = get_all
    index = exclusion.exclusion_index(client)

    assert index.covers("vcenter-01") is True, "a VM the resolved half proves excluded is still excluded"
    assert index.covers("web-01") is None, "absence cannot be proved from a partial index"
    assert index.error


def test_get_group_marks_the_group_and_its_members():
    from vmware_nsx_security.ops import security_group

    group_path = "/infra/domains/default/groups/mgmt-vms"
    client = MagicMock()

    def get(path, params=None, **kwargs):
        if path == EXCLUDE_PATH:
            return {"members": [group_path]}
        if path == f"{GROUPS_BASE}/mgmt-vms":
            return {"id": "mgmt-vms", "display_name": "Management VMs", "path": group_path, "expression": []}
        if path == f"{GROUPS_BASE}/mgmt-vms/members/virtual-machines":
            return {"results": [{"id": "vm-1", "display_name": "vcenter-01"}], "result_count": 1}
        raise AssertionError(f"unexpected GET {path}")

    def get_all(path, params=None, **kwargs):
        if path == GROUPS_BASE:
            return [{"id": "mgmt-vms", "display_name": "Management VMs", "path": group_path}]
        if path == f"{GROUPS_BASE}/mgmt-vms/members/virtual-machines":
            return [{"id": "vm-1", "display_name": "vcenter-01"}]
        return []

    client.get.side_effect = get
    client.get_all.side_effect = get_all

    result = security_group.get_group(client, "mgmt-vms")
    assert result["dfw_excluded"] is True, "a group on the exclusion list must say so"
    assert result["members"]["items"][0]["dfw_excluded"] is True
    assert result["members"]["items"][0]["id"] == "vm-1", (
        "RealizedVirtualMachine carries no external_id, so the member id must fall back to 'id'"
    )


def test_the_policy_listing_warns_when_anything_is_excluded():
    from vmware_nsx_security.ops import dfw_policy

    client = _client()

    def get(path, params=None, **kwargs):
        if path == EXCLUDE_PATH:
            return {"members": ["/infra/domains/default/groups/mgmt-vms"]}
        raise AssertionError(f"unexpected GET {path}")

    def get_all(path, params=None, **kwargs):
        return [{"id": "pol-1", "display_name": "App tier", "rule_count": 3}]

    client.get.side_effect = get
    client.get_all.side_effect = get_all

    result = dfw_policy.list_dfw_policies(client)
    assert result["exclusion_note"], "a listing of rules that do not apply to 10/12 hosts must say so"
    assert "exclusion" in result["exclusion_note"].lower()


def test_the_policy_listing_stays_quiet_when_nothing_is_excluded():
    """The control that stops the note becoming background noise."""
    from vmware_nsx_security.ops import dfw_policy

    client = MagicMock()
    client.get.side_effect = lambda path, params=None, **kw: {"members": []}
    client.get_all.side_effect = lambda path, params=None, **kw: [
        {"id": "pol-1", "display_name": "App tier", "rule_count": 3}
    ]

    result = dfw_policy.list_dfw_policies(client)
    assert "exclusion_note" not in result


def test_the_new_read_tool_writes_no_audit_row(monkeypatch):
    """A read must not start writing audit rows."""
    from vmware_nsx_security.mcp_server import _write_audit
    from vmware_nsx_security.mcp_server.tools import exclusion as tool

    recorded = MagicMock()
    monkeypatch.setattr(_write_audit, "_audit", recorded)
    monkeypatch.setattr(tool, "_get_connection", lambda target=None: _client())

    result = tool.list_dfw_exclusions()
    assert "error" not in result, f"the tool failed instead of reading: {result}"
    assert not recorded.log.called, "a read tool wrote an audit row"
    from vmware_nsx_security.mcp_server import server as srv

    assert "list_dfw_exclusions" not in srv._AUDITED_WRITES, (
        "a read tool was swept into the write audit"
    )


def test_the_tool_is_registered_and_declared_read_only():
    import asyncio

    from vmware_nsx_security.mcp_server.server import mcp

    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    assert "list_dfw_exclusions" in tools, "the exclusion list is still invisible over MCP"
    assert tools["list_dfw_exclusions"].annotations.readOnlyHint is True


# ---------------------------------------------------------------------------


def _fabric_and_exclusion(client, vm_name, *, excluded_name="vcenter-01", exclusion_fails=False):
    """A ``client.get`` serving both the fabric VM lookup and the exclusion list."""
    fabric = "/api/v1/fabric/virtual-machines"
    group_path = "/infra/domains/default/groups/mgmt-vms"

    def get(path, params=None, **kwargs):
        if path == fabric:
            return {"results": [{"external_id": f"uuid-{vm_name}", "display_name": vm_name, "tags": []}]}
        if path == EXCLUDE_PATH:
            if exclusion_fails:
                raise ValueError("exclusion list unavailable")
            return {"members": [group_path]}
        raise AssertionError(f"unexpected GET {path}")

    def get_all(path, params=None, **kwargs):
        if path == GROUPS_BASE:
            return [{"id": "mgmt-vms", "display_name": "Management VMs", "path": group_path}]
        if path == f"{GROUPS_BASE}/mgmt-vms/members/virtual-machines":
            return [{"id": "vm-1", "display_name": excluded_name}]
        return []

    client.get_all.side_effect = get_all
    return get

