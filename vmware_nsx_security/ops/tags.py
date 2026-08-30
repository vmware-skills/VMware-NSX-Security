"""VM NSX Tag management operations.

NSX Tags are key-value metadata labels applied to virtual machines.
They are used by security groups (Groups with Condition expressions)
to dynamically include or exclude VMs from firewall policies.

APIs used:
  GET  /api/v1/fabric/virtual-machines?display_name=<name>
  POST /api/v1/fabric/virtual-machines?action=add_tags
  POST /api/v1/fabric/virtual-machines?action=remove_tags

Note: these Manager (MP) API endpoints are deprecated in NSX 3.x/4.x but
remain functional. The Policy API successor is
POST /policy/api/v1/infra/realized-state/enforcement-points/<ep>/virtual-machines?action=update_tags.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from vmware_policy import paginated, sanitize

from vmware_nsx_security.ops.exclusion import exclusion_index

if TYPE_CHECKING:
    from vmware_nsx_security.connection import NsxClient

_log = logging.getLogger("vmware-nsx-security.tags")


# ---------------------------------------------------------------------------
# VM tag list
# ---------------------------------------------------------------------------


def list_vm_tags(client: NsxClient, vm_display_name: str) -> dict:
    """List all NSX tags currently applied to a virtual machine.

    Looks up the VM by display name and returns all scope/value tag pairs.

    Args:
        client: Authenticated NsxClient instance.
        vm_display_name: Display name of the virtual machine to query.

    Returns:
        The family list envelope; ``items`` holds the VM's tag dicts (each
        with 'scope' and 'tag' fields), alongside the extras 'vm_id',
        'display_name' and 'power_state' naming the VM they belong to.

        ``dfw_excluded`` says whether this VM is on the NSX distributed-firewall
        exclusion list: ``True`` means **no DFW rule applies to it**, whatever
        tags it carries and whatever groups those tags put it in.
        ``False`` means it is not excluded. ``None`` means the exclusion list
        could not be read — which is not the same as ``False``, and
        ``dfw_exclusion_note`` says which of the three it is.

        The fabric API returns a VM's tags in full, in one response, so the
        set is never paged: ``limit`` is None, ``total`` equals ``returned``,
        and ``truncated`` is always False. That is the honest reading — a
        short tag list here means the VM really has that many tags, not that
        the listing stopped early.

    .. deprecated:: 1.8.6
       ``tags`` is a compatibility alias for ``items`` and will be removed in
       2.0. Until v1.8.0 this function returned
       ``{vm_id, display_name, power_state, tags}``; the envelope renamed
       ``tags`` to ``items``, and because the payload was already a keyed dict
       the break was silent — ``result.get("tags", [])`` started returning
       ``[]``, which reads as "this VM is untagged" rather than as a failure,
       and an untagged VM is exactly what a microsegmentation check is looking
       for. Both keys are the *same* list object, so they cannot drift.
       Migrate to ``items``.

    Raises:
        KeyError: If no VM with that display name is found.
        ValueError: If multiple VMs share the same display name.
    """
    safe_name = sanitize(vm_display_name)
    data = client.get(
        "/api/v1/fabric/virtual-machines",
        params={"display_name": safe_name},
    )
    vms = data.get("results", [])

    if not vms:
        raise KeyError(
            "No such VM in the NSX fabric inventory. The name must match "
            "the vCenter VM name exactly (case-sensitive, no "
            "wildcards). Run vmware-monitor's list_virtual_machines to copy "
            f"an exact VM name, then retry. Got: '{safe_name}'"
        )
    if len(vms) > 1:
        # The match list comes from NSX and is unbounded — and every entry
        # normally repeats the same display_name, so six duplicates pushed this
        # message to 784 and ``sanitize``'s 300-char cap deleted "or
        # remove_vm_tag directly" along with the list itself. De-duplicate,
        # bound it, and put both interpolations after the remedy.
        names = sorted({v.get("display_name", "") for v in vms})
        shown = ", ".join(names[:3])
        more = f" (+{len(names) - 3} more)" if len(names) > 3 else ""
        raise ValueError(
            f"{len(vms)} VMs in the NSX fabric share this display_name, so NSX "
            "cannot resolve the tag owner. Run vmware-monitor's "
            "list_virtual_machines to get the intended VM's instance UUID, then "
            "pass that UUID as vm_id to apply_vm_tag or remove_vm_tag directly. "
            f"Name: '{safe_name}'. Matches: {shown}{more}"
        )

    vm = vms[0]
    tags = vm.get("tags", [])
    # Tags are how this VM gets into groups, and groups are how DFW rules reach
    # it — but none of that happens at all if the VM is on the DFW exclusion
    # list. Answering "here are its tags" without saying so is the answer that
    # was wrong for ten of twelve hosts on the 2026-08-30 estate. One list GET
    # plus one member fetch per excluded group; nothing per VM (踩坑 #31).
    index = exclusion_index(client)
    excluded = index.covers(
        vm.get("display_name"), vm.get("external_id"), vm.get("uuid")
    )
    envelope = paginated(
        tags,
        limit=None,
        total=len(tags),
        vm_id=sanitize(vm.get("external_id", "")),
        display_name=sanitize(vm.get("display_name", "")),
        power_state=vm.get("power_state", ""),
        dfw_excluded=excluded,
        dfw_exclusion_note=index.note_for(excluded),
    )
    # Deprecated alias for pre-v1.8.0 callers; removed in 2.0. Same list object
    # as ``items`` — a copy would let the two drift.
    return {**envelope, "tags": envelope["items"]}


# ---------------------------------------------------------------------------
# Apply / remove VM tag
# ---------------------------------------------------------------------------


def apply_vm_tag(
    client: NsxClient,
    vm_id: str,
    tag_scope: str,
    tag_value: str,
) -> dict:
    """Apply an NSX tag to a virtual machine.

    Uses POST /api/v1/fabric/virtual-machines?action=add_tags with body
    {"external_id", "tags"} (returns 204 No Content). The tag is added
    non-destructively — existing tags on the VM are preserved.

    Args:
        client: Authenticated NsxClient instance.
        vm_id: VM external ID (fabric ID, not display name).
        tag_scope: Tag scope string (e.g. 'env', 'tier', 'owner').
        tag_value: Tag value string (e.g. 'production', 'web').

    Returns:
        Dict with 'status', 'vm_id', 'scope', and 'tag' keys.
    """
    body: dict[str, Any] = {
        "external_id": vm_id,
        "tags": [
            {
                "scope": sanitize(tag_scope),
                "tag": sanitize(tag_value),
            }
        ],
    }
    client.post("/api/v1/fabric/virtual-machines?action=add_tags", body)
    _log.info("Applied tag %s=%s to VM %s", tag_scope, tag_value, vm_id)
    return {
        "status": "applied",
        "vm_id": vm_id,
        "scope": tag_scope,
        "tag": tag_value,
    }


def remove_vm_tag(
    client: NsxClient,
    vm_id: str,
    tag_scope: str,
    tag_value: str,
) -> dict:
    """Remove an NSX tag from a virtual machine.

    Uses POST /api/v1/fabric/virtual-machines?action=remove_tags with body
    {"external_id", "tags"} (returns 204 No Content).

    Args:
        client: Authenticated NsxClient instance.
        vm_id: VM external ID (fabric ID, not display name).
        tag_scope: Tag scope string to remove.
        tag_value: Tag value string to remove.

    Returns:
        Dict with 'status', 'vm_id', 'scope', and 'tag' keys.
    """
    body: dict[str, Any] = {
        "external_id": vm_id,
        "tags": [
            {
                "scope": sanitize(tag_scope),
                "tag": sanitize(tag_value),
            }
        ],
    }
    client.post("/api/v1/fabric/virtual-machines?action=remove_tags", body)
    _log.info("Removed tag %s=%s from VM %s", tag_scope, tag_value, vm_id)
    return {
        "status": "removed",
        "vm_id": vm_id,
        "scope": tag_scope,
        "tag": tag_value,
    }
