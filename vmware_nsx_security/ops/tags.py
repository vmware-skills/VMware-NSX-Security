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

        The fabric API returns a VM's tags in full, in one response, so the
        set is never paged: ``limit`` is None, ``total`` equals ``returned``,
        and ``truncated`` is always False. That is the honest reading — a
        short tag list here means the VM really has that many tags, not that
        the listing stopped early.

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
        names = [v.get("display_name", "") for v in vms]
        raise ValueError(
            f"Multiple VMs share display_name='{safe_name}' — NSX cannot "
            "resolve the tag owner from an ambiguous name. Run "
            "vmware-monitor's list_virtual_machines to identify the intended "
            "VM's instance UUID, then pass that UUID as vm_id to apply_vm_tag "
            f"or remove_vm_tag directly. Matches: {names}"
        )

    vm = vms[0]
    tags = vm.get("tags", [])
    return paginated(
        tags,
        limit=None,
        total=len(tags),
        vm_id=sanitize(vm.get("external_id", "")),
        display_name=sanitize(vm.get("display_name", "")),
        power_state=vm.get("power_state", ""),
    )


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
