"""MCP tools for VM NSX tags (1 read, 2 write)."""

from typing import Optional

from vmware_policy import vmware_tool

from vmware_nsx_security.mcp_server._shared import (
    _DOCTOR_HINT,
    _audit,
    _get_connection,
    _safe_error,
    _write_error,
    mcp,
)


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_vm_tags(vm_display_name: str, target: Optional[str] = None) -> dict:
    """[READ] List all NSX tags applied to a virtual machine.

    Returns the list envelope: 'items' holds the VM's scope/tag pairs and
    'vm_id' the fabric UUID apply_vm_tag and remove_vm_tag require — call
    this first to get it. Tags always arrive in one response, so
    'truncated' is always false and empty 'items' means the VM really has
    no tags. Returns {"error", "hint"} if no VM matches, or several do.

    Args:
        vm_display_name: Exact vCenter display name (case-sensitive, no
            wildcards). This skill does not enumerate VMs — run
            vmware-monitor's list_virtual_machines to get one.
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.tags import list_vm_tags as _fn

        client = _get_connection(target)
        return _fn(client, vm_display_name)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(
    risk_level="medium",
    undo=lambda params, result: {
        "tool": "remove_vm_tag",
        "params": {
            "vm_id": params.get("vm_id"),
            "tag_scope": params.get("tag_scope"),
            "tag_value": params.get("tag_value"),
            "target": params.get("target"),
        },
        "skill": "nsx_security",
        "note": "Inverse of apply_vm_tag: remove the tag just applied.",
    },
)
def apply_vm_tag(
    vm_id: str,
    tag_scope: str,
    tag_value: str,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Apply an NSX tag to a virtual machine.

    Returns {"status": "applied", "vm_id", "scope", "tag"} — not the VM's
    tag list. Use list_vm_tags first for the vm_id, and again after to see
    the result. Additive, so existing tags survive, but note that
    tag-based group membership shifts as NSX re-evaluates: check with
    get_group.

    Args:
        vm_id: VM external ID (fabric UUID, from list_vm_tags).
        tag_scope: Tag scope (e.g. 'env', 'tier', 'owner').
        tag_value: Tag value (e.g. 'production', 'web').
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.tags import apply_vm_tag as _fn

        client = _get_connection(target)
        result = _fn(client, vm_id, tag_scope, tag_value)
        _audit.log(
            target=target or "default",
            operation="apply_vm_tag",
            resource=vm_id,
            parameters={"scope": tag_scope, "tag": tag_value},
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="apply_vm_tag", resource=vm_id,
            target=target, parameters={"scope": tag_scope, "tag": tag_value},
        )


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="medium")
def remove_vm_tag(
    vm_id: str,
    tag_scope: str,
    tag_value: str,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Remove an NSX tag from a virtual machine.

    Returns {"status": "removed", "vm_id", "scope", "tag"}, not the VM's
    remaining tags. Only the exact scope/value pair is removed — other
    tags survive. Removing a tag changes dynamic group membership
    immediately — groups with tag Conditions stop matching the VM — so
    re-check with get_group. Use list_vm_tags first to confirm the pair.

    Args:
        vm_id: VM external ID (fabric UUID, from list_vm_tags).
        tag_scope: Scope of the tag to remove (e.g. 'env').
        tag_value: Value of the tag to remove (e.g. 'production').
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.tags import remove_vm_tag as _fn

        client = _get_connection(target)
        result = _fn(client, vm_id, tag_scope, tag_value)
        _audit.log(
            target=target or "default",
            operation="remove_vm_tag",
            resource=vm_id,
            parameters={"scope": tag_scope, "tag": tag_value},
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="remove_vm_tag", resource=vm_id,
            target=target, parameters={"scope": tag_scope, "tag": tag_value},
        )
