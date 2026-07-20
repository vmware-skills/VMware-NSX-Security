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

    Returns the list envelope: 'items' holds the VM's scope/tag pairs, and
    'vm_id' carries the fabric UUID that apply_vm_tag and remove_vm_tag
    require — call this first to obtain it. A VM's tags always arrive in one
    response, so 'truncated' is always false and 'total' equals 'returned';
    an empty 'items' means the VM genuinely carries no tags. Returns
    {"error", "hint"} if no VM matches the name, or if several do.

    Args:
        vm_display_name: Exact vCenter display name of the virtual machine
            (case-sensitive, no wildcards). This skill does not enumerate
            VMs — run vmware-monitor's list_virtual_machines, or
            vmware-aiops', to obtain one.
        target: Optional NSX Manager target name from config.
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

    Existing tags on the VM are preserved — this operation is additive.
    Use list_vm_tags to get the vm_id (external_id) first.

    Args:
        vm_id: VM external ID (fabric UUID, obtainable from list_vm_tags).
        tag_scope: Tag scope string (e.g. 'env', 'tier', 'owner').
        tag_value: Tag value string (e.g. 'production', 'web').
        target: Optional NSX Manager target name from config.
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

    Only the exact scope/value pair is removed — other tags on the VM are
    preserved. Removing a tag can change dynamic security group membership
    immediately (groups with tag Conditions stop matching the VM). Use
    list_vm_tags first to confirm the exact scope and value.

    Args:
        vm_id: VM external ID (fabric UUID, obtainable from list_vm_tags).
        tag_scope: Tag scope string of the tag to remove (e.g. 'env').
        tag_value: Tag value string of the tag to remove (e.g. 'production').
        target: Optional NSX Manager target name from config.
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
