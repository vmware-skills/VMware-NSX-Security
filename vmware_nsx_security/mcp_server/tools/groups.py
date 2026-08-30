"""MCP tools for NSX security groups (2 read, 2 write)."""

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
def list_groups(
    target: Optional[str] = None,
    name_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """[READ] List NSX security groups in the default domain.

    Returns the list envelope: 'items' holds each group's id, display_name,
    description and expression count; 'returned'/'limit'/'total'/
    'truncated'/'hint' say whether the page is the whole answer — never
    read a full page as complete, narrow with name_filter or page with
    offset. Then get_group for one group's criteria and effective members.

    Page with 'next_offset': pass the value back as 'offset' and stop when it
    is null. Do not loop on 'truncated' — that says this page is not the whole
    collection, which stays true on the last page of a walk.

    Args:
        target: Optional NSX Manager target from config.
        name_filter: Substring/glob match on group display_name.
        limit: Page size, 1..1000 (default 50). Not a way to ask for
            everything — 0 or negative is rejected.
        offset: Matched groups to skip, 0 or more. Pass the previous
            response's 'next_offset'.
    """
    try:
        from vmware_nsx_security.ops.security_group import list_groups as _fn

        client = _get_connection(target)
        return _fn(client, name_filter=name_filter, limit=limit, offset=offset)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_group(group_id: str, target: Optional[str] = None) -> dict:
    """[READ] Get details of a security group including membership criteria and effective members.

    Returns one group object: its expression rules, member_count (the group's
    real size), and members — an envelope holding at most the first 50
    effective VirtualMachine members, whose truncated flag says whether more
    were withheld. Report member_count as the size; counting members.items
    reports the sample instead. Use it once list_groups has narrowed to one
    id; membership is evaluated by NSX, so a tag written with apply_vm_tag may
    take seconds to appear.

    Args:
        group_id: Group identifier (e.g. 'web-tier-vms').
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import get_group as _fn

        client = _get_connection(target)
        return _fn(client, group_id)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(
    risk_level="medium",
    undo=lambda params, result: {
        "tool": "delete_group",
        "params": {"group_id": params.get("group_id"), "target": params.get("target")},
        "skill": "nsx_security",
        "note": "Inverse of create_group: delete the security group just created.",
    },
)
def create_group(
    group_id: str,
    display_name: str,
    description: str = "",
    tag_scope: Optional[str] = None,
    tag_value: Optional[str] = None,
    ip_addresses: Optional[list[str]] = None,
    segment_paths: Optional[list[str]] = None,
    target: Optional[str] = None,
) -> dict:
    """[WRITE] Create an NSX security group with optional membership criteria.

    Returns the created group dict (id, path, expression, ...). Criteria
    are ORed — NSX only permits AND between same-member-type Conditions:
    tag_scope/tag_value matches VMs carrying that tag, ip_addresses
    matches IPs or CIDRs, segment_paths every VM on those segments. Use it
    before create_dfw_rule, which references the group path; confirm
    members with get_group.

    Args:
        group_id: Unique id (alphanumerics, hyphens, underscores).
        display_name: Human-readable name.
        description: Optional description.
        tag_scope: NSX tag scope for membership (e.g. 'env').
        tag_value: NSX tag value for membership (e.g. 'production').
        ip_addresses: IP addresses or CIDRs (e.g. ['10.0.1.0/24']).
        segment_paths: NSX segment policy paths.
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import create_group as _fn

        client = _get_connection(target)
        result = _fn(
            client, group_id, display_name,
            description=description,
            tag_scope=tag_scope, tag_value=tag_value,
            ip_addresses=ip_addresses, segment_paths=segment_paths,
        )
        _audit.log(
            target=target or "default",
            operation="create_group",
            resource=group_id,
            parameters={"display_name": display_name},
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="create_group", resource=group_id,
            target=target, parameters={"display_name": display_name},
        )


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
@vmware_tool(risk_level="high")
def delete_group(group_id: str, target: Optional[str] = None) -> dict:
    """[WRITE] Delete an NSX security group.

    Returns {"status": "deleted", "message": ...}, else {"error", "hint"}.
    Use it once get_group shows the group is unwanted. Refuses if anything
    still references it (NSX's group-associations API covers DFW rules and
    policies, gateway firewall, nested groups, service insertion), and
    refuses if that check itself fails (fail-safe). When the refusal names
    a DFW rule, retarget it with update_dfw_rule or drop it with
    delete_dfw_rule first.

    Args:
        group_id: ID of the group to delete.
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.security_group import delete_group as _fn

        client = _get_connection(target)
        result = _fn(client, group_id)
        _audit.log(
            target=target or "default",
            operation="delete_group",
            resource=group_id,
            result="ok",
        )
        return result
    except Exception as e:
        return _write_error(
            e, operation="delete_group", resource=group_id,
            target=target,
        )
