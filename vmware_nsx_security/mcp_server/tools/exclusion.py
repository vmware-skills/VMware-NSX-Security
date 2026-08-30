"""MCP tool for the DFW exclusion list (1 read)."""

from typing import Optional

from vmware_policy import vmware_tool

from vmware_nsx_security.mcp_server._shared import (
    _DOCTOR_HINT,
    _get_connection,
    _safe_error,
    mcp,
)


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_dfw_exclusions(
    target: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """[READ] List the DFW exclusion list — the members no distributed-firewall rule reaches.

    Read this before answering any question about a VM being micro-segmented
    or protected by DFW policy. A VM on this list has no DFW in its datapath:
    rules that name it, groups that contain it and policies scoped to it all
    still exist and none of them apply. On a VCF estate the management VMs
    (vCenter, VCF Operations, NSX managers) are commonly on it.

    Returns the list envelope. 'items' holds one row per excluded member: the
    group 'path', its 'id' and 'display_name', the 'virtual_machines' in it and
    'vm_count'. A row with 'members_error' is a group whose members could not
    be read — that is not an empty group, so do not read it as one.

    'scope' says which list answered: "system_and_user" includes NSX's own
    system-owned exclusions, "user" means this manager refused that variant and
    system exclusions are NOT in the answer. An empty list under "user" is not
    proof that nothing is excluded.

    Page with 'next_offset': pass the value back as 'offset' and stop when it
    is null. The list holds at most 100 groups, so one page is normally all of
    it.

    Args:
        target: Optional NSX Manager target from config.
        limit: Page size, 1..1000 (default 50). Not a way to ask for
            everything — 0 or negative is rejected.
        offset: Excluded members to skip, 0 or more. Pass the previous
            response's 'next_offset'.
    """
    try:
        from vmware_nsx_security.ops.exclusion import list_dfw_exclusions as _fn

        client = _get_connection(target)
        return _fn(client, limit=limit, offset=offset)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}
