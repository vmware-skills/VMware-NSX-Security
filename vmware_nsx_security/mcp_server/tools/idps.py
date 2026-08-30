"""MCP tools for NSX IDPS status (2 read)."""

from typing import Optional

from vmware_policy import vmware_tool

from vmware_nsx_security.mcp_server._shared import _DOCTOR_HINT, _get_connection, _safe_error, mcp


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def list_idps_profiles(
    target: Optional[str] = None,
    name_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """[READ] List IDPS profiles configured in NSX.

    Returns the list envelope: 'items' holds each profile's id,
    display_name, profile_severity (comma-joined), criteria
    (filter_name/filter_value pairs, e.g. ATTACK_TYPE or CVSS) and
    overridden signature count; 'returned'/'limit'/'total'/'truncated'/
    'hint' say whether the page is the whole answer — never read a full
    page as complete, narrow with name_filter or page with offset.
    Then get_idps_status for the signature-bundle version and IDS settings.

    Page with 'next_offset': pass the value back as 'offset' and stop when it
    is null. Do not loop on 'truncated' — that says this page is not the whole
    collection, which stays true on the last page of a walk.

    Args:
        target: Optional NSX Manager target from config.
        name_filter: Substring/glob match on profile display_name.
        limit: Page size, 1..1000 (default 50). Not a way to ask for
            everything — 0 or negative is rejected.
        offset: Matched profiles to skip, 0 or more. Pass the previous
            response's 'next_offset'.
    """
    try:
        from vmware_nsx_security.ops.idps import list_idps_profiles as _fn

        client = _get_connection(target)
        return _fn(client, name_filter=name_filter, limit=limit, offset=offset)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}


@mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@vmware_tool(risk_level="low")
def get_idps_status(target: Optional[str] = None) -> dict:
    """[READ] Get IDPS signature status and global IDS settings.

    Returns one bundle, not an envelope: 'signature_status' (scalar fields
    of the signature bundle status, e.g. version/update state — names vary
    by NSX release) and 'settings' (auto_update, ids_events_to_syslog).
    Use it first to confirm IDS is on and current, then list_idps_profiles
    for the profiles. No per-signature or per-event detail, and
    'signature_status' may be empty where IDS was never enabled.

    Args:
        target: Optional NSX Manager target from config.
    """
    try:
        from vmware_nsx_security.ops.idps import get_idps_status as _fn

        client = _get_connection(target)
        return _fn(client)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}
