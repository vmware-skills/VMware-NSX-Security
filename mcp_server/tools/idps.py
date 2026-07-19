"""MCP tools for NSX IDPS status (2 read)."""

from typing import Optional

from vmware_policy import vmware_tool

from mcp_server._shared import _DOCTOR_HINT, _get_connection, _safe_error, mcp


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
    display_name, profile_severity (comma-joined list), criteria
    (filter_name/filter_value pairs such as ATTACK_TYPE or CVSS filters),
    and overridden signature count, while 'returned'/'limit'/'total'/
    'truncated'/'hint' state whether the listing is complete. Defaults to
    the first 50 matches — use name_filter to narrow and offset to page on
    large estates. 'total' is the real profile count on an unfiltered
    listing and null when a name_filter is used.

    Args:
        target: Optional NSX Manager target name from config.
        name_filter: Optional substring/glob match on profile display_name.
        limit: Max profiles to return (default 50).
        offset: Number of matched profiles to skip (pagination).
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

    Returns 'signature_status' (scalar fields of the signature bundle
    status resource, e.g. version/update state — field names vary by NSX
    release) and 'settings' (auto_update, ids_events_to_syslog).

    Args:
        target: Optional NSX Manager target name from config.
    """
    try:
        from vmware_nsx_security.ops.idps import get_idps_status as _fn

        client = _get_connection(target)
        return _fn(client)
    except Exception as e:
        return {"error": _safe_error(e, "nsx-security"), "hint": _DOCTOR_HINT}
