"""MCP tool modules grouped by NSX security domain.

Importing this package imports every tool module, which executes the
``@mcp.tool()`` decorators and registers all 22 tools (11 read, 11 write)
onto the shared ``mcp`` instance in ``vmware_nsx_security.mcp_server._shared``.
"""

from vmware_nsx_security.mcp_server.tools import (  # noqa: F401
    dfw_policy,
    dfw_rules,
    exclusion,
    groups,
    idps,
    tags,
    traceflow,
)
