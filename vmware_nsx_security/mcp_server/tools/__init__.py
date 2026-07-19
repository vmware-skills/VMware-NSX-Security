"""MCP tool modules grouped by NSX security domain.

Importing this package imports every tool module, which executes the
``@mcp.tool()`` decorators and registers all 21 tools (10 read, 11 write)
onto the shared ``mcp`` instance in ``vmware_nsx_security.mcp_server._shared``.
"""

from vmware_nsx_security.mcp_server.tools import (  # noqa: F401
    dfw_policy,
    dfw_rules,
    groups,
    idps,
    tags,
    traceflow,
)
