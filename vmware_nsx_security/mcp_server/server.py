"""MCP server wrapping VMware NSX Security operations.

This module is the thin entrypoint: it imports ``vmware_nsx_security.mcp_server.tools`` (which
registers all 22 ``@mcp.tool()`` functions onto the shared ``mcp`` instance),
re-exports the tool functions and shared plumbing for direct import, and
exposes ``main()`` as the ``vmware-nsx-security-mcp`` console entry point.
The per-tool bodies now live in ``mcp_server/tools/*.py`` grouped by domain;
the shared connection/audit/error helpers live in ``mcp_server/_shared.py``.

Tool categories
---------------
* **Read-only** (no side effects): list_dfw_policies, get_dfw_policy,
  list_dfw_rules, list_groups, get_group, list_vm_tags,
  get_traceflow_result, list_idps_profiles, get_idps_status,
  get_dfw_rule_stats, list_dfw_exclusions

* **Write** (mutate state): create_dfw_policy, update_dfw_policy,
  delete_dfw_policy, create_dfw_rule, update_dfw_rule, delete_dfw_rule,
  create_group, delete_group, apply_vm_tag, remove_vm_tag, run_traceflow
  — should be gated by the AI agent's confirmation flow.

Security considerations
-----------------------
* **Credential handling**: Credentials are loaded from environment
  variables / ``.env`` file — never passed via MCP messages.
* **Transport**: Uses stdio transport (local only); no network listener.
* **Destructive ops**: Delete operations check for active references
  before proceeding and raise ValueError if unsafe.

For NSX networking (segments, gateways, NAT) use vmware-nsx.
For VM operations use vmware-aiops.
"""

import logging

from vmware_policy import describe_tool_parameters

# Importing the tools package executes every @mcp.tool() decorator and
# registers all 22 tools onto the shared `mcp` instance.
import vmware_nsx_security.mcp_server.tools  # noqa: F401
from vmware_nsx_security.mcp_server._shared import (  # noqa: F401
    _DOCTOR_HINT,
    _get_connection,
    _safe_error,
    _write_error,
    logger,
    mcp,
)
from vmware_nsx_security.mcp_server._write_audit import install_write_audit

# Give every registered write tool this skill's own audit log, derived from the
# readOnlyHint each tool already declares. Must run BEFORE the re-exports below,
# so the names published here are the audited callables and not a second,
# unaudited copy of each tool.
_AUDITED_WRITES = install_write_audit(mcp)

# Re-export the tool functions so `from vmware_nsx_security.mcp_server.server import apply_vm_tag`
# and similar direct imports keep working after the domain split.
from vmware_nsx_security.mcp_server.tools.dfw_policy import (  # noqa: F401
    create_dfw_policy,
    delete_dfw_policy,
    get_dfw_policy,
    list_dfw_policies,
    update_dfw_policy,
)
from vmware_nsx_security.mcp_server.tools.dfw_rules import (  # noqa: F401
    create_dfw_rule,
    delete_dfw_rule,
    get_dfw_rule_stats,
    list_dfw_rules,
    update_dfw_rule,
)
from vmware_nsx_security.mcp_server.tools.exclusion import (  # noqa: F401
    list_dfw_exclusions,
)
from vmware_nsx_security.mcp_server.tools.groups import (  # noqa: F401
    create_group,
    delete_group,
    get_group,
    list_groups,
)
from vmware_nsx_security.mcp_server.tools.idps import (  # noqa: F401
    get_idps_status,
    list_idps_profiles,
)
from vmware_nsx_security.mcp_server.tools.tags import (  # noqa: F401
    apply_vm_tag,
    list_vm_tags,
    remove_vm_tag,
)
from vmware_nsx_security.mcp_server.tools.traceflow import (  # noqa: F401
    get_traceflow_result,
    run_traceflow,
)

# ---------------------------------------------------------------------------
# Environment declaration
# ---------------------------------------------------------------------------
# The environment resolver lives in policy_environment so the CLI registers
# it too (its @guarded writes go through the same guard()); importing it here
# registers it for the MCP surface.
from vmware_nsx_security.policy_environment import _cached_config, _environment_for  # noqa: F401 — imported to register the resolver, and re-exported

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server using stdio transport."""
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()

# The docstrings above are the schema. `describe_tool_parameters` copies each
# `Args:` entry into the JSON schema an agent actually reads, and closes the
# object. Without it every parameter reaches the model as a bare name and a
# type, which is how a wrong guess becomes an unfiltered result or a silent
# zero-row answer instead of an error (real-hardware round, 2026-08-30).
_DESCRIBED_PARAMS = describe_tool_parameters(mcp._tool_manager._tools)
