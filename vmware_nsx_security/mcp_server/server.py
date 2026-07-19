"""MCP server wrapping VMware NSX Security operations.

This module is the thin entrypoint: it imports ``vmware_nsx_security.mcp_server.tools`` (which
registers all 21 ``@mcp.tool()`` functions onto the shared ``mcp`` instance),
re-exports the tool functions and shared plumbing for direct import, and
exposes ``main()`` as the ``vmware-nsx-security-mcp`` console entry point.
The per-tool bodies now live in ``mcp_server/tools/*.py`` grouped by domain;
the shared connection/audit/error helpers live in ``mcp_server/_shared.py``.

Tool categories
---------------
* **Read-only** (no side effects): list_dfw_policies, get_dfw_policy,
  list_dfw_rules, list_groups, get_group, list_vm_tags,
  get_traceflow_result, list_idps_profiles, get_idps_status,
  get_dfw_rule_stats

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
import os
from pathlib import Path
from typing import Optional

from vmware_policy import apply_read_only_gate, mtime_cached_loader, set_environment_resolver

from vmware_nsx_security.config import CONFIG_FILE, load_config

# Importing the tools package executes every @mcp.tool() decorator and
# registers all 21 tools onto the shared `mcp` instance.
import vmware_nsx_security.mcp_server.tools  # noqa: F401
from vmware_nsx_security.mcp_server._shared import (  # noqa: F401
    _DOCTOR_HINT,
    _audit,
    _get_connection,
    _safe_error,
    _write_error,
    logger,
    mcp,
)

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
# Read-only gate
# ---------------------------------------------------------------------------


def _config_read_only() -> Optional[bool]:
    """Best-effort read of ``read_only`` from the config file.

    Runs at import time, when no config file need exist yet (tests, ``--help``,
    smoke checks), so every failure degrades to "not configured" and lets the
    env vars decide. None and False are equivalent here — config is the last
    link in the precedence chain — but None keeps 'not configured'
    distinguishable from 'configured off' in logs and debugging.
    """
    try:
        config_path_str = os.environ.get("VMWARE_NSX_SECURITY_CONFIG")
        config_path = Path(config_path_str) if config_path_str else None
        return load_config(config_path).read_only
    except Exception:  # noqa: BLE001 — absent/unreadable config is not an error here
        return None


# Applied once, after every tool module above has registered. In read-only mode
# the write tools are removed from the registry, so list_tools() never offers
# them — the guarantee is structural rather than a prompt instruction the model
# may ignore (VMware-AIops issue #31).
WITHHELD_WRITE_TOOLS: list[str] = apply_read_only_gate(
    mcp, "vmware-nsx-security", config_flag=_config_read_only()
)


# ---------------------------------------------------------------------------
# Environment declaration
# ---------------------------------------------------------------------------


_cached_config = mtime_cached_loader("VMWARE_NSX_SECURITY_CONFIG", CONFIG_FILE, load_config)


def _environment_for(target: Optional[str]) -> str:
    """Report the environment a target declares, for policy scoping.

    Policy rules scope by environment ("irreversible work in production needs a
    second person"), and vmware-policy cannot read this skill's config itself.
    Registering this lookup is what lets those rules fire at all. Reloaded on
    config.yaml mtime change so an edit takes effect without restarting the
    server. The config is cached via :func:`vmware_policy.mtime_cached_loader`,
    so repeated tool calls pay one ``os.stat`` instead of a full YAML parse.
    """
    try:
        return _cached_config().environment_for(target)
    except Exception:  # noqa: BLE001 — an unreadable config means "undeclared"
        return ""


set_environment_resolver(_environment_for)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the MCP server using stdio transport."""
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
