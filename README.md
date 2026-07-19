<!-- mcp-name: io.github.zw008/vmware-nsx-security -->
# VMware NSX Security

> **Author**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com
> This is a community-driven project by a VMware engineer, not an official VMware product.
> For official VMware developer tools see [developer.broadcom.com](https://developer.broadcom.com).

VMware NSX DFW microsegmentation and security MCP skill — 21 tools for distributed firewall policies/rules, security groups, VM tags, Traceflow packet tracing, and IDPS.

- **Read-only mode** (v1.8.0) — one env var (`VMWARE_READ_ONLY=true`) strips all 11 write tools (DFW policy/rule writes, security groups, VM tags, Traceflow injection) from the MCP registry at startup, leaving the 10 read tools; ideal for audits, PoCs, and untrusted/local models. See [Read-Only Mode](#read-only-mode).

> **Companion skills**: [vmware-nsx](https://github.com/zw008/VMware-NSX) (networking), [vmware-aiops](https://github.com/zw008/VMware-AIops) (VM lifecycle), [vmware-monitor](https://github.com/zw008/VMware-Monitor) (monitoring)

## Quick Start

```bash
uv tool install vmware-nsx-security

mkdir -p ~/.vmware-nsx-security
cp config.example.yaml ~/.vmware-nsx-security/config.yaml
# Edit config.yaml with your NSX Manager host

echo "VMWARE_NSX_SECURITY_NSX_PROD_PASSWORD=your_password" > ~/.vmware-nsx-security/.env
chmod 600 ~/.vmware-nsx-security/.env

vmware-nsx-security doctor
```

## Read-Only Mode

A prompt instruction is advisory — a model can ignore it. Read-only mode is structural: set `VMWARE_READ_ONLY=true` and all 11 write tools (DFW policy and rule create-update-delete, security group create/delete, VM tag apply/remove, Traceflow packet injection) are removed from the MCP registry at startup — `list_tools()` never offers them, so the model cannot call what it cannot see. The 10 read tools remain, including DFW rule stats and IDS/IPS profile and signature inspection. Off by default, and fail-closed: if the mode is requested but cannot be guaranteed, the server refuses to start.

Three ways to enable:

```json
{
  "mcpServers": {
    "vmware-nsx-security": {
      "command": "vmware-nsx-security",
      "args": ["mcp"],
      "env": { "VMWARE_READ_ONLY": "true" }
    }
  }
}
```

- Per-skill override: `VMWARE_NSX_SECURITY_READ_ONLY=true` (takes precedence over the family-wide `VMWARE_READ_ONLY`)
- Config alternative: `read_only: true` in `~/.vmware-nsx-security/config.yaml`

Precedence: per-skill env → family env → config → off. Startup logs list exactly which tools were withheld.

## What It Does

| Category | Tools |
|----------|-------|
| DFW Policy | list, get, create, update, delete, list rules |
| DFW Rules | create, update, delete, stats |
| Security Groups | list, get, create, delete |
| VM Tags | list tags, apply tag, remove tag |
| Traceflow | run trace, get result |
| IDPS | list profiles, signature status + settings |

**Total: 21 MCP tools** (10 read-only + 11 write)

## MCP Server Setup

**After `uv tool install vmware-nsx-security`, start the MCP server with one command** (v1.5.15+):

```bash
# Recommended — single command, no network re-resolve
vmware-nsx-security mcp

# With a custom config path
VMWARE_NSX_SECURITY_CONFIG=/path/to/config.yaml vmware-nsx-security mcp
```

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "vmware-nsx-security": {
      "command": "vmware-nsx-security",
      "args": ["mcp"],
      "env": {
        "VMWARE_NSX_SECURITY_CONFIG": "~/.vmware-nsx-security/config.yaml"
      }
    }
  }
}
```

<details>
<summary>Alternative: uvx (no install) or legacy entry point</summary>

```bash
# Run without installing (requires PyPI access each launch)
uvx --from vmware-nsx-security vmware-nsx-security mcp

# Legacy entry point (still works, kept for backward compatibility)
vmware-nsx-security-mcp
```

> **Behind a corporate TLS proxy?** uvx may fail with `invalid peer certificate: UnknownIssuer`.
> Use the recommended `vmware-nsx-security mcp` form above (no network needed), or set `UV_NATIVE_TLS=true`.

</details>

## Common Workflows

### Microsegment an Application

```bash
# 1. Create groups by tag — via the create_group MCP tool
#    (tag_scope=tier, tag_value=web → matched as Condition value "tier|web";
#     multiple criteria types — tag/IP/segment — are ORed)

# 2. Create DFW policy
vmware-nsx-security policy create web-app-policy --name "Web to App" --category Application
```

### Tag a VM

```bash
# Find VM and its external ID
vmware-nsx-security tag list my-vm-01

# Apply tag using the external ID
vmware-nsx-security tag apply <external-id> --scope tier --value web
```

### Trace a Packet

```bash
vmware-nsx-security traceflow run <src-lport-id> \
  --src-ip 10.0.1.5 --dst-ip 10.0.2.10 --proto TCP --dst-port 443
```

Output reports `operation_state` (`IN_PROGRESS`/`FINISHED`/`FAILED`),
hop-by-hop `observations` discriminated by `resource_type` (Dropped*
entries carry `reason` + `acl_rule_id`), and a `dfw_hits` summary.

## Safety

- **Dependency checks**: Cannot delete a policy with active rules, or a group referenced by DFW rules/scopes; group deletion aborts if the reference scan fails
- **Audit logging**: All write ops logged to `~/.vmware-nsx-security/audit.log`
- **Input validation**: IDs validated; all API text sanitized against prompt injection
- **Dry-run mode**: All CLI write commands support `--dry-run`
- **Credential safety**: Passwords only from env vars, never in config files

### Companion Skills

| Skill | Scope | Tools | Install |
|-------|-------|:-----:|---------|
| **[vmware-aiops](https://github.com/zw008/VMware-AIops)** ⭐ entry point | VM lifecycle, deployment, guest ops, clusters | 49 | `uv tool install vmware-aiops` |
| **[vmware-monitor](https://github.com/zw008/VMware-Monitor)** | Read-only monitoring, alarms, events, VM info | 27 | `uv tool install vmware-monitor` |
| **[vmware-nsx](https://github.com/zw008/VMware-NSX)** | NSX networking: segments, gateways, NAT, IPAM | 33 | `uv tool install vmware-nsx-mgmt` |
| **[vmware-storage](https://github.com/zw008/VMware-Storage)** | Datastores, iSCSI, vSAN | 11 | `uv tool install vmware-storage` |
| **[vmware-vks](https://github.com/zw008/VMware-VKS)** | Tanzu Namespaces, TKC cluster lifecycle | 20 | `uv tool install vmware-vks` |
| **[vmware-aria](https://github.com/zw008/VMware-Aria)** | Aria Ops metrics, alerts, capacity planning | 28 | `uv tool install vmware-aria` |


## Version Compatibility

| NSX Version | Support | Notes |
|-------------|---------|-------|
| NSX 9.1 / VCF 9.1 | ✅ Full | DFW + Security Group + Traceflow + IDS/IPS via Policy API. VDS 7.0+ required (N-VDS removed in NSX 9). |
| NSX 9.0 / VCF 9.0 | ✅ Full | Same as 9.1. Bare-metal NSX agent removed. |
| NSX 4.x / VCF 5.x | ✅ Full | All features supported. |
| NSX-T 3.2 / VCF 4.5 | ✅ Full | Policy API stable. |

#### Official Broadcom References

- **SDKs**: <https://developer.broadcom.com/sdks> — VMware NSX for Python SDK (future migration target)
- **REST APIs**: <https://developer.broadcom.com/xapis> — NSX-T Data Center REST API
- **CLI Tools**: <https://developer.broadcom.com/tools> — VCF PowerCLI 9.1

## License

MIT
