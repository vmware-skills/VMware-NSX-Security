<!-- mcp-name: io.github.zw008/vmware-nsx-security -->
# VMware NSX Security

> **Author**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com
> This is a community-driven project by a VMware engineer, not an official VMware product.
> For official VMware developer tools see [developer.broadcom.com](https://developer.broadcom.com).

VMware NSX DFW microsegmentation and security MCP skill — 21 tools for distributed firewall policies/rules, security groups, VM tags, Traceflow packet tracing, and IDPS.

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

### Offline / Air-Gapped Install (from source)

This project uses the modern PEP 517 build system (hatchling), so there is **no
`setup.py`** by design — that is expected, not a missing file. If you cloned the
source and hit `ERROR: File "setup.py" or "setup.cfg" not found ... editable mode
currently requires a setuptools-based build`, your `pip` is older than 21.3 and
cannot do an *editable* (`-e`) install with a non-setuptools backend. Editable
mode is a developer convenience, not needed to run the tool — do one of:

```bash
# From the source tree — a normal (non-editable) install builds a wheel:
pip install .              # NOT  pip install -e .

# ...or upgrade pip first, and editable works too:
pip install --upgrade pip && pip install -e .
```

For a **truly air-gapped host**, build the wheels on a connected machine and copy
them over — the target then needs no network:

```bash
# On a connected machine, collect this package + its dependencies as wheels:
pip wheel . -w dist        # → dist/*.whl   (or: uv build, for just this package)

# Copy dist/ to the air-gapped host, then install offline:
pip install --no-index --find-links dist vmware-nsx-security
```

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
