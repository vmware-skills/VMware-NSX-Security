<!-- mcp-name: io.github.vmware-skills/vmware-nsx-security -->

# VMware-NSX-Security

Investigate and manage NSX/vDefend security policies.

English · [简体中文](README-CN.md)

Community-maintained · MIT · Not an official VMware/Broadcom product.

[![18-second illustrative investigation demo](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-en.gif)](https://github.com/vmware-skills/marketplace/blob/main/assets/demos/vmware-skills-en.mp4)

Synthetic-data animation, not a live recording. [Watch the AI-narrated family introduction (~2 min)](https://github.com/vmware-skills/marketplace/blob/main/assets/demos/vmware-skills-en.mp4)

## Why use it?

- Inspect firewall policies, groups and VM tags.
- Use Traceflow and IDPS evidence for troubleshooting.
- Make security configuration changes through scoped tools.

## Get started

Install the published CLI and inspect its commands:

```sh
uv tool install vmware-nsx-security==1.17.3
vmware-nsx-security --help
```

Requires uv and Python >=3.10. Configure targets and credentials locally before remote queries. [Setup guide](skills/vmware-nsx-security/references/setup-guide.md).

For Claude Code and other host installation paths, see the [family portal](https://github.com/vmware-skills/marketplace).

## Know the boundaries

Includes security policy and rule writes. Use suitable target permissions and local Policy; a successful tool call is not proof that an application is secure.

## Go deeper

- [Capabilities](skills/vmware-nsx-security/references/capabilities.md)
- [CLI reference](skills/vmware-nsx-security/references/cli-reference.md)
- [Agent guardrails](skills/vmware-nsx-security/references/agent-guardrails.md)
- [Detailed usage and architecture](skills/vmware-nsx-security/references/detailed-guide.md)
- [Canonical skill instructions](skills/vmware-nsx-security/SKILL.md)

Part of [VMware Skills](https://github.com/vmware-skills/marketplace): 15 skills, 14 MCP servers and one shared Policy library. If it helps your work, star the family portal.

[Issues and feedback](https://github.com/vmware-skills/VMware-NSX-Security/issues) · [MIT](https://opensource.org/license/mit/)
