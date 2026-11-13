<!-- mcp-name: io.github.vmware-skills/vmware-nsx-security -->

# VMware-NSX-Security

<a id="readme-overview"></a>

Investigate and manage NSX/vDefend security policies.

English · [简体中文](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/README-CN.md)

Community-maintained · MIT · Not an official VMware/Broadcom product.

[![24-second illustrative investigation demo](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-en.gif)](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-operations/vmware-skills-en.mp4)

Synthetic-data GIF; video includes redacted historical screenshots. [Download the AI-narrated family introduction (~3 min)](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-operations/vmware-skills-en.mp4)

<a id="readme-capabilities-and-workflows"></a>

## Why use it?

- Inspect firewall policies, groups and VM tags.
- Use Traceflow and IDPS evidence for troubleshooting.
- Make security configuration changes through scoped tools.

<a id="readme-quick-start"></a>

## Get started

Install the published CLI and inspect its commands:

```sh
uv tool install vmware-nsx-security==1.17.3
vmware-nsx-security --help
```

Requires uv and Python >=3.10. Configure targets and credentials locally before remote queries. [Setup guide](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/setup-guide.md).

For agent-host installation, use the [setup guide](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/setup-guide.md) and [Cursor, Codex, Gemini CLI, Cline and local-model examples](https://github.com/vmware-skills/marketplace/blob/main/docs/agent-hosts.md).

Choose a model with the [shared model-fit workflow](https://github.com/vmware-skills/marketplace/blob/main/model-fit/RUNNER.md): compare the same tasks, review quality and safety, then select the smallest tested passing configuration per task group; this is not a production guarantee.

<a id="readme-safety-and-audit"></a>

## Know the boundaries

Includes security policy and rule writes. Use suitable target permissions and local Policy; a successful tool call is not proof that an application is secure.

<a id="readme-mcp-configuration"></a> <a id="readme-troubleshooting"></a> <a id="readme-reference"></a>

## Go deeper

- [Capabilities](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/capabilities.md)
- [CLI reference](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/cli-reference.md)
- [Agent guardrails](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/agent-guardrails.md)
- [Detailed usage and architecture](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/detailed-guide.md)
- [MCP launch configuration](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/.mcp.json)
- [Canonical skill instructions](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/SKILL.md)

<a id="readme-companion-skills"></a>

Part of [VMware Skills](https://github.com/vmware-skills/marketplace): 15 skills, 14 MCP servers and one shared Policy library. If it helps your work, star the family portal.

<a id="readme-license"></a>

[Issues and feedback](https://github.com/vmware-skills/VMware-NSX-Security/issues) · [MIT](https://opensource.org/license/mit/)
