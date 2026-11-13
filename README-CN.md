<!-- mcp-name: io.github.vmware-skills/vmware-nsx-security -->

# VMware-NSX-Security

<a id="readme-overview"></a>

调查和管理 NSX/vDefend 安全策略。

[English](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/README.md) · 简体中文

社区维护 · MIT 开源 · 非 VMware/Broadcom 官方产品。

[![24 秒调查示意演示](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-zh.gif)](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-model-fit/vmware-skills-zh.mp4)

GIF 使用合成数据；视频包含脱敏的历史截图。[下载家族 AI 配音介绍（约 3 分钟）](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-model-fit/vmware-skills-zh.mp4)

<a id="readme-capabilities-and-workflows"></a>

## 能解决什么问题？

- 检查防火墙策略、安全组与 VM 标签。
- 结合 Traceflow 与 IDPS 证据排障。
- 通过明确范围的工具变更安全配置。

<a id="readme-quick-start"></a>

## 快速开始

安装已发布 CLI，并查看可用命令：

```sh
uv tool install vmware-nsx-security==1.17.3
vmware-nsx-security --help
```

需要 uv 与 Python >=3.10。远程查询前，在本地配置目标与凭据。[配置指南](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/setup-guide.md)。

Agent 宿主安装见本模块的[配置指南](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/setup-guide.md)，以及 [Cursor、Codex、Gemini CLI、Cline 与本地模型示例](https://github.com/vmware-skills/marketplace/blob/main/docs/agent-hosts-CN.md)。

选模型可用[共享模型自测流程](https://github.com/vmware-skills/marketplace/blob/main/model-fit/RUNNER-CN.md)：统一任务、复核质量与安全，再按任务组选择最小已测通过配置；不代表生产质量保证。

<a id="readme-safety-and-audit"></a>

## 使用边界

包含安全策略与规则写操作。使用适当目标权限和本地 Policy；工具调用成功不等于应用已经安全。

<a id="readme-mcp-configuration"></a> <a id="readme-troubleshooting"></a> <a id="readme-reference"></a>

## 详细文档

- [能力范围](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/capabilities.md)
- [CLI 用法](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/cli-reference.md)
- [Agent 使用约束](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/agent-guardrails.md)
- [详细用法与架构](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/references/detailed-guide-CN.md)
- [MCP 启动配置](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/.mcp.json)
- [唯一技能指令正本](https://github.com/vmware-skills/VMware-NSX-Security/blob/main/skills/vmware-nsx-security/SKILL.md)

<a id="readme-companion-skills"></a>

属于 [VMware Skills 家族](https://github.com/vmware-skills/marketplace/blob/main/README-CN.md)：15 个 skill、14 个 MCP server 与一个共享 Policy 库。如果对你有用，欢迎 Star 家族门户。

<a id="readme-license"></a>

[问题与反馈](https://github.com/vmware-skills/VMware-NSX-Security/issues) · [MIT](https://opensource.org/license/mit/)
