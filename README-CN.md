# VMware NSX Security

> **作者**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com
> 本项目由 VMware 工程师维护的社区项目，非 VMware 官方产品。
> VMware 官方开发者工具请访问 [developer.broadcom.com](https://developer.broadcom.com)。

VMware NSX DFW 微分段与安全管理 MCP skill — 21 个工具，涵盖分布式防火墙策略与规则、安全组、VM 标签、Traceflow 数据包追踪和 IDPS。

> **配套 skill**：[vmware-nsx](https://github.com/zw008/VMware-NSX)（网络）、[vmware-aiops](https://github.com/zw008/VMware-AIops)（VM 生命周期）、[vmware-monitor](https://github.com/zw008/VMware-Monitor)（监控）

## 快速开始

```bash
uv tool install vmware-nsx-security

mkdir -p ~/.vmware-nsx-security
cp config.example.yaml ~/.vmware-nsx-security/config.yaml
# 编辑 config.yaml，填写 NSX Manager 地址

echo "VMWARE_NSX_SECURITY_NSX_PROD_PASSWORD=your_password" > ~/.vmware-nsx-security/.env
chmod 600 ~/.vmware-nsx-security/.env

vmware-nsx-security doctor
```

### 离线 / 隔离网络安装（从源码）

本项目采用现代 PEP 517 构建系统（hatchling），因此**没有 `setup.py`**——这是
预期设计，而非缺失文件。如果你克隆源码后遇到
`ERROR: File "setup.py" or "setup.cfg" not found ... editable mode
currently requires a setuptools-based build`，说明你的 `pip` 版本早于 21.3，
无法对非 setuptools 后端做 *editable*（`-e`）安装。Editable 模式只是开发便利，
运行本工具并不需要它——任选其一：

```bash
# 在源码目录中——普通（非 editable）安装会构建 wheel：
pip install .              # 不要用  pip install -e .

# ……或先升级 pip，editable 也可用：
pip install --upgrade pip && pip install -e .
```

若目标是**完全隔离网络的主机**，在联网机器上构建好 wheel 再拷贝过去，目标主机即无需联网：

```bash
# 在联网机器上，将本包及其依赖收集为 wheel：
pip wheel . -w dist        # → dist/*.whl   （或用 uv build 仅构建本包）

# 将 dist/ 拷到隔离主机，离线安装：
pip install --no-index --find-links dist vmware-nsx-security
```

## 功能

| 类别 | 工具数 |
|------|--------|
| DFW 策略 | 列出、获取、创建、更新、删除、列出规则（6 个） |
| DFW 规则 | 创建、更新、删除、统计（4 个） |
| 安全组 | 列出、获取、创建、删除（4 个） |
| VM 标签 | 列出标签、应用标签、移除标签（3 个） |
| Traceflow | 运行追踪、获取结果（2 个） |
| IDPS | 列出 Profile、签名状态 + 全局设置（2 个） |

**共 21 个 MCP 工具**（10 只读 + 11 写入）

## MCP 服务器配置

**v1.5.15+ 推荐方式**：完成 `uv tool install vmware-nsx-security` 后，**一条命令启动 MCP**：

```bash
# 推荐 — 单命令，无网络依赖
vmware-nsx-security mcp

# 指定配置路径
VMWARE_NSX_SECURITY_CONFIG=/path/to/config.yaml vmware-nsx-security mcp
```

添加到 `~/.claude.json`：

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
<summary>备选方案：uvx（不安装）或 legacy 入口</summary>

```bash
# 不想安装，临时运行（每次需要联网 resolve 依赖）
uvx --from vmware-nsx-security vmware-nsx-security mcp

# 旧 entry point（仍可用，向后兼容）
vmware-nsx-security-mcp
```

> **公司 TLS 代理网络下？** uvx 可能报 `invalid peer certificate: UnknownIssuer`。
> 推荐使用上面的 `vmware-nsx-security mcp`（无需联网），或 `export UV_NATIVE_TLS=true`。

</details>

## 常见操作

### 对应用进行微分段

```bash
# 1. 按标签创建安全组 — 使用 create_group MCP 工具
#    （tag_scope=tier, tag_value=web → Condition value 为 "tier|web"；
#      多个条件类型（标签/IP/Segment）之间为 OR 关系）

# 2. 创建 DFW 策略
vmware-nsx-security policy create web-app-policy --name "Web to App" --category Application
```

### 为 VM 打标签

```bash
# 查询 VM 及其 external ID
vmware-nsx-security tag list my-vm-01

# 使用 external ID 应用标签
vmware-nsx-security tag apply <external-id> --scope tier --value web
```

### 追踪数据包路径

```bash
vmware-nsx-security traceflow run <src-lport-id> \
  --src-ip 10.0.1.5 --dst-ip 10.0.2.10 --proto TCP --dst-port 443
```

输出包含 `operation_state`（`IN_PROGRESS`/`FINISHED`/`FAILED`）、按
`resource_type` 区分的逐跳 `observations`（Dropped* 条目携带 `reason` +
`acl_rule_id`）以及 `dfw_hits` 命中摘要。

## 安全性

- **依赖检查**：有活跃规则时不允许删除策略；被 DFW 规则/作用域引用的安全组不允许删除；引用扫描失败时中止删除
- **审计日志**：所有写操作记录到 `~/.vmware-nsx-security/audit.log`（JSON Lines 格式）
- **输入验证**：ID 字符集校验；API 返回文本经过 `_sanitize()` 清洗，防止提示注入
- **Dry-run 模式**：CLI 写命令均支持 `--dry-run` 预览
- **凭据安全**：密码仅从环境变量读取，永不写入 config.yaml

### 配套 Skill

| Skill | 功能范围 | 工具数 | 安装 |
|-------|---------|:-----:|------|
| **[vmware-aiops](https://github.com/zw008/VMware-AIops)** ⭐ 入口 | VM 生命周期、部署、Guest 操作、集群管理 | 49 | `uv tool install vmware-aiops` |
| **[vmware-monitor](https://github.com/zw008/VMware-Monitor)** | 只读监控：告警、事件、VM 信息 | 27 | `uv tool install vmware-monitor` |
| **[vmware-nsx](https://github.com/zw008/VMware-NSX)** | NSX 网络：Segment、网关、NAT、IPAM | 33 | `uv tool install vmware-nsx-mgmt` |
| **[vmware-storage](https://github.com/zw008/VMware-Storage)** | 数据存储、iSCSI、vSAN | 11 | `uv tool install vmware-storage` |
| **[vmware-vks](https://github.com/zw008/VMware-VKS)** | Tanzu 命名空间、TKC 集群生命周期 | 20 | `uv tool install vmware-vks` |
| **[vmware-aria](https://github.com/zw008/VMware-Aria)** | Aria Ops 指标、告警、容量规划 | 28 | `uv tool install vmware-aria` |

## 许可证

MIT
