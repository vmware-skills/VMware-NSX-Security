# Security Policy

## Disclaimer

This is a community-maintained open-source project and is **not affiliated with, endorsed by, or sponsored by VMware, Inc. or Broadcom Inc.** "VMware" and "NSX" are trademarks of Broadcom Inc.

**Author**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately:

- **Email**: wei-wz.zhou@broadcom.com
- **GitHub**: Open a [private security advisory](https://github.com/zw008/VMware-NSX-Security/security/advisories/new)

Do **not** open a public GitHub issue for security vulnerabilities.

## Security Design

### Credential Management

- Passwords are stored exclusively in `~/.vmware-nsx-security/.env` (never in `config.yaml`, never in code)
- `.env` file permissions are verified at startup (`chmod 600` required)
- No credentials are logged, echoed, or included in audit entries
- Each NSX Manager target uses a separate environment variable: `VMWARE_<TARGET_NAME_UPPER>_PASSWORD`

### Destructive Operation Safeguards

All write operations pass through multiple safety layers:

1. **`@vmware_tool` decorator** — mandatory on every MCP tool; provides pre-checks, audit logging, data sanitization, and timeout control
2. **Double confirmation** — CLI destructive commands (DFW policy delete, security group delete, IDS/IPS config changes) require two separate "Are you sure?" prompts
3. **DFW policy deletion guard** — policy delete checks for active rules before proceeding; policies with active rules require explicit override
4. **Security group deletion guard** — group delete checks for references (policies, rules, other groups that depend on it) and rejects deletion if references exist
5. **Traceflow safety** — Traceflow operations are strictly read-only and cannot modify network state
6. **IDS/IPS confirmation** — IDS/IPS configuration changes (enable, disable, profile updates) require double confirmation due to security impact
7. **Audit logging** — every operation (read and write) is logged to `~/.vmware/audit.db` (SQLite WAL) with timestamp, user, target, operation, parameters, and result
8. **Policy engine** — `~/.vmware/rules.yaml` can deny operations by pattern, enforce maintenance windows, and set risk-level thresholds

### SSL/TLS Verification

- TLS certificate verification is **enabled by default**
- `disableSslCertValidation: true` exists solely for NSX Manager instances using self-signed certificates in isolated lab/home environments
- In production, always use CA-signed certificates with full TLS verification

### Transitive Dependencies

- `vmware-policy` is the only transitive dependency auto-installed; it provides the `@vmware_tool` decorator and audit logging
- All other dependencies are standard Python packages (requests, Click, Rich, python-dotenv)
- No post-install scripts or background services are started during installation
- PyPI package name: `vmware-nsx-security`

### Prompt Injection Protection

- All NSX-sourced content (policy names, rule descriptions, security group members, IDS/IPS alert details) is processed through `_sanitize()`
- Sanitization truncates to 500 characters and strips C0/C1 control characters
- Output is wrapped in boundary markers when consumed by LLM agents

## Static Analysis

This project is scanned with [Bandit](https://bandit.readthedocs.io/) before every release, targeting 0 Medium+ issues:

```bash
uvx bandit -r vmware_nsx_security/
```

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x   | Yes       |
| < 1.5   | No        |
