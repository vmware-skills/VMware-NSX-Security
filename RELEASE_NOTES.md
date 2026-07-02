## v1.7.2 (2026-07-02) — name-search correctness + list pagination

### Fixed
- **Name search silently missed objects past the first 1000 (correctness bug).**
  `list_groups` / `list_dfw_policies` fetched at most 1000 objects then filtered
  client-side, so a group/policy ranked #1001+ returned "not found" on large
  estates. Name filters now route through the NSX Policy **Search API** (server-side
  match), with a bounded-scan fallback that raises a teaching error rather than
  returning an empty result when it can't confirm. `list_dfw_rules` gained
  `limit` / `offset` instead of draining every rule in a policy.

### Changed
- List operations accept server-side `page_size` / `limit` (consistent with the
  sibling NSX `get_all`).

> Note: the Search API query shape was validated against NSX documentation; if you
> upgrade in a large environment, do a quick name-search smoke test against your
> manager. The fallback path is safe (never reports a truncated list as empty).

## v1.7.1 (2026-07-02) — family version alignment

No code changes. Version bump to stay aligned with the v1.7.1 family release
(VMware-AIops + VMware-Monitor large-inventory scale fix — PropertyCollector
batching to stop per-object lazy SOAP round-trips, GitHub issue #31).

## v1.7.0 (2026-06-27) — guided onboarding + teaching auth errors

### Added
- **`vmware-nsx-security init` — interactive first-run setup wizard.** Prompts for host /
  username / password and writes `config.yaml` + `.env` for you. The password is
  stored grep-safe (`b64:`, never plaintext on disk) and `.env` is locked to
  0600, then the connection is verified. Replaces the manual "mkdir + cp
  config.example.yaml + edit YAML + chmod 600" dance.
- `.env.example` added documenting the per-target password var.

### Changed
- `doctor` now points to `vmware-nsx-security init` when config/credentials are missing
  (previously suggested a command that did not exist), keeping the manual steps
  as a fallback.
- Authentication and TLS failures now print a teaching message naming the exact
  file and env var to fix (`~/.vmware-nsx-security/.env` password var, `config.yaml`
  username) plus a `verify_ssl: false` hint for self-signed labs.
- Auth teaching reaffirms special-character passwords are sent via form-body.

## v1.6.1 (2026-06-24)

### Added
- **`.env` passwords are auto-obfuscated to a grep-safe `b64:` form** on first
  load and decoded transparently at runtime — plaintext no longer sits in
  `~/.<skill>/.env` for a casual `grep` to find. Values are read/written through
  python-dotenv's own parser, so the stored secret never drifts from the
  configured one (handles quotes, inline comments, trailing whitespace, and a
  password that literally starts with `b64:`). **Obfuscation, not encryption** —
  for real at-rest secrecy, inject the password from a secret manager instead of
  storing `.env`. New regression suite (10 cases) covers dotenv parity, the
  `b64:`-prefixed edge case, idempotency, and 0600 preservation.

## v1.6.0 (2026-06-22) — trust architecture: undo tokens

### Added
- **Undo-token recording** (vmware-policy 1.6.0): `create_dfw_policy`→`delete_dfw_policy`,
  `create_group`→`delete_group`, `create_dfw_rule`→`delete_dfw_rule`, `apply_vm_tag`→`remove_vm_tag`.
- Inherits harness budget guard, audit accountability fields, and graduated risk tiers.

### Changed
- Requires **vmware-policy >= 1.6.0**.

## v1.5.39 (2026-06-22) — family version alignment

No code changes. Version bump to stay aligned with the v1.5.39 family release
(AIops snapshot-delete async + honest-timeout token-burn fix; Storage datastore-browse timeout fix).

## v1.5.38 (2026-06-12) — backlog finish: server split

### Changed
- Split `mcp_server/server.py` (823 lines) into `mcp_server/tools/*` domain modules under the 800-line
  cap. Behavior-preserving — 21 tools unchanged. (#8)

## v1.5.37 (2026-06-12) — backlog: robust group-delete guard, list pagination

### Fixed
- `delete_group`'s reference guard uses NSX's `group-associations` dependency API, catching nested-group,
  gateway-firewall, and service-insertion/IDPS references the old DFW-only scan missed (and fails safe if
  the check errors). (#6)

### Added
- `list_dfw_policies` / `list_groups` / `list_idps_profiles` gained `name_filter` + `limit`(=50)/`offset`
  pagination across ops/MCP/CLI. (#7)
- `get_all()` safety cap (1000) ported from the sibling NSX repo (家族-sync). (#9)

## v1.5.36 (2026-06-12) — error translation, tag-remove parity, audit completeness

### Fixed
- **404/5xx no longer surface as tracebacks/opaque errors** — `NsxApiError` + central `_request()`
  (mirrors VMware-NSX): teaching hints, GET-only retry-once on transient 5xx, re-auth once on 401
  only (403 = permission error, writes never blindly re-sent).
- **Traceflow no longer deletes an in-progress trace** it just returned the id for; poll budget now
  honors the requested timeout (was silently capped at 30s / 0 polls).
- **Failed write attempts are now audited** (`result="error"`), not just successes.
- `get_group` reports `members_error` instead of a misleading `member_count: 0` on a fetch failure.

### Added
- **`tag remove`** CLI command + **`remove_vm_tag`** MCP tool — VM tags could be applied but never
  removed, so a mistagged VM couldn't be remediated. Tool count is now **21 (10 read / 11 write)**.
- Shared `ops/_validate.py` (deduped the id validators); CLI teaching-error decorator.

## v1.5.35 (2026-06-10) — security hardening: safe errors

### Fixed
- **MCP tools route errors through `_safe_error()`** — full detail to the server log, a
  sanitized message to the agent. Closes raw-exception leakage across all 20 tools.
- **Traceflow cleanup** failure now logs instead of silently passing.

This release aligns the whole family back to a single version (1.5.35); vmware-policy and vmware-pilot return to the shared number after sitting at 1.5.22.

## v1.5.32 (2026-06-08) — VM tagging, IDPS status, and Traceflow rewritten to real NSX APIs

A family-wide spec audit found three features calling invented endpoints or
sending invented payloads — none had ever worked against a real NSX Manager.

### Fixed
- **VM tagging**: `POST /api/v1/fabric/virtual-machines?action=add_tags|remove_tags`
  with `{external_id, tags}` (the previous `/fabric/tags/tag` path never existed).
- **IDPS status**: reads the real `intrusion-services/signatures/status` and
  `intrusion-services` (IdsSettings) endpoints; the old code called two invented
  endpoints and swallowed the 404s into a permanent "UNKNOWN" — errors now surface.
- **Traceflow**: packet body uses the real FieldsPacketData structure (nested
  ip_header/transport_header; transport_type=UNICAST); polling reads
  `operation_state` (IN_PROGRESS/FINISHED/FAILED); observations discriminated
  by `resource_type` (dropped detection + reason/acl_rule_id now work).
- **Groups**: tag conditions carry the required `value: "scope|tag"` string
  (the invented `tag` object 400'd every tag-based group create);
  heterogeneous expressions joined with OR (NSX rejects AND across types);
  `delete_group` reference scan extended to rule/policy `scope` and now ABORTS
  on scan failure instead of deleting blind.
- **IDPS profiles**: polymorphic `IdsProfileFilterCriteria` parsing; severity
  array handling; overridden-signature count from the real list field.
- **Rules**: stats report real RuleStatistics fields; category validated against
  the full enum (incl. Ethernet); JUMP_TO_APPLICATION constraint documented.

### Tests & docs
- +22 shape regression tests; safety test asserts CLI confirm guards;
  README/SKILL/references synced.

## v1.5.30 (2026-06-07) — Tool description quality (Glama TDQS)

### Improved
- Rewrote MCP tool descriptions flagged by Glama's Tool Description Quality Score review:
  per-parameter semantics (format, defaults, valid values), return-field documentation,
  sibling-tool routing guidance, and behavioral transparency (side effects, audit logging,
  async semantics). Corrected descriptions that overstated or misstated actual behavior.
- No functional changes; descriptions only.

## v1.5.29 (2026-05-29) — NSX/VCF Version Compatibility Table

### Documentation
- `references/capabilities.md`: added "NSX Version Compatibility" + "VCF Compatibility" tables mirroring sibling vmware-nsx. Covers NSX 9.0/9.1 (DFW Policy API paths unchanged), 4.x, NSX-T 3.x/2.5.x; VCF 9.1/9.0/5.x/4.x.
- Caveats noted: NSX 9 removed N-VDS and bare-metal agent — no impact on this skill (NSX-T Policy API only).
- Closes the v1.5.23 doc gap (compatibility was declared in README but missing from reference doc).

### No code changes
Documentation-only release.

## v1.5.28 (2026-05-20)

**Fix `subclass() arg 1 must be a class` in goose/old mcp environments** —
v1.5.25–1.5.27 replaced `X | None` with `Optional[X]` but kept
`from __future__ import annotations` at the top of `mcp_server/server.py`.
Under mcp 1.10–1.13 (which Goose and some sandboxes pin), `Tool.from_function`
calls `issubclass(param.annotation, Context)` without resolving forward refs,
so string annotations crash the entire server load. Removed
`from __future__ import annotations` from `mcp_server/server.py` so annotations
are real classes; verified all tools load under mcp 1.10 and 1.14.

Traceback location: `mcp/server/fastmcp/tools/base.py:67`. CLAUDE.md 踩坑 #33
updated. family_smoke.sh Check 4b now installs `mcp==1.10.0` to catch this
regression class.

## v1.5.27 (2026-05-20)

**Loosen Python requirement: now supports Python >= 3.10** — v1.5.25/26 fixed
the PEP 604 root cause in MCP tool signatures (Optional[X] instead of X | None),
but kept `requires-python = ">=3.11"` and a 3.11 hard guard in `mcp_cmd`. Both
relaxed to 3.10 so users on Python 3.10 (e.g. Goose default sandbox, Ubuntu
22.04 system python) can install and run directly without a Python upgrade.

- `pyproject.toml`: `requires-python = ">=3.10"` (was `>=3.11`; VMware-VKS
  was `>=3.12`, now also `>=3.10` for family alignment).
- `<pkg>/cli.py` `mcp_cmd()`: version guard now triggers on `< (3, 10)`.
- Behavior on Python 3.10 matches 3.11/3.12 — the Optional[X] fix from v1.5.25
  is what actually enables this; this release just stops blocking installs.

---

## v1.5.26

**Family-wide MCP server fix — Python 3.10 compatibility (踩坑 #33)** — `vmware-nsx-security mcp`
crashed at decorator time on Python 3.10 with `subclass() arg 1 must be a class`.
Root cause: `mcp_server/server.py` used PEP 604 `X | None` in tool signatures
plus `from __future__ import annotations`; on Python 3.10 + older mcp/pydantic
combos, `typing.get_type_hints()` evaluates `"str | None"` to a
`types.UnionType` instance, which FastMCP/Pydantic then feeds to `issubclass()`.
Reported by a goose user (qwen3.6:27, Python 3.10).

- `mcp_server/server.py`: all `X | None` → `Optional[X]`; ops layer untouched.
- `<pkg>/cli.py` `mcp_cmd()`: hard guard — exits with installation fix command
  if Python < 3.11 (defense in depth, our actual lower bound).
- `pyproject.toml`: `mcp[cli]>=1.10,<2.0` (was `>=1.0`) so uv doesn't pick
  an ancient version that has the same issubclass bug.

**Tooling — family smoke gains MCP schema-build check** — `scripts/family_smoke.sh`
new Check 4b runs `asyncio.run(mcp.list_tools())` per skill, forcing FastMCP to
build Pydantic models for every declared tool. Supports both module-level `mcp`
and `build_server()` factory patterns.

**Docs — CLAUDE.md gains 踩坑 #33 (PEP 604 / Python 3.10) and #34 (CLI/MCP exposure parity).**

---

## v1.5.24 (2026-05-19)

**Family version alignment** — no code changes in this skill. Bumped together
with VMware-AIops and VMware-VKS, which received a pyVmomi 8.x `ManagedObject`
setattr fix (踩坑 #32). `family_smoke.sh` now enforces the no-setattr rule
across all 9 skills.

## v1.5.23 (2026-05-19)

**NSX 9 / VCF 9.0 / 9.1 compatibility declared.**

- **docs:** README and `references/` now declare NSX 9.0 / 9.1 and VCF 9.0 / 9.1 as ✅ Full. DFW Policy / Security Group / Traceflow / IDS-IPS endpoints unchanged in NSX 9.
- **docs:** Same NSX 9 caveats apply as in vmware-nsx (N-VDS removed → VDS 7.0+ required, bare-metal agent removed), but neither affects this skill's security tools.
- **docs:** Added `Official Broadcom References` pointing to the [VMware NSX for Python SDK](https://developer.broadcom.com/sdks).
- **align:** Family v1.5.23 — all 9 skills tracking VCF 9.0 / 9.1 compatibility declaration.

## v1.5.22 (2026-05-08)

**Family alignment** — no source changes in this skill.

- **align:** Tracks v1.5.22 family bump driven by Smithery onboarding for vmware-avi / vmware-harden / vmware-pilot.

## v1.5.21 (2026-05-08)

**Family alignment** — no source changes in this skill.

- **deps:** Bumped `python-multipart` 0.0.26 → 0.0.27 (transitive, fixes GHSA HIGH DoS via unbounded multipart headers).
- **align:** Tracks v1.5.21 family bump driven by vmware-monitor folder_path feature (community PR #11).

## v1.5.20 (2026-05-08)

**Fix:** Added `<!-- mcp-name: io.github.zw008/vmware-nsx-security -->` marker to README.md so MCP Registry ownership validation passes. Without this marker the registry refused publish (HTTP 400, "PyPI package ownership validation failed"), leaving this skill missing from the official registry from v1.3.0 through v1.5.19.

- **registry:** First-time publish of `vmware-nsx-security` to registry.modelcontextprotocol.io.
- **align:** Family bumped 1.5.19 → 1.5.20 in lockstep.

## v1.5.19 (2026-05-06)

**Family alignment** — no source changes in this skill.

- **build:** Bumped `requires-python` from `>=3.10` to `>=3.11` (regression eval uses `tomllib`).
- **smoke:** Family `scripts/family_smoke.sh` adds Check 3b — recursive `--help` on every subcommand to surface broken lazy imports (yjs review 2026-05-06; 踩坑 #27).
- **align:** Tracks v1.5.19 fixes in vmware-nsx (CRITICAL CLI imports), vmware-vks (ApiClient leak), vmware-harden (Twin indexes + LEFT JOIN), vmware-policy (approval gate + singleton lock).

## v1.5.18 (2026-05-02)

**Family alignment + tooling normalization** — no source changes in this skill.

- **dev:** Added `[dependency-groups] dev` block (PEP 735) so `uv sync --group dev` works. Canonical set: `pytest>=8.0,<10.0`, `pytest-cov`, `ruff`.
- **test:** New `tests/eval/regression/test_release_blockers.py` (5 evals) catches the v1.5.x release blockers — missing `mcp_server` in wheel, AST-detected unimported runtime names (the v1.5.5 traceflow `import re` incident is now caught at test time), Typer app load failure, module import errors. Run via `pytest tests/eval/regression/`.
- **note:** A separate cross-skill smoke check verifies that NSX-Security and NSX stay in sync on the form-body auth pattern (v1.4.9 special-character-password fix), so the v1.5.5 sync drift can't recur silently.
- **align:** Family version bump to v1.5.18.

## v1.5.17 (2026-05-01)

**Family alignment** — no source changes in this skill.

This release tracks vmware-pilot v1.5.17 (new `investigate_alert` template + `review_workflow` MCP tool + `parallel_group` step type) and vmware-policy v1.5.17 (L5 pattern matcher integrated into `@vmware_tool`). Both work with the existing skill MCP surface unchanged.

- **align:** Family version bump to v1.5.17.

## v1.5.16 (2026-04-30)

**Enterprise Harness Engineering alignment** — adapted from the Linkloud × addxai framework articles ([part 1](https://mp.weixin.qq.com/s/hz4W7ILHJ1yz_pG0Z1xP-A), [part 2](https://mp.weixin.qq.com/s/F3qYbyB3S8oIqx-Y4BrWNQ)).

- **docs:** Added Broadcom/VMware brand disclaimer to `references/setup-guide.md` Security Notes (clears Snyk E005 brand-misuse flag on next clawhub Rescan).
- **docs:** "Automation Level Reference" section in `references/capabilities.md` — every tool tagged L1-L5 per the EHE framework.
- **docs:** Common Workflows in `SKILL.md` rewritten with DFW judgment (default-allow for management traffic FIRST, tag inventory verification, category choice, traceflow as verification gate).
- **align:** Family version bump to v1.5.16.

## v1.5.15 (2026-04-29)

**UX improvements from real user feedback**

- **feat:** New top-level CLI subcommand `vmware-nsx-security mcp` starts the MCP server. Single command after `uv tool install vmware-nsx-security` — no more `uvx --from`, no PyPI re-resolve, no TLS-proxy issues.
- **feat:** Default `verify_ssl: true` on new targets (was `false`). NSX Manager with default self-signed certs requires explicit `verify_ssl: false` in `config.yaml`.
- **docs:** README, SKILL.md, setup-guide.md, and `examples/mcp-configs/*.json` switched to `command: "vmware-nsx-security"`, `args: ["mcp"]`. uvx form moved to fallback with TLS-proxy troubleshooting note.
- **compat:** Legacy `vmware-nsx-security-mcp` console script kept — existing user configs continue to work.

## v1.5.14 (2026-04-21)

- Align with VMware skill family v1.5.14 (code review follow-up fixes by @yjs-2026)

## v1.5.13 (2026-04-21)

**Bug fixes from code review 2026-04-20**

- **fix:** `traceflow.py` — ID validation regex now allows dots (`^[\w\-\.]+$`), consistent with all other `_validate_id()` in the codebase

## v1.5.12 (2026-04-17)

- Align with VMware skill family v1.5.12 (security & bug fixes from code review by @yjs-2026)

## v1.5.11 (2026-04-17)

- Align with VMware skill family v1.5.11 (AVI 22.x fixes from @timwangbc)

## v1.5.10 (2026-04-16)

- Security: bump python-multipart 0.0.22→0.0.26 (DoS via large multipart preamble/epilogue)
- Align with VMware skill family v1.5.10

## v1.5.8 (2026-04-15)

- Fix: SSL warning suppression scope — replaced process-global `warnings.filterwarnings()` with class-targeted `urllib3.disable_warnings(InsecureRequestWarning)`, which no longer accidentally suppresses SSL warnings from other libraries in the same process.
- Align with VMware skill family v1.5.8

## v1.5.7 (2026-04-15)

- Align with VMware skill family v1.5.7 (Pilot `__from_step_N__` fix + VKS SSL/timeout fix)

## v1.5.6 (2026-04-15)

- Align with VMware skill family v1.5.6 (AVI bugfixes + packaging hotfix)

## v1.5.5 (2026-04-15)

- Fix: CRITICAL — missing `import re` in `ops/traceflow.py` caused `NameError` in traceflow operations
- Fix: 403 auth failure for NSX passwords containing special chars (!, ), etc.) — switched /api/session/create from Basic Auth to form-body credentials (j_username/j_password), same fix as NSX v1.4.9
- Align with VMware skill family v1.5.5

## v1.5.4 (2026-04-14)

- Security: bump pytest 9.0.2→9.0.3 (CVE-2025-71176, insecure tmpdir handling)

## v1.5.0 (2026-04-12)

### Anthropic Best Practices Integration

- **[READ]/[WRITE] tool prefixes**: All MCP tool descriptions now start with [READ] or [WRITE] to clearly indicate operation type
- **Read/write split counts**: SKILL.md MCP Tools section header shows exact read vs write tool counts
- **Negative routing**: Description frontmatter includes "Do NOT use when..." clause to prevent misrouting
- **Broadcom author attestation**: README.md, README-CN.md, and pyproject.toml include VMware by Broadcom author identity (wei-wz.zhou@broadcom.com) to resolve Snyk E005 brand warnings

## v1.4.9 (2026-04-11)

- Fix: require explicit VMware/vSphere context in skill routing triggers (prevent false triggers on generic "clone", "deploy", "alarms" etc.)
- Fix: clarify vmware-policy compatibility field (Python transitive dep, not a required standalone binary)

## v1.4.8 (2026-04-09)

- Security: bump cryptography 46.0.6→46.0.7 (CVE-2026-39892, buffer overflow)
- Security: bump urllib3 2.3.0→2.6.3 (multiple CVEs) [VMware-VKS]
- Security: bump requests 2.32.5→2.33.0 (medium CVE) [VMware-VKS]

## v1.4.7 (2026-04-08)

- Fix: align openclaw metadata with actual runtime requirements
- Fix: standardize audit log path to ~/.vmware/audit.db across all docs
- Fix: update credential env var docs to correct VMWARE_<TARGET>_PASSWORD convention
- Fix: declare .env config and vmware-policy optional dependency in metadata

# Release Notes


## v1.4.6 — 2026-04-06

- fix: remove suspicious content from SKILL.md for ClawHub clean scan

---

## v1.4.5 — 2026-04-03

- **Security**: bump pygments 2.19.2 → 2.20.0 (fix ReDoS CVE in GUID matching regex)
- **Infrastructure**: add uv.lock for reproducible builds and Dependabot security tracking


## v1.4.6 — 2026-04-06

- fix: remove suspicious content from SKILL.md for ClawHub clean scan

---

## v1.4.0 — 2026-03-29

### Architecture: Unified Audit & Policy

- **vmware-policy integration**: All MCP tools now wrapped with `@vmware_tool` decorator
- **Unified audit logging**: Operations logged to `~/.vmware/audit.db` (SQLite WAL), replacing per-skill JSON Lines logs
- **Policy enforcement**: `check_allowed()` with rules.yaml, maintenance windows, risk-level gating
- **Sanitize consolidation**: Replaced local `_sanitize()` with shared `vmware_policy.sanitize()`
- **Risk classification**: Each tool tagged with risk_level (low/medium/high) for confirmation gating
- **Agent detection**: Audit logs identify calling agent (Claude/Codex/local)
- **New family members**: vmware-policy (audit/policy infrastructure) + vmware-pilot (workflow orchestration)


## v1.4.6 — 2026-04-06

- fix: remove suspicious content from SKILL.md for ClawHub clean scan

---

## v1.3.1 — 2026-03-27

### Documentation

- Updated README.md and README-CN.md companion skills table: expanded to full 6-skill family with tool counts and install commands, added vmware-aria entry


## v1.4.6 — 2026-04-06

- fix: remove suspicious content from SKILL.md for ClawHub clean scan

---

## v1.3.0 — 2026-03-27

### Initial release

- 20 MCP tools: 10 read-only + 10 write operations
- DFW: security policy CRUD (6 tools) + rule CRUD + rule stats (4 tools)
- Security groups: list, get, create, delete with dependency checks (4 tools)
- VM Tags: list VM tags, apply tag (2 tools)
- Traceflow: run trace with polling + get result (2 tools)
- IDPS: list profiles, get engine status (2 tools)
- Safety: `delete_dfw_policy` blocks if active rules exist; `delete_group` blocks if DFW-referenced
- SKILL.md with progressive disclosure (Anthropic best practices)
- CLI (`vmware-nsx-security`) with typer — policy/rule/group/tag/traceflow/idps subcommands
- MCP server (20 tools) via stdio transport
- Docker one-command launch
- `vmware-nsx-security doctor` — 8-check environment diagnostics
- Audit logging (JSON Lines) for all write operations
- `references/`: cli-reference.md, capabilities.md, setup-guide.md
- `examples/mcp-configs/`: 3 agent config templates (Claude Code, Cursor, Goose)
- README.md and README-CN.md with companion skills, workflows, troubleshooting

**PyPI**: `uv tool install vmware-nsx-security==1.3.0`