## v1.9.0 — the exclusion list was invisible, so "protected" was wrong for most of the fabric

A minor bump because it adds a tool. On the test estate **10 of 12 fabric VMs
were on the NSX distributed-firewall exclusion list** — including vCenter, VCF
Operations and an NSX manager — and nothing in this skill surfaced it. Every
answer about a VM being micro-segmented or covered by DFW policy was therefore
wrong for 83% of those hosts, and confidently so: the rules exist, they simply
do not apply to an excluded member.

`list_dfw_exclusions` reads it directly, and the tools an operator actually asks
"is this host protected?" carry the state with them — `list_vm_tags`,
`get_group` on the group and each sampled member, and a note on
`list_dfw_policies`, which is the listing that gets read as "the fabric is
segmented". Not on `list_dfw_rules`: that is the paging loop, and its docstring
points at the tool instead. `null` is never `false` — an unreadable list reports
unknown, and a partially resolved index can prove membership but never absence.

Two details settled against the published 9.1 contract rather than from memory:
`members` on `PolicyExcludeList` is an array of Group *paths*, so naming VMs
means resolving groups; and `?system_owned=true` is required to see NSX's own
exclusions, which on a VCF estate is exactly where the management VMs are. The
obvious endpoint, `GET /api/v1/firewall/excludelist`, is on 9.1.0's Removed
Methods page — a test fails if it reappears.

`run_traceflow` was also declared a write and audited nothing, while the other
ten write tools each called the audit themselves; the sweep is derived from the
annotations now, so the eleventh joins by existing. The exclusion-list failure
message lost its remedy to the 300-character cap and was rewritten to lead with
the action. And the suite stopped writing to the operator's real audit database.

**The `vmware-policy` floor moves to >=1.11.0** — Policy 1.11.0 stops the engine
failing open when `rules.yaml` cannot be read. One behaviour travels with it: on
such a host, operations move from all-allowed to all-denied.
`VMWARE_POLICY_DISABLED=1` is checked above the rules, so the escape hatch does
not depend on them loading.

## v1.8.12 — the schema an agent reads now carries the descriptions

Parameter descriptions reach the JSON schema for the first time. An MCP client
sees the schema, not the docstring, and this repo's coverage of `description`
and `additionalProperties` was 0% — while nearly every parameter was already
described in an `Args:` block no client ever receives.

Measured on a real VCF 9.1 estate, the gap produced a silent failure with no
error at any stage: a parameter name guessed wrong is discarded and the tool
returns the full unfiltered result; a value guessed wrong (`power_state=
"running"`) returns 0 rows where there were 11.

vmware-policy 1.10.0's `describe_tool_parameters` copies what is already
written, so the docstring is now load-bearing and the two cannot drift apart. It
removes the `Args:` block from the description once copied — both travel in
every `tools/list` response, so leaving it bills the same sentences twice
against the manifest's token budget. `additionalProperties` is closed: an open
schema is room for a model to invent arguments that are then silently
discarded, which is the other half of the same failure.

**The `vmware-policy` floor moves to >=1.10.0.** Older releases have no
`describe_tool_parameters`, and resolving one gives an ImportError at server
start rather than a missing feature.


## v1.8.11 — every DFW policy reported zero rules, and paging never ended

Found against a real NSX 9.1.0.0200 deployment.

**`list_dfw_policies` reported `rule_count: 0` for every policy.** The real
value was 6, two of them DROP rules — so the tool said nothing was enforced
anywhere. NSX's `SecurityPolicy` does carry `rule_count`, but the collection
endpoint populates it only when the caller passes `include_rule_count`; the
default is false. The listing asked for nothing, the key was absent from every
row, and `p.get("rule_count", 0)` turned "the manager did not answer" into "the
answer is none". The unfiltered listing now requests it — riding the call it
already makes, no extra request — and a count that genuinely cannot be retrieved
comes back `null` with a note, never a fabricated `0`. The `name_filter` path
goes through the Search API, which serves indexed objects and cannot learn the
counts; it reports null rather than inventing them.

**A paging loop never terminated.** The four tools that already had `offset`
reported `truncated: true` on the last page, and on the empty page past the end.
The arithmetic ignored `offset` entirely: `returned < total` is true forever
once you are reading a collection in slices. They now emit `next_offset` — the
value to pass back, or `null` when the collection ends — and `truncated` keeps
its own meaning, which is "is `items` the whole collection?", still true on the
last page of a walk. Two questions, two keys.

`limit=0`, negatives and anything above the maximum are rejected with a message
naming the range, rather than clamped or read as "unlimited".

**`verify_ssl: false` needed a package this skill never declared** — a clean
install died with `No module named 'urllib3'` against a self-signed target,
which is the VCF default. The guarded code was already inert: this client is
httpx, which never used urllib3. Removed rather than declared.

**`doctor` reported on a different config file from the one the tools load**,
and the Dockerfile could not build the wheel it installs.

## v1.8.10 — two wrong numbers: the server's own version, and the advertised tool count

Both defects were invisible to the test suites and both were user-facing.

- **The MCP server reported the SDK's version as its own.** `FastMCP` accepts no
  `version` argument and leaves the lowlevel server's at `None`; with it `None`
  the SDK answers `initialize` with its OWN version. Every skill in the family
  therefore told its client it was mcp 1.29.1 — a number that exists for no
  package here, and one that would change with an SDK bump and no code change of
  ours. Verified end to end rather than by reading: unset the field and a probe
  server reports the installed SDK's version; set it and it reports ours.

Also new: this repo is installable as a Claude Code plugin
(`/plugin install vmware-nsx-security@vmware-skills`). The skill and its MCP server arrive in
one step; nothing is duplicated, the manifest points at the existing `skills/`
tree. family_smoke gained three gates — the server's reported version, the plugin
manifest's agreement with pyproject, and the advertised tool count against the
live registration.

## v1.8.9 — moved to vmware-skills org + MCP Registry namespace io.github.vmware-skills/vmware-nsx-security

Repo transferred from github.com/zw008 to github.com/vmware-skills (redirects preserve old links).
MCP Registry server renamed to `io.github.vmware-skills/*`; the old `io.github.zw008/*` entry is deprecated.
All in-repo links updated. No functional code change on this line beyond the org move.

## v1.8.8 — CLI writes now route through policy + audit, exactly like the MCP tools

Every state-changing CLI command is now wrapped by `@guarded`, the CLI counterpart
to the MCP `@vmware_tool` decorator: it runs the same vmware-policy `guard()`
authorization and writes the same `audit_call()` row to `~/.vmware/audit.db`. A
`delete`/`disable`/destructive command run through a shell is now authorized and
recorded exactly like the equivalent MCP tool — closing the gap where CLI writes
bypassed policy and landed only in the legacy per-skill log (HLD I-1/I-8).

- a policy `deny` rule now refuses the operation on the CLI with a teaching line
  naming the rule that fired, not a traceback
- the legacy per-skill audit log is still written this release (dual-write); it is
  removed at 2.0
- **requires vmware-policy >= 1.8.8** (the release that adds the shared `guarded` core)
- a regression test derives the write-command set from the MCP `[WRITE]` markers and
  asserts every one is `@guarded`, so a new write command cannot ship unguarded

Also carries the environment-field docstring correction (an optional label a `deny`
rule may scope to — there is no "warn now / refuse next major" gate).

## v1.8.7 (2026-07-21) — the skill-level read-only switch is removed; read/write authorization is the vCenter account's job (RBAC)

### Removed: `VMWARE_READ_ONLY` / `read_only:` — give the agent a read-only service account instead

The skill-level read-only switch is gone. It was enforced only on the MCP tool
registry, and any agent with a shell (every SKILL.md grants `allowed-tools: Bash`)
could reach the same change one CLI command away — so it withheld the *tool*, not
the *capability*. It was never a real boundary.

To run an agent read-only, give it a **read-only vCenter/NSX service account
(RBAC)**. Writes are then refused at the platform, un-bypassably, regardless of
surface or shell — the one place read/write control cannot be stepped around. A
config still carrying `read_only: true` is ignored, with a one-time warning that
names the replacement (no silent behavior change).

### Removed: approval tiers and the declared-environment gate (via vmware-policy)

The graduated-autonomy approval tiers (`confirm`/`dual`/`review`) and the "declare
an environment or be refused" baseline are removed — they only ever fired on the
rarest configuration while carrying the family's most complex machinery. Opt-in
`deny` rules and the maintenance window remain, and apply identically wherever a
tool runs.

### Added: offline / air-gapped install docs

The README now covers installing from source without editable mode (for older
`pip`) and building wheels to carry onto an air-gapped host — the modern PEP 517
layout has no `setup.py` by design, which is expected, not a missing file.

This release also carries the accumulated fixes staged since 1.8.5.

## v1.8.6 (unreleased) — `tags` comes back as a deprecated alias

### Fixed — a v1.8.0 rename that could invert a microsegmentation verdict

v1.8.0 said every `[READ]` list tool now returns the family envelope "instead of
a bare array". For `list_vm_tags` that was not true: it had returned a keyed
dict, `{vm_id, display_name, power_state, tags}`, and the conversion renamed
`tags` to `items`.

The distinction matters because it decides whether you find out. Replacing a
bare array with a dict breaks loudly — `result[0]` raises. Renaming a key inside
a dict that was already there breaks quietly: `result.get("tags", [])` kept
returning a value, just always `[]`.

**Here that empty list is not merely wrong, it is wrong in the direction of a
finding.** Code shaped like `if not result.get("tags", []): report_untagged(vm)`
did not start failing — it started reporting every VM as untagged. An untagged
VM is exactly what a microsegmentation audit is hunting for, so the broken read
does not surface as missing data.

The v1.8.0 notes made this worse rather than surfacing it. A reader who used
`list_vm_tags`, checked the sentence, saw that their payload was a keyed dict and
not a bare array, would correctly conclude the described change was not
theirs — and ship the bug. The v1.8.0 entry below now carries a correction
saying so explicitly.

**`tags` is restored as a deprecated alias**, pointing at the *same list object*
as `items` rather than a copy, so the two cannot drift. `items` remains the
primary key and the documented one. **`tags` is removed in 2.0** — migrate.

Pinned by `tests/eval/regression/test_deprecated_key_aliases.py`, which asserts
a pre-v1.8.0 caller still sees its tags, that a tagged VM is never reported
untagged, that the alias is the same object (verified by mutating one and
reading the other), and that `vm_id` — which the write path consumes — survives
the merge.

Three sibling tools shipped the same shape and are fixed in the same release:
`list_virtual_machines` in vmware-monitor, and `list_tkc_clusters` plus
`list_namespace_storage_usage` in vmware-vks.

---

## v1.8.5 (2026-07-20) — the two fixes v1.8.4 announced now actually work

Four adversarial reviews of v1.8.4 found that both of its headline fixes were
incomplete in ways the release notes did not reflect. This release makes them
real. If you are on 1.8.4, this is the one to take.

### Fixed — a failure that was *returned* was still audited as a success

vmware-policy 1.8.4 added `report_tool_failure()` for tools that catch an
exception and return an error payload instead of raising. **No skill called it.**

Every string-returning tool therefore kept doing exactly what 1.8.4 said it had
stopped doing: writing `status=ok` to `~/.vmware/audit.db` for an operation that
failed, recording an undo token for a change that never happened, and telling the
circuit breaker the call succeeded so repeated failures never tripped it.

The surface this covered is not marginal:

| Skill | What was mis-audited |
|---|---|
| vmware-aiops | 25 of 49 tools, including **every undo-bearing write** — a failed `vm_power_on` left an undo token saying "power it back off" |
| vmware-avi | all 28 tools, including `vs_toggle` and `ako_restart` |
| vmware-storage | all 4 write tools |
| vmware-nsx | the 5 delete tools |

vmware-avi is worth calling out: before 1.8.4 its exceptions propagated and the
audit was correct. 1.8.4 caught them and returned a string, so **that release made
its audit trail worse than it had been.**

Skills whose tools already return dict payloads (vmware-monitor, vmware-vks,
vmware-aria, vmware-log-insight, vmware-harden, vmware-debug, vmware-pilot) were
already detected correctly. They gained a test proving it rather than a redundant
call.

### Fixed — narrowing `OSError` did not close the leak it was meant to close

1.8.4 narrowed the `_safe_error` passthrough because bare `OSError` let TLS and
DNS failures reach the agent with hostnames and certificate subjects in them.
That narrowing had no effect on the error it was written for:

```
ssl.SSLCertVerificationError → ssl.SSLError → OSError, ValueError
```

`ValueError` has been on every allowlist since long before 1.8.4, so a
certificate failure kept passing through — the commonest self-signed-certificate
failure in this family, carrying the hostname it was checked against. An
allowlist structurally cannot express "not this one".

Where `ssl.SSLError` can actually surface — the pyVmomi skills — it is now
reduced *ahead* of the allowlist. In the httpx skills TLS arrives wrapped as
`httpx.ConnectError`, and in vmware-avi as `requests.exceptions.SSLError`, so the
guard cannot fire there; in those skills the leak was the raw exception
interpolated into an already-allowlisted `*ApiError`, and that is now authored
text naming the config target and `verify_ssl` instead of the exception.

The missing-password error — this family's most common first-run failure, whose
entire remedy is the environment variable name it carries — keeps its message
through a narrow `ConfigError(OSError)` rather than the base class. Connection
failures are translated at the connection layer into an authored remedy that
names the target and the setting to change, with the raw detail left on
`__cause__` for the server log.

### Also fixed

- **vmware-vks**: the quickstart documented a password variable the code never
  reads — following `README.md` verbatim produced "Password not found". Five
  places, plus six references to a `doctor` command this CLI has never had, two
  descriptions promising fields the tools do not return, and eight teaching
  messages that `RuntimeError` was masking.
- **vmware-nsx**: an error cited `--route-advertisement`; the flag is `--advertise`.
- **vmware-pilot**: `get_workflow_status` told the model to call `approve` — a
  tool the read-only gate withholds — as the required next step; and a hint
  pointed at a filename that could never appear in that message.
- **vmware-aiops**: `vm_task_status` polling a *failed task* returned
  `{"state": "error", "error": ...}` from a successful read, which the new
  detection read as the call itself failing. The field is now `task_error`.
  **This is a breaking change for anything parsing that payload.**
- Several remedies that were still being cut by the 300-character cap the 1.8.4
  notes claimed to have addressed.

### Known and not fixed

`ConnectionError` remains one type from two sources in several skills — a
skill's own authored message and urllib3's `HTTPSConnectionPool(host=..., port=...)`
share it, and an allowlist cannot separate them. vmware-vks is converted; the
rest need their own domain type and are deferred rather than half-done.

## v1.8.4 (2026-07-20) — errors that teach, and tool descriptions a small model can route from

A capability eval was rolled out across the family and asked two open questions:
when a call fails, is the model told enough to fix it, and can it pick the right
tool from the description alone? Both answers were worse than anyone thought, and
in several places the reason was that the measurement was looking somewhere other
than where the model reads.

### Fixed — teaching messages were being discarded on the way to the agent

`_safe_error` reduces unrecognised exceptions to `"<Class>: operation failed."`
so raw API text, credentials in URLs and internal paths cannot reach an agent.
Its allowlist held only the builtin validation errors — so this skill's **own**
domain exceptions, the ones that exist precisely to carry a corrected next step,
had their messages replaced by their class names.

The effect was invisible from the CLI, which prints those messages in full.

The worst case was shared by nine skills: `config.py` raises exactly one
`OSError`, the missing-password error, whose entire remedy is the environment
variable name it names. An agent hitting an unconfigured target received
`OSError: operation failed.` and had nothing to act on. That is the family's most
common first-run failure, and it landed one release after the documented variable
names were corrected — so the message that would have unstuck the operator was
the one being thrown away.

The rule is now the property it always meant: **every exception this skill raises
on purpose passes through**, and only genuinely unplanned ones are reduced.
`RuntimeError` stays reduced — it is the generic catch-all and in several skills
carries raw upstream text.

### Fixed — error messages now carry the correction

Every message that reported a failure without saying how to recover was
rewritten: it names the offending value, gives an imperative remedy, and names
something concrete to act on — a tool that exists, a real CLI command, a config
file, an environment variable. Recovery becomes an instruction-following problem
rather than an inference one, which is what a weak model can still do.

Three classes of defect surfaced while doing it:

- **Remedies that were never delivered.** `_safe_error` truncates with no
  ellipsis, so a message longer than the cap loses its closing sentence
  silently. One message had been shipping at 396 characters against a 300-char
  cap — its remedy had never once reached an agent. Messages now lead with the
  remedy so a long interpolated value truncates the expendable detail instead.
- **Commands that do not exist.** One skill's error hints named a `doctor`
  subcommand it does not have.
- **Tools that do not exist.** A tool description pointed at two sibling-skill
  tools that had been renamed, and another named a tool that had moved to a
  different skill entirely.

### Improved — tool descriptions state when to use them and what to call next

The description is the API for a small model: an unstated routing rule is a
routing rule that does not exist, and a tool with no stated next hop is one the
model stops at. Descriptions now say when to prefer this tool over a sibling,
what shape comes back, the caveat that bites, and which tool to call after.

**Manifest size did not grow.** Descriptions load into every session, so the
routing clauses were paid for by cutting duplicated reference material —
repeated boilerplate, examples that restated the parameter list, and prose
copies of the pagination contract.

### Note

Every tool and CLI command named anywhere in this release was verified against
the live MCP registry and the live command tree, not against documentation.

## v1.8.3 (2026-07-20) — credentials resolve as a pair; documented env vars now exist

### Added — the per-target username can come from the environment

Adapted from [VMware-AIops#33](https://github.com/vmware-skills/VMware-AIops/pull/33) by
@wright-bench, with thanks. The password already resolved from an env var; the
username did not, so a deployment injecting credentials from a secret store
(systemd `EnvironmentFile`, container secrets, a vault sidecar) could externalise
only half of the pair — and a config-file username paired with an env password
from a different account logs in as nobody.

`<PASSWORD-KEY-PREFIX>_USERNAME` now overrides the `username:` in config.yaml,
using that skill's own password-key convention. Absent, config.yaml still wins;
nothing changes for anyone not setting it.

**Resolved on every access, like the password.** The contributed version read the
username once at load time while the password stayed a property, which
reintroduces exactly the split the override exists to prevent: a sidecar rotating
both halves mid-process moves the password and leaves the username behind. A test
pins that both halves resolve at the same moment.

### Fixed — documented credential variables that the code never read

Rolling the above across the family surfaced a separate defect: four skills
documented a password variable their own loader does not look up. An operator
following the documentation exactly — correct file, correct place, correct-looking
name — got "Password not found".

| Skill | Documented | Actually read |
|---|---|---|
| vmware-nsx | `VMWARE_NSX_<TARGET>_PASSWORD` for target `nsx-prod` → `VMWARE_NSX_PROD_PASSWORD` | `VMWARE_NSX_NSX_PROD_PASSWORD` |
| vmware-nsx-security | `VMWARE_<TARGET>_PASSWORD` | `VMWARE_NSX_SECURITY_<TARGET>_PASSWORD` |
| vmware-aria | `VMWARE_<TARGET>_PASSWORD` | `VMWARE_ARIA_<TARGET>_PASSWORD` |
| vmware-vks | `VMWARE_<TARGET>_PASSWORD` | `VMWARE_VKS_<TARGET>_PASSWORD` |
| vmware-avi | three different forms across three files | `<CONTROLLER>_PASSWORD` |

The prefixes genuinely differ per skill, so nothing could be fixed by
standardising a pattern — each repo's docs were corrected against its own code.
The code was left alone: changing a key would break every existing deployment.

`family_smoke.sh` now compares the credential variables named in each repo's docs
against the ones that repo's code builds, so the two cannot drift apart again.

## v1.8.2 (2026-07-20) — the MCP server moves into the package namespace

### Fixed — co-installing two skills broke all but the last one

Every skill shipped its MCP server as a **top-level `mcp_server` package**. Python
has one top-level namespace, so installing any two of them into one environment let
the second overwrite the first — silently, with no error and no warning.

    uv tool install vmware-aiops   ->  49 tools   (correct)
    uv pip  install vmware-aiops   ->  27 tools   (Monitor's read-only server)

vmware-aiops depends on vmware-monitor, so this was not an edge case: **every pip
install hit it**, and the operator got 27 read-only tools where 49 were expected,
with all 35 write tools missing. Docker images, shared MCP hosts and CI runners that
install more than one skill were affected the same way.

The server now lives at `vmware_<skill>/mcp_server/`, a name only this package can
claim. Introduced 2026-02-26; it survived 70 releases because every test ran against
a single package in its own repo, where the local directory shadows site-packages —
the conflict was invisible by construction.

**Migration.** Console scripts are unchanged: `vmware-<skill>` and
`vmware-<skill>-mcp` work exactly as before, as does `"command": "vmware-<skill>",
"args": ["mcp"]` in an MCP client config. Only a direct `python -m mcp_server`
breaks; use `python -m vmware_<skill>.mcp_server`.

### Added — `references/agent-guardrails.md` in every skill

The operating rules for local and small models (Llama 3.3 70B, Qwen, Mistral via
Goose / Ollama / OpenShift AI) existed in two skills. They now ship in all 13, each
with its own tool counts and failure modes, and are linked from every SKILL.md.

## v1.8.1 (2026-07-19) — read-only mode reaches the surfaces that teach it

v1.8.0 put read-only mode in the code and documented it in the README only.
Every other layer was empty, and each serves a different reader: SKILL.md is what
the agent loads, setup-guide is what an operator reads while configuring, `doctor`
is where they verify it took. The gap had two concrete costs.

An agent read SKILL.md, called a write tool the gate had withheld, and got nothing
back — with no way to learn that the absence was a deliberate lockdown rather than
a fault. It reads as a broken tool, so the model retries or hunts for a workaround.

An operator who set the switch had no way to confirm it. The only signal was a line
in the MCP server's start-up log.

### Added — the feature is now documented where each reader looks

- **SKILL.md** — a short section telling the agent that a missing write tool is a
  lockdown, not a fault: name the blocked operation, do not retry, do not route
  around it.
- **references/setup-guide.md** — the operator's view: how to enable it, the
  precedence chain, and how to verify.
- **references/capabilities.md** — which tools the gate withholds.

### Added — `doctor` reports the read-only state

`vmware-nsx-security doctor` now shows whether read-only mode is on, **which** of the three
switches decided it, and the value as written. A typo'd value (`ture`) is called
out as a typo rather than reported as a confident ON — it resolves to on, which is
fail-closed but almost never what was meant.

The resolution runs through `vmware_policy.read_only_status()` rather than a local
copy of the precedence chain: a doctor that disagrees with the gate it reports on is
worse than no doctor. Requires `vmware-policy>=1.8.1`.

## v1.8.0 (2026-07-18) — read-only mode, working policy defaults, declared environments

Family release driven by [VMware-AIops#31](https://github.com/vmware-skills/VMware-AIops/issues/31),
where an operator running Llama 3.3 70B (Goose / OpenShift AI, on-prem H100) had to
hand-write 17 prompt guardrails to make tool calling reliable. A prompt is advisory — a
model can ignore it. Every guardrail that could move into the harness has.

### Added
- **Read-only mode.** Set `VMWARE_READ_ONLY=true` (or `VMWARE_<SKILL>_READ_ONLY`, or
  `read_only: true` in config.yaml) and every write tool is removed from the MCP registry
  at start-up. `list_tools()` never offers them, so the model cannot call what it cannot
  see. **Off by default** — nothing changes unless you turn it on. Fail-closed: if the
  mode is requested but cannot be guaranteed, the server refuses to start rather than
  running open.
- **`environment:` on each config target**, declaring which environment it is
  (production / staging / lab). Policy rules scope by this value.

### Added — list results now state whether they are complete

Every `[READ]` list tool returns the family envelope instead of a bare array:

    {"items": [...], "returned": 50, "limit": 50, "total": 213,
     "truncated": true, "hint": "Showing 50 of 213. Raise limit or narrow the query..."}

This closes the reported failure where long responses were summarised as "no data
returned": a bare list gives a model no way to tell a complete answer from page one, so
it guessed. `truncated: false` now positively states completeness — including when
`items` is empty, which means "checked, found none", not "the call failed".

> **Correction (v1.8.6).** The sentence "instead of a bare array" above is true
> of most tools converted family-wide, and false of exactly four. One of them
> is in this repo.
>
> (The four were established by an AST key-loss diff over every returning
> function in all twelve repos, mutation-verified in both directions. The
> total converted count is not restated here because it was never verified to
> the same standard — and a correction is the wrong place for a number
> nobody checked.)
>
> **`list_vm_tags` was never a bare array.** Before v1.8.0 it returned a keyed
> dict — `{vm_id, display_name, power_state, tags}` — and the conversion renamed
> `tags` to `items`. That is a different kind of break from the other 51. A
> bare-array caller doing `result[0]` gets an immediate `KeyError` on a dict and
> finds out at once; a caller doing `result.get("tags", [])` kept running and
> saw an empty tag list.
>
> **This one inverts a security verdict.** Code shaped like
> `if not result.get("tags", []): report_untagged(vm)` did not start failing —
> it started reporting *every* VM as untagged. An untagged VM is what a
> microsegmentation audit is looking for, so the broken read does not look like
> missing data. It looks like a finding.
>
> If you read this section when v1.8.0 shipped, checked `list_vm_tags`, saw a
> keyed dict and concluded the change did not apply to you: it did. The count in
> the bullet below is the tell — four tools are listed as converted, but five
> `list_*` ops functions return the envelope. `list_vm_tags` is the one missing
> from the count, and it was left out of the prose for the same reason.
>
> **v1.8.6 restores `tags`** as a deprecated alias pointing at the *same list
> object* as `items` (not a copy — copies drift). It is removed in 2.0. Migrate
> to `items`.
>
> The other three, for anyone running more of the family: `list_virtual_machines`
> (`vms` → `items`) in vmware-monitor, and `list_tkc_clusters`
> (`clusters` → `items`) plus `list_namespace_storage_usage` (`pvcs` → `items`,
> `pvc_count` deleted outright) in vmware-vks.

- **4 tool(s) converted** across ops, MCP and CLI. `total` is derived from what the code proves rather than from the wire: the client
  either drains the cursor or stops at its 1000-item cap, so a fetch under the cap
  consumed every page. It is measured before client-side filtering — a filter can shrink
  a capped scan below the cap and turn "unknown" into a confident lie. Name-filtered and
  capped listings therefore report `total: null`.

### Fixed
- **Deleting an empty DFW policy was about to start failing.** The pre-delete check read
  `if list_dfw_rules(...)` — truthy for an envelope dict whether or not it holds rows, so
  every policy delete would have been refused with "it still contains firewall rule(s)".
  Caught while converting; the existing suite only covered the has-rules branch, so the
  empty-policy branch is now pinned by its own test.

### Changed — migration, read this
- **Approval tiers now actually run.** They shipped in v1.6.0 but the engine only ever
  read `~/.vmware/rules.yaml`, and a fresh install has no such file — so every deny rule,
  maintenance window and approval tier had been inert on every install that never
  hand-authored one. A packaged baseline now loads when you have written no rules of your
  own. Writes at medium risk and above are stamped with their tier in the audit log;
  irreversible work and guest execution against a target declared `production` require a
  named approver via `VMWARE_AUDIT_APPROVED_BY`.
- **`environment:` will become required for writes.** Today a state-changing operation
  against a target that declares none still runs and logs a warning. **The next major
  release refuses it.** Declare it now and that upgrade is a no-op:

      targets:
        prod-vc01:
          host: vc01.corp.local
          environment: production

  Read-only operations are never affected, in this release or the next. Check what applies
  to your targets before upgrading: `vmware-audit policy --operation vm_delete --env <env>`.

### Fixed
- **Policy glob patterns with a leading wildcard silently matched nothing.** A rule written
  `operations: ["*_delete"]` parsed fine, read correctly, and never fired — only a trailing
  `*` was honoured. Now full glob matching, for operations and environments alike.
- Config-path overrides (`VMWARE_<SKILL>_CONFIG`) are honoured when reading `read_only`
  and `environment`, so a setting in a custom config file is no longer silently ignored.

### Notes
- Requires `vmware-policy>=1.8.0`; publish that package first.
- `vmware-audit policy` reports which rules are in force and where they came from —
  including the case where your rules file exists but failed to parse, which previously
  looked identical to "policy is working".

## v1.7.5 (2026-07-13) — internal dead-code cleanup + family version alignment

### Internal
- Removed an unused `CONFIG_DIR` import (cli). No behavior change; MCP tool
  surface unchanged (21).

## v1.7.4 (2026-07-13) — family version alignment

## v1.7.3 (2026-07-03) — family version alignment

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