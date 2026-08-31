"""CLI entry point for VMware NSX Security.

Provides DFW policy/rule management, security group operations, VM tag
management, traceflow, and IDPS queries with --dry-run preview and
double confirmation for destructive actions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from vmware_policy import PolicyDenied, guarded

from vmware_nsx_security.notify.audit import AuditLogger
import sys


def _harden_console_encoding() -> None:
    """Never let one unrepresentable glyph kill a command.

    On a console whose encoding cannot carry the characters we print -- cp936 on
    the Chinese Windows boxes this family is tested on, or any ASCII locale --
    ``print`` raises ``UnicodeEncodeError`` and the whole command dies with a
    traceback. ``--help`` died that way in four repos. A mangled dash is a
    cosmetic loss; a dead ``--help`` is an outage, so the error handler is
    relaxed rather than the vocabulary narrowed.

    Best effort: ``reconfigure`` is absent when stdout has been replaced by a
    plain object (pytest capture, some MCP hosts), and losing the hardening
    there is not worth an exception at import.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


_harden_console_encoding()

_audit = AuditLogger()

app = typer.Typer(
    name="vmware-nsx-security",
    help="VMware NSX DFW microsegmentation and security operations.",
    no_args_is_help=True,
)
console = Console()

# ─── Sub-command groups ──────────────────────────────────────────────────────

policy_app = typer.Typer(help="DFW security policy management: list, get, create, update, delete.")
rule_app = typer.Typer(help="DFW rule management: list, create, update, delete, stats.")
group_app = typer.Typer(help="Security group management: list, get, create, delete.")
tag_app = typer.Typer(help="VM NSX tag management: list, apply, remove.")
traceflow_app = typer.Typer(help="Traceflow packet tracing: run, get.")
idps_app = typer.Typer(help="IDPS: list profiles, check engine status.")

app.add_typer(policy_app, name="policy")
app.add_typer(rule_app, name="rule")
app.add_typer(group_app, name="group")
app.add_typer(tag_app, name="tag")
app.add_typer(traceflow_app, name="traceflow")
app.add_typer(idps_app, name="idps")

# ─── Type aliases ────────────────────────────────────────────────────────────

TargetOption = Annotated[str | None, typer.Option("--target", "-t", help="Target name from config")]
ConfigOption = Annotated[Path | None, typer.Option("--config", "-c", help="Config file path")]
DryRunOption = Annotated[bool, typer.Option("--dry-run", help="Print API calls without executing")]
NameFilterOption = Annotated[
    str | None,
    typer.Option("--name-filter", help="Substring/glob match on display name"),
]
LimitOption = Annotated[
    int,
    typer.Option("--limit", help="Page size, 1-1000 (default 50); 0 or negative is rejected"),
]
OffsetOption = Annotated[
    int,
    typer.Option("--offset", help="Rows to skip, 0 or more; use next_offset from the last page"),
]


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _cli_errors(fn):
    """Translate known errors into a red one-liner + exit code 1.

    Catches the connection layer's teaching ``NsxApiError`` plus common
    local failures (missing config file, bad lookup key, OS errors) so CLI
    users see an actionable message instead of a raw traceback. Unknown
    exceptions still propagate with a full traceback for debugging.
    """
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        from vmware_nsx_security.connection import NsxApiError

        try:
            return fn(*args, **kwargs)
        except (typer.Exit, typer.Abort):
            raise
        except PolicyDenied as exc:
            # A deny rule or maintenance window refused this write — @guarded ran
            # guard() before the body and already wrote the status="denied" audit
            # row. Teach the operator which rule fired instead of a traceback.
            rule = f" [dim](rule: {exc.result.rule})[/]" if exc.result.rule else ""
            console.print(f"[bold red]Denied by policy:[/] {exc.result.reason}{rule}")
            raise typer.Exit(1) from exc
        except (NsxApiError, FileNotFoundError, KeyError, OSError, ValueError) as exc:
            # KeyError reprs its message with quotes — unwrap for display.
            msg = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
            console.print(f"[bold red]Error:[/] {msg}")
            raise typer.Exit(1) from exc

    return wrapper


def _audit_write(target: str, operation: str, resource: str, parameters: dict | None = None):
    """Run a write call auditing both outcomes (success-only audit was a gap)."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        try:
            yield
        except BaseException:
            _audit.log(target=target, operation=operation, resource=resource, parameters=parameters, result="error")
            raise
        _audit.log(target=target, operation=operation, resource=resource, parameters=parameters, result="ok")

    return _ctx()


def _get_connection(target: str | None, config_path: Path | None = None):
    """Return (NsxClient, AppConfig)."""
    from vmware_nsx_security.config import load_config
    from vmware_nsx_security.connection import ConnectionManager

    cfg = load_config(config_path)
    mgr = ConnectionManager(cfg)
    name = target or cfg.default_target
    return mgr.connect(name), cfg


def _resolve_target(target: str | None) -> str:
    """Return display name for audit logs."""
    return target or "default"


def _dry_run_print(
    *,
    target: str,
    resource: str,
    operation: str,
    api_call: str,
    parameters: dict | None = None,
) -> None:
    """Print a dry-run preview of the API call that would be made."""
    console.print("\n[bold magenta][DRY-RUN] No changes will be made.[/]")
    console.print(f"[magenta]  Target:    {target}[/]")
    console.print(f"[magenta]  Resource:  {resource}[/]")
    console.print(f"[magenta]  Operation: {operation}[/]")
    console.print(f"[magenta]  API Call:  {api_call}[/]")
    if parameters:
        console.print(f"[magenta]  Params:    {json.dumps(parameters, indent=2)}[/]")
    console.print()


def _confirm_destructive(resource_type: str, resource_id: str) -> bool:
    """Double-confirmation prompt for destructive operations."""
    console.print(f"[bold red]WARNING:[/] This will permanently delete {resource_type} '[bold]{resource_id}[/]'.")
    first = typer.confirm("Are you sure you want to proceed?", default=False)
    if not first:
        return False
    second = typer.confirm(
        f"Second confirmation: DELETE {resource_type} '{resource_id}'?",
        default=False,
    )
    return second


# ═══════════════════════════════════════════════════════════════════════════════
# DFW Policy commands
# ═══════════════════════════════════════════════════════════════════════════════


@policy_app.command("list")
@_cli_errors
def policy_list(
    target: TargetOption = None,
    config: ConfigOption = None,
    name_filter: NameFilterOption = None,
    limit: LimitOption = 50,
    offset: OffsetOption = 0,
) -> None:
    """List DFW security policies (default 50; filter with --name-filter)."""
    from vmware_nsx_security.ops.dfw_policy import list_dfw_policies

    client, _ = _get_connection(target, config)
    result = list_dfw_policies(client, name_filter=name_filter, limit=limit, offset=offset)
    policies = result["items"]

    table = Table(title="DFW Security Policies")
    table.add_column("ID")
    table.add_column("Display Name")
    table.add_column("Category")
    table.add_column("Seq#", justify="right")
    table.add_column("Stateful")
    table.add_column("Rules", justify="right")

    for p in policies:
        table.add_row(
            p["id"],
            p["display_name"],
            p["category"],
            str(p["sequence_number"]),
            str(p["stateful"]),
            # "?" rather than "0" or "None": an unretrieved count must not
            # read as an empty policy in the one column an operator scans to
            # find where rules live.
            "?" if p["rule_count"] is None else str(p["rule_count"]),
        )
    console.print(table)
    if result.get("rule_count_note"):
        console.print(f"[yellow]? = rule count not retrieved.[/yellow] {result['rule_count_note']}")


@policy_app.command("get")
@_cli_errors
def policy_get(
    policy_id: str = typer.Argument(..., help="Policy ID"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Get details of a DFW security policy."""
    from vmware_nsx_security.ops.dfw_policy import get_dfw_policy

    client, _ = _get_connection(target, config)
    p = get_dfw_policy(client, policy_id)
    console.print_json(json.dumps(p))


@policy_app.command("create")
@_cli_errors
@guarded(risk_level='medium')
def policy_create(
    policy_id: str = typer.Argument(..., help="Policy ID"),
    display_name: str = typer.Option(..., "--name", help="Display name"),
    category: str = typer.Option("Application", "--category", help="Policy category"),
    sequence_number: int = typer.Option(10, "--seq", help="Sequence number"),
    description: str = typer.Option("", "--description", help="Description"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Create a DFW security policy."""
    from vmware_nsx_security.ops.dfw_policy import create_dfw_policy

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=policy_id,
            operation="create_dfw_policy",
            api_call=f"PUT /policy/api/v1/infra/domains/default/security-policies/{policy_id}",
            parameters={"display_name": display_name, "category": category, "sequence_number": sequence_number},
        )
        return

    client, _ = _get_connection(target, config)
    with _audit_write(t, "create_dfw_policy", policy_id):
        result = create_dfw_policy(
            client,
            policy_id,
            display_name,
            category=category,
            sequence_number=sequence_number,
            description=description,
        )
    console.print(f"[green]Created DFW policy '{policy_id}'[/]")
    console.print_json(json.dumps(result))


@policy_app.command("delete")
@_cli_errors
@guarded(risk_level='high')
def policy_delete(
    policy_id: str = typer.Argument(..., help="Policy ID to delete"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Delete a DFW security policy (checks for active rules first)."""
    from vmware_nsx_security.ops.dfw_policy import delete_dfw_policy

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=policy_id,
            operation="delete_dfw_policy",
            api_call=f"DELETE /policy/api/v1/infra/domains/default/security-policies/{policy_id}",
        )
        return

    if not _confirm_destructive("DFW policy", policy_id):
        console.print("Aborted.")
        raise typer.Exit(0)

    client, _ = _get_connection(target, config)
    with _audit_write(t, "delete_dfw_policy", policy_id):
        result = delete_dfw_policy(client, policy_id)
    console.print(f"[green]{result['message']}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# DFW Rule commands
# ═══════════════════════════════════════════════════════════════════════════════


@rule_app.command("list")
@_cli_errors
def rule_list(
    policy_id: str = typer.Argument(..., help="Parent policy ID"),
    target: TargetOption = None,
    config: ConfigOption = None,
    limit: LimitOption = 50,
    offset: OffsetOption = 0,
) -> None:
    """List rules in a DFW policy (first 50 by default; page with --offset)."""
    from vmware_nsx_security.ops.dfw_policy import list_dfw_rules

    client, _ = _get_connection(target, config)
    rules = list_dfw_rules(client, policy_id, limit=limit, offset=offset)["items"]

    table = Table(title=f"DFW Rules in Policy '{policy_id}'")
    table.add_column("ID")
    table.add_column("Display Name")
    table.add_column("Action")
    table.add_column("Direction")
    table.add_column("Disabled")
    table.add_column("Logged")

    for r in rules:
        table.add_row(
            r["id"],
            r["display_name"],
            r["action"],
            r["direction"],
            str(r["disabled"]),
            str(r["logged"]),
        )
    console.print(table)


@rule_app.command("stats")
@_cli_errors
def rule_stats(
    policy_id: str = typer.Argument(..., help="Parent policy ID"),
    rule_id: str = typer.Argument(..., help="Rule ID"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Get hit-count statistics for a DFW rule."""
    from vmware_nsx_security.ops.dfw_rules import get_dfw_rule_stats

    client, _ = _get_connection(target, config)
    stats = get_dfw_rule_stats(client, policy_id, rule_id)
    console.print_json(json.dumps(stats))


@rule_app.command("delete")
@_cli_errors
@guarded(risk_level='high')
def rule_delete(
    policy_id: str = typer.Argument(..., help="Parent policy ID"),
    rule_id: str = typer.Argument(..., help="Rule ID to delete"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Delete a DFW rule."""
    from vmware_nsx_security.ops.dfw_rules import delete_dfw_rule

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=f"{policy_id}/{rule_id}",
            operation="delete_dfw_rule",
            api_call=f"DELETE ...security-policies/{policy_id}/rules/{rule_id}",
        )
        return

    if not _confirm_destructive("DFW rule", rule_id):
        console.print("Aborted.")
        raise typer.Exit(0)

    client, _ = _get_connection(target, config)
    with _audit_write(t, "delete_dfw_rule", f"{policy_id}/{rule_id}"):
        result = delete_dfw_rule(client, policy_id, rule_id)
    console.print(f"[green]{result['message']}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# Security Group commands
# ═══════════════════════════════════════════════════════════════════════════════


@group_app.command("list")
@_cli_errors
def group_list(
    target: TargetOption = None,
    config: ConfigOption = None,
    name_filter: NameFilterOption = None,
    limit: LimitOption = 50,
    offset: OffsetOption = 0,
) -> None:
    """List security groups (default 50; filter with --name-filter)."""
    from vmware_nsx_security.ops.security_group import list_groups

    client, _ = _get_connection(target, config)
    groups = list_groups(client, name_filter=name_filter, limit=limit, offset=offset)["items"]

    table = Table(title="Security Groups")
    table.add_column("ID")
    table.add_column("Display Name")
    table.add_column("Description")
    table.add_column("Expressions", justify="right")

    for g in groups:
        table.add_row(
            g["id"],
            g["display_name"],
            g["description"][:60],
            str(g["expression_count"]),
        )
    console.print(table)


@group_app.command("get")
@_cli_errors
def group_get(
    group_id: str = typer.Argument(..., help="Group ID"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Get details and members of a security group."""
    from vmware_nsx_security.ops.security_group import get_group

    client, _ = _get_connection(target, config)
    g = get_group(client, group_id)
    console.print_json(json.dumps(g))


@group_app.command("delete")
@_cli_errors
@guarded(risk_level='high')
def group_delete(
    group_id: str = typer.Argument(..., help="Group ID to delete"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Delete a security group (checks DFW policy references first)."""
    from vmware_nsx_security.ops.security_group import delete_group

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=group_id,
            operation="delete_group",
            api_call=f"DELETE /policy/api/v1/infra/domains/default/groups/{group_id}",
        )
        return

    if not _confirm_destructive("security group", group_id):
        console.print("Aborted.")
        raise typer.Exit(0)

    client, _ = _get_connection(target, config)
    with _audit_write(t, "delete_group", group_id):
        result = delete_group(client, group_id)
    console.print(f"[green]{result['message']}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# Tag commands
# ═══════════════════════════════════════════════════════════════════════════════


@tag_app.command("list")
@_cli_errors
def tag_list(
    vm_name: str = typer.Argument(..., help="VM display name"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """List NSX tags applied to a VM."""
    from vmware_nsx_security.ops.tags import list_vm_tags

    client, _ = _get_connection(target, config)
    result = list_vm_tags(client, vm_name)

    console.print(f"[bold]VM:[/] {result['display_name']}  [bold]ID:[/] {result['vm_id']}")
    table = Table(title="NSX Tags")
    table.add_column("Scope")
    table.add_column("Tag")
    for t_entry in result.get("items", []):
        table.add_row(t_entry.get("scope", ""), t_entry.get("tag", ""))
    console.print(table)


@tag_app.command("apply")
@_cli_errors
@guarded(risk_level='medium')
def tag_apply(
    vm_id: str = typer.Argument(..., help="VM external ID"),
    scope: str = typer.Option(..., "--scope", help="Tag scope"),
    value: str = typer.Option(..., "--value", help="Tag value"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Apply an NSX tag to a VM."""
    from vmware_nsx_security.ops.tags import apply_vm_tag

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=vm_id,
            operation="apply_vm_tag",
            api_call="POST /api/v1/fabric/virtual-machines?action=add_tags",
            parameters={"external_id": vm_id, "scope": scope, "tag": value},
        )
        return

    client, _ = _get_connection(target, config)
    with _audit_write(t, "apply_vm_tag", vm_id, {"scope": scope, "tag": value}):
        apply_vm_tag(client, vm_id, scope, value)
    console.print(f"[green]Applied tag {scope}={value} to VM {vm_id}[/]")


@tag_app.command("remove")
@_cli_errors
@guarded(risk_level='medium')
def tag_remove(
    vm_id: str = typer.Argument(..., help="VM external ID"),
    scope: str = typer.Option(..., "--scope", help="Tag scope to remove"),
    value: str = typer.Option(..., "--value", help="Tag value to remove"),
    dry_run: DryRunOption = False,
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Remove an NSX tag from a VM."""
    from vmware_nsx_security.ops.tags import remove_vm_tag

    t = _resolve_target(target)
    if dry_run:
        _dry_run_print(
            target=t,
            resource=vm_id,
            operation="remove_vm_tag",
            api_call="POST /api/v1/fabric/virtual-machines?action=remove_tags",
            parameters={"external_id": vm_id, "scope": scope, "tag": value},
        )
        return

    client, _ = _get_connection(target, config)
    with _audit_write(t, "remove_vm_tag", vm_id, {"scope": scope, "tag": value}):
        remove_vm_tag(client, vm_id, scope, value)
    console.print(f"[green]Removed tag {scope}={value} from VM {vm_id}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# Traceflow commands
# ═══════════════════════════════════════════════════════════════════════════════


@traceflow_app.command("run")
@_cli_errors
@guarded(risk_level='medium')
def traceflow_run(
    src_lport: str = typer.Argument(..., help="Source logical port ID"),
    src_ip: str = typer.Option(..., "--src-ip", help="Source IP address"),
    dst_ip: str = typer.Option(..., "--dst-ip", help="Destination IP address"),
    protocol: str = typer.Option("TCP", "--proto", help="Protocol: TCP, UDP, or ICMP"),
    dst_port: int = typer.Option(80, "--dst-port", help="Destination port"),
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Run a Traceflow packet trace from a logical port."""
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client, _ = _get_connection(target, config)
    result = run_traceflow(client, src_lport, src_ip, dst_ip, protocol=protocol, dst_port=dst_port)
    console.print_json(json.dumps(result))


# ═══════════════════════════════════════════════════════════════════════════════
# IDPS commands
# ═══════════════════════════════════════════════════════════════════════════════


@idps_app.command("profiles")
@_cli_errors
def idps_profiles(
    target: TargetOption = None,
    config: ConfigOption = None,
    name_filter: NameFilterOption = None,
    limit: LimitOption = 50,
    offset: OffsetOption = 0,
) -> None:
    """List IDPS profiles (default 50; filter with --name-filter)."""
    from vmware_nsx_security.ops.idps import list_idps_profiles

    client, _ = _get_connection(target, config)
    profiles = list_idps_profiles(client, name_filter=name_filter, limit=limit, offset=offset)["items"]

    table = Table(title="IDPS Profiles")
    table.add_column("ID")
    table.add_column("Display Name")
    table.add_column("Severity")
    table.add_column("Overridden Sigs", justify="right")

    for p in profiles:
        table.add_row(
            p["id"],
            p["display_name"],
            p["profile_severity"],
            str(p["overridden_signature_count"]),
        )
    console.print(table)


@idps_app.command("status")
@_cli_errors
def idps_status(
    target: TargetOption = None,
    config: ConfigOption = None,
) -> None:
    """Get IDPS engine status."""
    from vmware_nsx_security.ops.idps import get_idps_status

    client, _ = _get_connection(target, config)
    status = get_idps_status(client)
    console.print_json(json.dumps(status))


# ═══════════════════════════════════════════════════════════════════════════════
# Init / Doctor
# ═══════════════════════════════════════════════════════════════════════════════


@app.command("init")
@_cli_errors
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config"),
    skip_test: bool = typer.Option(False, "--skip-test", help="Skip the post-setup connection test"),
) -> None:
    """Interactive first-run setup: write config.yaml + .env, then verify.

    Prompts for the NSX Manager host, username, port, TLS verification, and
    password. The password is written to ~/.vmware-nsx-security/.env in
    grep-safe b64: form (0600), never plaintext. Offers to run doctor as a
    connection test when done.
    """
    from vmware_nsx_security.init_wizard import run_init

    raise typer.Exit(run_init(force=force, skip_test=skip_test))


@app.command("doctor")
@_cli_errors
def doctor(
    skip_auth: bool = typer.Option(False, "--skip-auth", help="Skip authentication test"),
    config: ConfigOption = None,
) -> None:
    """Run pre-flight environment diagnostics."""
    from vmware_nsx_security.doctor import run_doctor

    ok = run_doctor(config_path=config, skip_auth=skip_auth)
    raise typer.Exit(0 if ok else 1)


@app.command("mcp")
@_cli_errors
def mcp_cmd() -> None:
    """Start the MCP server (stdio transport).

    Single-command entry point for MCP clients:
        vmware-nsx-security mcp

    Equivalent to the legacy `vmware-nsx-security-mcp` console script.
    """
    import sys

    if sys.version_info < (3, 10):
        msg = (
            f"ERROR: vmware-nsx-security MCP server requires Python >= 3.10 "
            f"(got {sys.version_info.major}.{sys.version_info.minor}).\n"
            f"Interpreter: {sys.executable}\n"
            "Fix: uv python install 3.12 && "
            "uv tool install --python 3.12 --force vmware-nsx-security"
        )
        typer.echo(msg, err=True)
        raise typer.Exit(2)

    from vmware_nsx_security.mcp_server.server import main as _mcp_main

    _mcp_main()


if __name__ == "__main__":
    app()
