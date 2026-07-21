"""Every CLI command that performs a write is wrapped by @guarded (HLD I-1, I-8).

A write CLI command must route through vmware_policy's guard() + audit_call() —
the same enforcement @vmware_tool gives the MCP surface — so ``vmware-nsx-security
policy delete`` run through Bash is authorized and audited to ~/.vmware/audit.db
exactly like the ``delete_dfw_policy`` MCP tool. Without @guarded a CLI write
bypassed policy and landed only in the legacy per-skill log (the gap HLD §2.1
documents).

The write set is DERIVED, never hand-listed (踩坑 #43): a tool annotated
``readOnlyHint=False`` is a write; the ops functions its body calls — reached by
a bare name OR ``module.func`` on an ops-module import — are the state-changing
ops; a CLI ``@command`` calling one is a write command and must carry @guarded.

Import resolution is scoped to the DEFINING function, not the file. NSX-Security's
MCP tools each do ``from ops.X import realname as _fn`` inside their own body,
reusing the alias ``_fn`` across every tool in a module. A file-scoped map
collapses every ``_fn`` to the module's LAST import (tags → remove_vm_tag,
traceflow → get_traceflow_result), so create_dfw_policy / apply_vm_tag /
run_traceflow silently drop out of the write set and their CLI commands look
already-safe — the "empty results read as no problem" shape. Function-scoped
resolution keeps each ``_fn`` bound to its own op.
"""
from __future__ import annotations

import ast
import asyncio
import pathlib

_REPO = pathlib.Path(__file__).resolve().parents[3]
_PKG = _REPO / "vmware_nsx_security"
# The CLI may be a package dir or a single module; resolve to concrete files and
# refuse an empty scan (a check that scans nothing still reports green).
_CLI_DIR = _PKG / "cli"
CLI_FILES = sorted(_CLI_DIR.rglob("*.py")) if _CLI_DIR.is_dir() else [_PKG / "cli.py"]
TOOLS_DIR = _PKG / "mcp_server" / "tools"
assert CLI_FILES and all(p.is_file() for p in CLI_FILES), (
    f"no CLI source found under {_PKG} — the scan would find nothing"
)
assert TOOLS_DIR.is_dir(), f"MCP tools not found at {TOOLS_DIR} — the derivation would be empty"


def _write_tool_names() -> frozenset[str]:
    from vmware_nsx_security.mcp_server.server import mcp

    return frozenset(
        t.name
        for t in asyncio.run(mcp.list_tools())
        if getattr(getattr(t, "annotations", None), "readOnlyHint", None) is False
    )


def _refs_from(nodes) -> tuple[dict[str, str], set[str]]:
    """(local name -> REAL ops function name, ops-module aliases) over ImportFrom nodes."""
    func_map: dict[str, str] = {}
    mods: set[str] = set()
    for n in nodes:
        if isinstance(n, ast.ImportFrom) and n.module:
            parts = n.module.split(".")
            if "ops" in parts:
                if parts[-1] == "ops":
                    mods.update(a.asname or a.name for a in n.names)
                else:
                    for a in n.names:
                        func_map[a.asname or a.name] = a.name
    return func_map, mods


def _module_refs(tree: ast.AST) -> tuple[dict[str, str], set[str]]:
    """Top-level ops imports (shared by every function in the file)."""
    return _refs_from(tree.body)


def _func_refs(
    func_node: ast.AST, base_map: dict[str, str], base_mods: set[str]
) -> tuple[dict[str, str], set[str]]:
    """Module-level refs merged with imports inside this function (function wins)."""
    fm, md = dict(base_map), set(base_mods)
    local_map, local_mods = _refs_from(ast.walk(func_node))
    fm.update(local_map)
    md.update(local_mods)
    return fm, md


def _ops_calls(node: ast.AST, func_map: dict[str, str], mods: set[str]) -> set[str]:
    """Real ops function names called in ``node`` — via ``f()`` or ``mod.f()``."""
    out: set[str] = set()
    for c in ast.walk(node):
        if not isinstance(c, ast.Call):
            continue
        f = c.func
        if isinstance(f, ast.Name) and f.id in func_map:
            out.add(func_map[f.id])
        elif (
            isinstance(f, ast.Attribute)
            and isinstance(f.value, ast.Name)
            and f.value.id in mods
        ):
            out.add(f.attr)
    return out


def _write_ops() -> frozenset[str]:
    targets = _write_tool_names()
    assert targets, "no write MCP tools (readOnlyHint=False) — derivation would be vacuous"
    ops: set[str] = set()
    for path in sorted(TOOLS_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        base_map, base_mods = _module_refs(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in targets:
                func_map, mods = _func_refs(node, base_map, base_mods)
                ops |= _ops_calls(node, func_map, mods)
    return frozenset(ops)


def _decorator_names(node: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for d in node.decorator_list:
        t = d.func if isinstance(d, ast.Call) else d
        if isinstance(t, ast.Name):
            names.add(t.id)
        elif isinstance(t, ast.Attribute):
            names.add(t.attr)
    return names


def _cli_write_commands() -> tuple[list[str], list[str]]:
    """(write commands, of those the ones missing @guarded)."""
    write_ops = _write_ops()
    assert write_ops, "no write ops derived — vacuous"
    writing: list[str] = []
    unguarded: list[str] = []
    for path in CLI_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        base_map, base_mods = _module_refs(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not any(
                isinstance(d, ast.Call)
                and isinstance(getattr(d, "func", None), ast.Attribute)
                and d.func.attr == "command"
                for d in node.decorator_list
            ):
                continue
            func_map, mods = _func_refs(node, base_map, base_mods)
            if _ops_calls(node, func_map, mods) & write_ops:
                label = f"{path.name}:{node.name}"
                writing.append(label)
                if "guarded" not in _decorator_names(node):
                    unguarded.append(label)
    return writing, unguarded


def test_every_write_cli_command_is_guarded():
    writing, unguarded = _cli_write_commands()
    # The CLI exposes 7 of the 11 [WRITE] MCP tools as commands (no policy
    # update, rule create/update or group create command). Floor at that real
    # count: a derivation that collapses (e.g. the _fn alias bug) drops below it.
    assert len(writing) >= 7, (
        f"only {len(writing)} write CLI commands derived ({writing}) — the "
        f"MCP→ops→CLI derivation is likely stale; a check matching almost nothing "
        f"is worse than none."
    )
    assert not unguarded, (
        f"these CLI commands call a [WRITE] ops function but are not @guarded, so "
        f"they bypass policy + audit (HLD I-1): {unguarded}"
    )


def test_high_blast_radius_commands_are_derived_and_guarded():
    """Pin named destructive commands so a broad-but-wrong derivation cannot pass.

    ``policy_delete`` and ``group_delete`` only appear when the per-function
    ``_fn`` alias resolves to the right delete op; their presence proves the
    function-scoped derivation works.
    """
    writing, _ = _cli_write_commands()
    names = {w.split(":", 1)[1] for w in writing}
    for must in ("policy_delete", "group_delete"):
        assert must in names, (
            f"{must} is no longer derived as a write command — the readOnlyHint→"
            f"ops→command derivation stopped resolving it"
        )
