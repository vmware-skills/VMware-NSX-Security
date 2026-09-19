"""Spec conformance: every NSX API path this skill calls must exist in the NSX SDK.

2026-09-19 review: ``delete_group``'s reference check read
``/policy/api/v1/infra/domains/{d}/groups/{g}/group-associations`` — a path that
is not in NSX's API. On a real NSX it 404s, so every ``delete_group`` was
refused (or failed) and the reference check it documented never ran. The
mocked tests answered any path ending in ``/group-associations``, so nothing
in this repo could see it.

The spec index is the one VMware-NSX vendors (NSX 4.2 Python SDK
url_templates, path-only), copied to ``tests/eval/spec/``. This scanner differs
from VMware-NSX's in one way that matters here: module-level path constants
(``_GROUPS_BASE = "..."``) resolve inside functions. VMware-NSX's scanner
resets the environment per function, so ``f"{_GROUPS_BASE}/{gid}/..."`` became
``{param}/{param}/...``, did not start with ``/``, and was skipped — that
scanner would not have caught the invented path above.

2026-09-19 narrow review: a client call whose path the scanner cannot resolve
(the group-reference walk built ``f"{base}/..."`` from a loop variable) was
silently skipped, so a skipped call read as a passing one. Now every call on a
client (a receiver named ``client`` / ``*_client``, or ``self`` inside the
connection layer) must resolve to a path, or be one of the listed forwarders
that pass a caller's path through — and those forwarders' callers are checked
instead.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SPEC_PATH = REPO_ROOT / "tests" / "eval" / "spec" / "nsx_api_operations.json"
SCAN_DIR = REPO_ROOT / "vmware_nsx_security"

_HTTP_METHODS = {"get", "get_all", "post", "put", "patch", "delete"}

# Endpoints intentionally outside the SDK url_template index.
_ALLOWLIST = {
    # Session-cookie auth endpoint (REST authentication, not SDK operation metadata).
    "/api/session/create",
}

#: Functions that forward a caller's path to the client: name -> (positional
#: index, keyword) of that path. Their call sites are checked like client calls.
_FORWARDERS = {"search_by_name": (2, "collection_path")}

#: Client calls whose path is a parameter of the enclosing function — the
#: forwarding itself, whose callers are checked. (file, function, parameter).
_FORWARDING_SITES = {
    ("vmware_nsx_security/connection.py", "get_all", "path"),
    ("vmware_nsx_security/ops/_search.py", "search_by_name", "collection_path"),
}

#: The path delete_group used to read. It must be rejected (positive control).
_OLD_INVENTED = "/policy/api/v1/infra/domains/default/groups/{param}/group-associations"


def _spec_segment_lists() -> list[list[str]]:
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    return [op["path"].split("/") for op in spec["operations"]]


def _resolve_path(node: ast.AST, env: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif (isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name)
                  and v.value.id in env):
                parts.append(env[v.value.id])
            else:
                parts.append("{param}")
        return "".join(parts)
    if isinstance(node, ast.Name):
        return env.get(node.id)
    return None


def _is_client(receiver: ast.AST, rel_path: str) -> bool:
    """A receiver that is an NSX client (or the client itself, in its own module)."""
    text = ast.unparse(receiver)
    last = text.rsplit(".", 1)[-1].lower()
    return last == "client" or last.endswith("_client") or (
        text == "self" and rel_path.endswith("/connection.py"))


class _ApiCallScanner(ast.NodeVisitor):
    """Collect (location, path-template); functions see module constants.

    A client call whose path does not resolve is recorded in ``unresolved``
    (never dropped), unless it is a listed forwarding site, which is recorded
    in ``forwarding``.
    """

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.env: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []
        self.unresolved: list[str] = []
        self.forwarding: set[tuple[str, str, str]] = set()
        self._function = ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        saved, saved_fn = self.env, self._function
        self.env = dict(saved)
        self._function = node.name
        self.generic_visit(node)
        self.env, self._function = saved, saved_fn

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = _resolve_path(node.value, self.env)
            if value is not None:
                self.env[node.targets[0].id] = value
        self.generic_visit(node)

    def _path_arg(self, node: ast.Call) -> ast.AST | None:
        func = node.func
        if (isinstance(func, ast.Attribute) and func.attr in _HTTP_METHODS
                and _is_client(func.value, self.rel_path)):
            return node.args[0] if node.args else next(
                (k.value for k in node.keywords if k.arg == "path"), None)
        name = func.id if isinstance(func, ast.Name) else (
            func.attr if isinstance(func, ast.Attribute) else None)
        if name in _FORWARDERS:
            index, keyword = _FORWARDERS[name]
            if len(node.args) > index:
                return node.args[index]
            return next((k.value for k in node.keywords if k.arg == keyword), None)
        return None

    def visit_Call(self, node: ast.Call) -> None:
        arg = self._path_arg(node)
        if arg is not None or self._is_call_without_path(node):
            where = f"{self.rel_path}:{node.lineno}"
            path = _resolve_path(arg, self.env) if arg is not None else None
            site = (self.rel_path, self._function, getattr(arg, "id", None))
            if path is not None and path.startswith("/"):
                self.calls.append((where, path))
            elif site in _FORWARDING_SITES:
                self.forwarding.add(site)
            else:
                self.unresolved.append(f"{where}: {ast.unparse(node)[:120]}")
        self.generic_visit(node)

    def _is_call_without_path(self, node: ast.Call) -> bool:
        func = node.func
        return (isinstance(func, ast.Attribute) and func.attr in _HTTP_METHODS
                and _is_client(func.value, self.rel_path))


def _scan() -> list[_ApiCallScanner]:
    sources = sorted(SCAN_DIR.rglob("*.py"))
    assert sources, f"no sources under {SCAN_DIR}"
    scanners = []
    for py in sources:
        scanner = _ApiCallScanner(py.relative_to(REPO_ROOT).as_posix())
        scanner.visit(ast.parse(py.read_text(encoding="utf-8")))
        scanners.append(scanner)
    return scanners


def _collect_api_calls() -> list[tuple[str, str]]:
    return [c for s in _scan() for c in s.calls]


def _matches_spec(path: str, spec_paths: list[list[str]]) -> bool:
    if path in _ALLOWLIST:
        return True
    candidate = path.split("?")[0].split("/")
    for spec in spec_paths:
        if len(spec) != len(candidate):
            continue
        cand_wild_vs_spec_literal = False
        cand_literal_vs_spec_wild = False
        for spec_seg, cand_seg in zip(spec, candidate):
            spec_wild = bool(re.fullmatch(r"\{[^}]+\}", spec_seg))
            cand_wild = "{param}" in cand_seg
            if not (spec_wild or cand_wild or spec_seg == cand_seg):
                break
            if cand_wild and not spec_wild:
                cand_wild_vs_spec_literal = True
            elif spec_wild and not cand_wild:
                cand_literal_vs_spec_wild = True
        else:
            if not (cand_wild_vs_spec_literal and cand_literal_vs_spec_wild):
                return True
    return False


def test_spec_index_is_loaded() -> None:
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    assert spec["operation_count"] >= 2000, "spec index missing or truncated"
    assert spec["operation_count"] == len(spec["operations"])


def test_matcher_rejects_the_old_group_associations_path() -> None:
    """Positive control: the path delete_group used to read is not in NSX's API."""
    assert not _matches_spec(_OLD_INVENTED, _spec_segment_lists())


def test_scanner_resolves_module_constants() -> None:
    """Positive control: the old call site, as written, resolves to a full path."""
    src = (
        '_GROUPS_BASE = "/policy/api/v1/infra/domains/default/groups"\n'
        "def f(client, group_id):\n"
        '    return client.get_all(f"{_GROUPS_BASE}/{group_id}/group-associations")\n'
    )
    scanner = _ApiCallScanner("sample.py")
    scanner.visit(ast.parse(src))
    assert [p for _, p in scanner.calls] == [_OLD_INVENTED]


def test_real_endpoints_are_accepted() -> None:
    spec_paths = _spec_segment_lists()
    for path in (
        "/policy/api/v1/infra/group-associations",
        "/policy/api/v1/infra/domains/default/groups/{param}",
        "/policy/api/v1/infra/domains/default/security-policies/{param}/rules",
        "/policy/api/v1/infra/domains/default/gateway-policies/{param}/rules",
        "/policy/api/v1/search/query",
    ):
        assert _matches_spec(path, spec_paths), f"matcher rejected real path {path}"


def test_every_api_call_exists_in_nsx_sdk_spec() -> None:
    spec_paths = _spec_segment_lists()
    calls = _collect_api_calls()
    assert len(calls) >= 30, f"only {len(calls)} API calls collected — AST scan regressed?"
    violations = [f"{loc}: {path}" for loc, path in calls if not _matches_spec(path, spec_paths)]
    assert not violations, (
        "API paths not present in the NSX 4.2 SDK url_template index "
        "(invented endpoints 404 in production):\n  " + "\n  ".join(violations)
    )


def test_every_client_call_path_resolves() -> None:
    """A call the scanner cannot resolve must fail, not be skipped as if it passed."""
    unresolved = [u for s in _scan() for u in s.unresolved]
    assert not unresolved, (
        "client calls whose path the spec scanner cannot resolve (write the path "
        "from literals / module constants, or list a true forwarder):\n  "
        + "\n  ".join(unresolved)
    )


def test_every_listed_forwarding_site_still_exists() -> None:
    """A stale exemption would hide nothing today and anything tomorrow."""
    seen = set().union(*(s.forwarding for s in _scan()))
    assert seen == _FORWARDING_SITES


def _scan_source(src: str) -> _ApiCallScanner:
    scanner = _ApiCallScanner("vmware_nsx_security/ops/sample.py")
    scanner.visit(ast.parse(src))
    return scanner


def test_scanner_reports_a_loop_variable_path_as_unresolved() -> None:
    """Positive control: the old rule-walk form is caught, not skipped."""
    scanner = _scan_source(
        "_COLLS = (('A', '/policy/api/v1/infra/domains/default/security-policies'),)\n"
        "def f(client):\n"
        "    for kind, base in _COLLS:\n"
        "        client.get_all(base)\n"
        "        client.get_all(f\"{base}/x/rules\")\n"
    )
    assert scanner.calls == []
    assert len(scanner.unresolved) == 2


def test_an_invented_path_in_the_rule_walk_position_goes_red() -> None:
    """Positive control: the rewritten walk's form, with an invented segment, fails the spec."""
    scanner = _scan_source(
        '_GW = "/policy/api/v1/infra/domains/default/gateway-policies"\n'
        "def f(client, policy):\n"
        "    client.get_all(f\"{_GW}/{policy.get('id')}/rule-list\")\n"
    )
    ((_, path),) = scanner.calls
    assert not _matches_spec(path, _spec_segment_lists())
    assert _matches_spec(path.replace("rule-list", "rules"), _spec_segment_lists())


def test_forwarder_call_sites_are_checked() -> None:
    scanner = _scan_source(
        "def f(client):\n"
        "    search_by_name(client, 'Group', '/policy/api/v1/infra/domains/default/grps', 'x')\n"
    )
    ((_, path),) = scanner.calls
    assert not _matches_spec(path, _spec_segment_lists())


def test_dict_get_is_not_a_client_call() -> None:
    assert _scan_source("def f(policy):\n    policy.get('id')\n").unresolved == []
