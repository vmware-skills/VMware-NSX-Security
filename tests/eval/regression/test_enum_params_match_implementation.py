"""Closed-value parameters must carry their values in the MCP schema.

Round 3 found this family's ``enum`` coverage still at 0% for VKS and most of
its siblings. A parameter with a fixed set of valid values typed as ``str``
names those values only in prose, and an MCP client sees the schema, not the
prose -- so a model guesses the spelling, and here a wrong guess is a rejected
write rather than a silent one, which is the better failure but still an avoidable
round trip.

The values are taken from the implementation's own validation sets, never from
the docstring. That distinction is not pedantic: ``vmware-nsx``'s
``create_nat_rule`` accepts six actions and its docstring names three, so an
enum copied from prose would have hard-rejected three working values.

Deliberately NOT enumerated, and this file records why so the next pass does not
"finish the job" and break them:

* ``run_traceflow(protocol=...)`` and ``vmware-log-insight``'s ``aggregation``
  upper-case the argument before validating, so ``"tcp"`` works today. An enum
  would reject it.
* ``vmware-aria``'s ``resource_kind`` only *warns* on an unknown value and then
  proceeds -- vROps knows far more kinds than the six listed. Enumerating it
  would convert an advisory into a refusal.

A closed set is one the implementation refuses to leave. Nothing else qualifies.
"""

from __future__ import annotations

import asyncio

import pytest

from vmware_nsx_security.mcp_server.server import mcp
from vmware_nsx_security.ops.dfw_policy import _VALID_CATEGORIES
from vmware_nsx_security.ops.dfw_rules import (
    _VALID_ACTIONS,
    _VALID_DIRECTIONS,
    _VALID_IP_PROTOS,
)

#: (tool, parameter) -> the set the implementation itself enforces.
EXPECTED = {
    ("create_dfw_policy", "category"): _VALID_CATEGORIES,
    ("create_dfw_rule", "action"): _VALID_ACTIONS,
    ("create_dfw_rule", "direction"): _VALID_DIRECTIONS,
    ("create_dfw_rule", "ip_protocol"): _VALID_IP_PROTOS,
    ("update_dfw_rule", "action"): _VALID_ACTIONS,
}


@pytest.fixture(scope="module")
def schemas():
    return {t.name: (t.inputSchema or {}) for t in asyncio.run(mcp.list_tools())}


def _enum_of(schema: dict, param: str) -> set[str] | None:
    prop = schema.get("properties", {}).get(param)
    if prop is None:
        return None
    if "enum" in prop:
        return set(prop["enum"])
    # Optional[Literal[...]] renders as anyOf[{enum: [...]}, {type: "null"}]
    for branch in prop.get("anyOf", []):
        if "enum" in branch:
            return set(branch["enum"])
    return None


def test_the_gate_is_wired_to_something():
    """A gate over an empty table passes forever (形态 #1)."""
    assert EXPECTED, "no parameters listed — this check verifies nothing"


@pytest.mark.parametrize(("tool", "param"), sorted(EXPECTED))
def test_schema_enum_equals_the_implementations_own_set(tool, param, schemas):
    assert tool in schemas, f"{tool} is not registered — did it get renamed?"
    got = _enum_of(schemas[tool], param)
    assert got is not None, (
        f"{tool}.{param} has no enum in its schema, so an MCP client has to "
        f"guess the spelling from prose it cannot see"
    )
    assert got == set(EXPECTED[(tool, param)]), (
        f"{tool}.{param} advertises {sorted(got)} but the implementation accepts "
        f"{sorted(EXPECTED[(tool, param)])} — the schema and the check have drifted"
    )
