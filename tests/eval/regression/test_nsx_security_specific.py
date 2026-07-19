"""NSX-Security-specific regression evals.

2026-06 API-correctness review — three whole features never worked because
their request/response shapes were invented rather than taken from the
official NSX API docs / SDK models:

* VM tagging (C1): POSTed to a non-existent
  /api/v1/fabric/tags/tag?action=add_tag endpoint. Real endpoint is
  POST /api/v1/fabric/virtual-machines?action=add_tags|remove_tags with
  body {"external_id", "tags"} (no resource_type) returning 204.
* IDPS status (C2/C3): GET intrusion-services/status and /node-status do
  not exist. Real reads are .../intrusion-services/signatures/status
  (signature status) and .../intrusion-services (IdsSettings).
* Traceflow (C5/H1/H2): FieldsPacketData must nest ip_header /
  transport_header, transport_type is UNICAST (not the protocol), poll
  field is operation_state (IN_PROGRESS/FINISHED/FAILED, not
  status/COMPLETED), and observations are discriminated by resource_type
  (not observation_type).

Plus: tag Condition value must be the pipe-delimited "scope|tag" string
(C4), heterogeneous group expressions join with OR not AND (H3), IDPS
profile criteria are polymorphic filter_name/filter_value items (H4),
category validation incl. Ethernet (M2), delete_group reference scan must
cover rule/policy scope and abort on scan failure (M3), RuleStatistics has
no population_count (M4), JUMP_TO_APPLICATION requires an
Environment-category policy (M5).

These tests drive the real ops functions against a mocked NsxClient, so
any future drift back to the invented shapes fails here, not in prod.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

_IDPS_BASE = "/policy/api/v1/infra/settings/firewall/security/intrusion-services"


def _mock_client() -> MagicMock:
    client = MagicMock(name="NsxClient")
    client.get.return_value = {}
    client.get_all.return_value = []
    client.post.return_value = {}
    client.put.return_value = {"id": "created"}
    client.patch.return_value = {"id": "patched"}
    client.delete.return_value = None
    return client


# ── C1: VM tag endpoint must be the real fabric/virtual-machines API ────


def test_apply_vm_tag_uses_real_endpoint_and_body() -> None:
    from vmware_nsx_security.ops.tags import apply_vm_tag

    client = _mock_client()
    result = apply_vm_tag(client, "vm-ext-1", "env", "prod")

    path, body = client.post.call_args.args
    assert path == "/api/v1/fabric/virtual-machines?action=add_tags", (
        f"invented endpoint used: {path}"
    )
    assert body == {
        "external_id": "vm-ext-1",
        "tags": [{"scope": "env", "tag": "prod"}],
    }
    assert "resource_type" not in body
    assert result["status"] == "applied"


def test_remove_vm_tag_uses_real_endpoint_and_body() -> None:
    from vmware_nsx_security.ops.tags import remove_vm_tag

    client = _mock_client()
    result = remove_vm_tag(client, "vm-ext-1", "env", "prod")

    path, body = client.post.call_args.args
    assert path == "/api/v1/fabric/virtual-machines?action=remove_tags", (
        f"invented endpoint used: {path}"
    )
    assert body == {
        "external_id": "vm-ext-1",
        "tags": [{"scope": "env", "tag": "prod"}],
    }
    assert "resource_type" not in body
    assert result["status"] == "removed"


def test_cli_tag_apply_dry_run_audit_string_matches_real_endpoint() -> None:
    """cli.py dry-run preview must not advertise the invented endpoint."""
    import inspect

    import vmware_nsx_security.cli as cli

    src = inspect.getsource(cli.tag_apply)
    assert "fabric/tags/tag" not in src, "CLI still references the invented tag endpoint"
    assert "fabric/virtual-machines?action=add_tags" in src


# ── C2/C3: IDPS status must read signatures/status + IdsSettings ────────


def test_get_idps_status_queries_real_endpoints() -> None:
    from vmware_nsx_security.ops.idps import get_idps_status

    client = _mock_client()

    def _get(path, params=None):
        if path == f"{_IDPS_BASE}/signatures/status":
            return {"update_state": "SUCCESS", "signature_version": "4.2.1"}
        if path == _IDPS_BASE:
            return {"auto_update": True, "ids_events_to_syslog": False}
        raise AssertionError(f"unexpected GET {path}")

    client.get.side_effect = _get
    result = get_idps_status(client)

    called_paths = [c.args[0] for c in client.get.call_args_list]
    assert f"{_IDPS_BASE}/signatures/status" in called_paths
    assert _IDPS_BASE in called_paths
    assert f"{_IDPS_BASE}/status" not in called_paths, "invented endpoint queried"
    assert f"{_IDPS_BASE}/node-status" not in called_paths, "invented endpoint queried"

    # Real settings fields surfaced
    assert result["settings"]["auto_update"] is True
    assert result["settings"]["ids_events_to_syslog"] is False
    # Signature status parsed defensively (scalar fields passed through)
    assert result["signature_status"]["signature_version"] == "4.2.1"
    # Invented fields for the invented endpoint must be gone
    for invented in ("global_status", "node_status_counts", "signatures_up_to_date"):
        assert invented not in result, f"invented field '{invented}' still present"


def test_get_idps_status_errors_surface_not_swallowed_to_unknown() -> None:
    from vmware_nsx_security.ops.idps import get_idps_status

    client = _mock_client()
    client.get.side_effect = RuntimeError("403 Forbidden")
    with pytest.raises(RuntimeError):
        get_idps_status(client)


def test_get_idps_status_defensive_parse_skips_nested_and_meta_fields() -> None:
    """Signature status shape varies by NSX release — nested objects and
    _meta fields must be skipped, scalars passed through stringified."""
    from vmware_nsx_security.ops.idps import get_idps_status

    client = _mock_client()

    def _get(path, params=None):
        if path.endswith("/signatures/status"):
            return {
                "signature_version": "4.2.1",
                "auto_update_enabled": True,
                "download_status": {"state": "SUCCESS"},  # nested → skipped
                "versions": ["4.2.0", "4.2.1"],  # list → skipped
                "_revision": 3,  # meta → skipped
            }
        return {"auto_update": False, "ids_events_to_syslog": True}

    client.get.side_effect = _get
    result = get_idps_status(client)
    assert result["signature_status"] == {
        "signature_version": "4.2.1",
        "auto_update_enabled": "True",
    }
    assert result["settings"] == {"auto_update": False, "ids_events_to_syslog": True}


# ── H4: IDPS profile criteria are polymorphic filter items ──────────────


def test_list_idps_profiles_parses_polymorphic_criteria() -> None:
    from vmware_nsx_security.ops.idps import list_idps_profiles

    client = _mock_client()
    client.get_all.return_value = [
        {
            "id": "p1",
            "display_name": "Profile 1",
            "description": "",
            "criteria": [
                {
                    "resource_type": "IdsProfileFilterCriteria",
                    "filter_name": "ATTACK_TYPE",
                    "filter_value": ["trojan-activity"],
                },
                {
                    "resource_type": "IdsProfileConjunctionOperator",
                    "operator": "AND",
                },
                {
                    "resource_type": "IdsProfileFilterCriteria",
                    "filter_name": "CVSS",
                    "filter_value": ["CRITICAL", "HIGH"],
                },
            ],
            "profile_severity": ["HIGH", "CRITICAL"],
            "overridden_signatures": [{"signature_id": "1"}, {"signature_id": "2"}],
            "path": "/infra/settings/firewall/security/intrusion-services/profiles/p1",
        }
    ]

    profiles = list_idps_profiles(client)
    p = profiles["items"][0]
    assert p["criteria"] == [
        {"filter_name": "ATTACK_TYPE", "filter_value": ["trojan-activity"]},
        {"filter_name": "CVSS", "filter_value": ["CRITICAL", "HIGH"]},
    ]
    # profile_severity is an ARRAY in the API — must be joined, not str()'d
    assert "[" not in p["profile_severity"]
    assert "HIGH" in p["profile_severity"] and "CRITICAL" in p["profile_severity"]
    # count derives from the overridden_signatures list
    assert p["overridden_signature_count"] == 2


# ── C4: tag Condition value is the pipe-delimited "scope|tag" string ────


def test_create_group_tag_condition_uses_pipe_value() -> None:
    from vmware_nsx_security.ops.security_group import create_group

    client = _mock_client()
    create_group(client, "g1", "G1", tag_scope="env", tag_value="prod")

    body = client.put.call_args.args[1]
    cond = body["expression"][0]
    assert cond["resource_type"] == "Condition"
    assert cond["member_type"] == "VirtualMachine"
    assert cond["key"] == "Tag"
    assert cond["operator"] == "EQUALS"
    assert cond["value"] == "env|prod", f"got {cond!r}"
    assert cond["scope_operator"] == "EQUALS"
    assert "tag" not in cond, "invented 'tag' object still in Condition body"


def test_create_group_tag_condition_without_scope() -> None:
    from vmware_nsx_security.ops.security_group import create_group

    client = _mock_client()
    create_group(client, "g1", "G1", tag_value="prod")

    cond = client.put.call_args.args[1]["expression"][0]
    assert cond["value"] == "|prod"
    assert "scope_operator" not in cond
    assert "tag" not in cond


# ── H3: heterogeneous expression types must join with OR ────────────────


def test_create_group_heterogeneous_expressions_join_with_or() -> None:
    from vmware_nsx_security.ops.security_group import create_group

    client = _mock_client()
    create_group(
        client,
        "g1",
        "G1",
        tag_scope="env",
        tag_value="prod",
        ip_addresses=["10.0.1.0/24"],
        segment_paths=["/infra/segments/web"],
    )

    exprs = client.put.call_args.args[1]["expression"]
    conjunctions = [e for e in exprs if e["resource_type"] == "ConjunctionOperator"]
    assert len(conjunctions) == 2
    for c in conjunctions:
        assert c["conjunction_operator"] == "OR", (
            "NSX rejects AND between Condition and "
            "IPAddressExpression/PathExpression — must be OR"
        )


# ── C5/H1/H2: Traceflow request shape, polling, observations ────────────


def _traceflow_client(observations: list[dict] | None = None) -> MagicMock:
    client = _mock_client()
    client.post.return_value = {"id": "tf-1"}

    def _get(path, params=None):
        if path == "/api/v1/traceflows/tf-1":
            return {"operation_state": "FINISHED"}
        if path == "/api/v1/traceflows/tf-1/observations":
            return {"results": observations or []}
        raise AssertionError(f"unexpected GET {path}")

    client.get.side_effect = _get
    return client


def test_run_traceflow_builds_nested_fields_packet_data() -> None:
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client = _traceflow_client()
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        run_traceflow(
            client, "lport-1", "10.0.0.1", "10.0.0.2",
            protocol="TCP", dst_port=443, src_port=1234, ttl=64,
        )

    body = client.post.call_args.args[1]
    assert set(body) == {"lport_id", "packet"}
    packet = body["packet"]
    assert packet["resource_type"] == "FieldsPacketData"
    assert packet["routed"] is True
    # transport_type enum is UNICAST/BROADCAST/MULTICAST — NOT the protocol
    assert packet["transport_type"] == "UNICAST"
    assert packet["ip_header"]["src_ip"] == "10.0.0.1"
    assert packet["ip_header"]["dst_ip"] == "10.0.0.2"
    assert packet["ip_header"]["ttl"] == 64
    assert packet["ip_header"]["protocol"] == 6  # TCP
    tcp = packet["transport_header"]["tcp_header"]
    assert tcp["src_port"] == 1234
    assert tcp["dst_port"] == 443
    # Flat invented fields must be gone
    for flat in ("src_ip", "dst_ip", "ip_ttl", "src_port", "dst_port"):
        assert flat not in packet, f"flat field '{flat}' still on packet"


@pytest.mark.parametrize(
    ("protocol", "proto_num", "header_key"),
    [("UDP", 17, "udp_header"), ("ICMP", 1, "icmp_echo_request_header")],
)
def test_run_traceflow_udp_icmp_headers(protocol: str, proto_num: int, header_key: str) -> None:
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client = _traceflow_client()
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        run_traceflow(client, "lport-1", "10.0.0.1", "10.0.0.2", protocol=protocol)

    packet = client.post.call_args.args[1]["packet"]
    assert packet["ip_header"]["protocol"] == proto_num
    assert header_key in packet["transport_header"]
    assert packet["transport_type"] == "UNICAST"


def test_run_traceflow_polls_operation_state() -> None:
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client = _traceflow_client()
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        result = run_traceflow(client, "lport-1", "10.0.0.1", "10.0.0.2")

    assert result["operation_state"] == "FINISHED"
    # Single poll suffices because operation_state was read correctly
    poll_calls = [
        c for c in client.get.call_args_list if c.args[0] == "/api/v1/traceflows/tf-1"
    ]
    assert len(poll_calls) == 1, (
        "polled more than once for an already-FINISHED traceflow — "
        "operation_state not being read"
    )


def test_run_traceflow_stops_polling_on_failed() -> None:
    """FAILED is a terminal operation_state — polling must stop, not run
    out the full timeout window."""
    from vmware_nsx_security.ops.traceflow import run_traceflow

    client = _mock_client()
    client.post.return_value = {"id": "tf-1"}
    states = iter(["IN_PROGRESS", "FAILED"])

    def _get(path, params=None):
        if path == "/api/v1/traceflows/tf-1":
            return {"operation_state": next(states)}
        if path == "/api/v1/traceflows/tf-1/observations":
            return {"results": []}
        raise AssertionError(f"unexpected GET {path}")

    client.get.side_effect = _get
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        result = run_traceflow(client, "lport-1", "10.0.0.1", "10.0.0.2")

    assert result["operation_state"] == "FAILED"
    poll_calls = [
        c for c in client.get.call_args_list if c.args[0] == "/api/v1/traceflows/tf-1"
    ]
    assert len(poll_calls) == 2, "must stop polling once FAILED is observed"


def test_traceflow_observations_discriminated_by_resource_type() -> None:
    from vmware_nsx_security.ops.traceflow import run_traceflow

    obs = [
        {
            "resource_type": "TraceflowObservationForwarded",
            "component_name": "tier1-router",
            "component_type": "EDGE",
            "transport_node_name": "edge-01",
        },
        {
            "resource_type": "TraceflowObservationDroppedLogical",
            "component_name": "dfw",
            "component_type": "FIREWALL",
            "transport_node_name": "esx-01",
            "reason": "FW_RULE",
            "acl_rule_id": 1012,
        },
    ]
    client = _traceflow_client(obs)
    with patch("vmware_nsx_security.ops.traceflow.time.sleep"):
        result = run_traceflow(client, "lport-1", "10.0.0.1", "10.0.0.2")

    forwarded, dropped = result["observations"]
    assert forwarded["resource_type"] == "TraceflowObservationForwarded"
    assert "reason" not in forwarded
    assert dropped["resource_type"] == "TraceflowObservationDroppedLogical"
    assert dropped["reason"] == "FW_RULE"
    assert dropped["acl_rule_id"] == "1012"
    assert result["dfw_hits"] and result["dfw_hits"][0]["acl_rule_id"] == "1012"


def test_get_traceflow_result_reads_operation_state_and_resource_type() -> None:
    from vmware_nsx_security.ops.traceflow import get_traceflow_result

    client = _mock_client()

    def _get(path, params=None):
        if path == "/api/v1/traceflows/tf-9":
            return {"operation_state": "IN_PROGRESS"}
        if path == "/api/v1/traceflows/tf-9/observations":
            return {
                "results": [
                    {
                        "resource_type": "TraceflowObservationReceived",
                        "component_name": "vnic",
                        "component_type": "VNIC",
                        "transport_node_name": "esx-02",
                    }
                ]
            }
        raise AssertionError(f"unexpected GET {path}")

    client.get.side_effect = _get
    result = get_traceflow_result(client, "tf-9")
    assert result["operation_state"] == "IN_PROGRESS"
    entry = result["observations"][0]
    assert entry["resource_type"] == "TraceflowObservationReceived"
    assert "reason" not in entry  # reason only exists on Dropped* observations


# ── M2: category validation must include Ethernet + teach valid values ──


def test_create_dfw_policy_rejects_invalid_category_with_teaching_error() -> None:
    from vmware_nsx_security.ops.dfw_policy import create_dfw_policy

    client = _mock_client()
    with pytest.raises(ValueError) as exc:
        create_dfw_policy(client, "p1", "P1", category="Bogus")
    msg = str(exc.value)
    for cat in ("Ethernet", "Emergency", "Infrastructure", "Environment", "Application"):
        assert cat in msg, f"teaching error must list '{cat}': {msg}"
    client.put.assert_not_called()


def test_create_dfw_policy_accepts_ethernet_category() -> None:
    from vmware_nsx_security.ops.dfw_policy import create_dfw_policy

    client = _mock_client()
    create_dfw_policy(client, "p1", "P1", category="Ethernet")
    assert client.put.call_args.args[1]["category"] == "Ethernet"


# ── M3 / issue #6: delete_group uses the group-associations dependency API,
#    covering every reference class (DFW, gateway firewall, NESTED GROUPS,
#    service-insertion) and failing safe when the check errors. ────────────


def _associations_client(associations: list[dict]) -> MagicMock:
    """Mock whose group-associations endpoint returns ``associations``."""
    client = _mock_client()

    def _get_all(path, params=None):
        if path.endswith("/group-associations"):
            return associations
        return []

    client.get_all.side_effect = _get_all
    return client


def test_delete_group_blocks_on_dfw_policy_reference() -> None:
    from vmware_nsx_security.ops.security_group import delete_group

    client = _associations_client(
        [{"target_type": "SecurityPolicy", "target_display_name": "pol1", "path": "/infra/.../pol1"}]
    )
    with pytest.raises(ValueError):
        delete_group(client, "g1")
    client.delete.assert_not_called()


def test_delete_group_blocks_on_nested_group_reference() -> None:
    """A group referenced only by ANOTHER GROUP (not a DFW rule) must be
    detected. The old DFW-only rule walk missed this and would orphan the
    nested-group reference. Maps to issue #6.
    """
    from vmware_nsx_security.ops.security_group import delete_group

    # Sole reference is a nested group (target_type=Group), with no DFW
    # rule referencing it at all.
    client = _associations_client(
        [{"target_type": "Group", "target_display_name": "parent-group", "path": "/infra/domains/default/groups/parent-group"}]
    )
    with pytest.raises(ValueError) as exc:
        delete_group(client, "g1")
    assert "parent-group" in str(exc.value)
    client.delete.assert_not_called()


def test_delete_group_blocks_on_gateway_firewall_reference() -> None:
    from vmware_nsx_security.ops.security_group import delete_group

    client = _associations_client(
        [{"target_type": "GatewayPolicy", "target_display_name": "gw-pol", "path": "/infra/domains/default/gateway-policies/gw-pol"}]
    )
    with pytest.raises(ValueError):
        delete_group(client, "g1")
    client.delete.assert_not_called()


def test_delete_group_succeeds_when_unreferenced() -> None:
    from vmware_nsx_security.ops.security_group import delete_group

    client = _associations_client([])
    result = delete_group(client, "g1")
    assert result["status"] == "deleted"
    client.delete.assert_called_once_with(
        "/policy/api/v1/infra/domains/default/groups/g1"
    )


def test_delete_group_aborts_when_reference_scan_fails() -> None:
    from vmware_nsx_security.ops.security_group import delete_group

    client = _mock_client()
    client.get_all.side_effect = RuntimeError("API timeout")
    with pytest.raises(ValueError) as exc:
        delete_group(client, "g1")
    assert "scan" in str(exc.value).lower() or "verify" in str(exc.value).lower()
    client.delete.assert_not_called()


# ── M4: RuleStatistics has no population_count ───────────────────────────


def test_rule_stats_reports_real_fields_only() -> None:
    from vmware_nsx_security.ops.dfw_rules import get_dfw_rule_stats

    client = _mock_client()
    client.get.return_value = {
        "results": [
            {
                "packet_count": 10,
                "byte_count": 100,
                "session_count": 2,
                "hit_count": 5,
                "popularity_index": 1,
            }
        ]
    }
    stats = get_dfw_rule_stats(client, "pol1", "r1")
    assert stats["packet_count"] == 10
    assert stats["byte_count"] == 100
    assert stats["session_count"] == 2
    assert stats["hit_count"] == 5
    assert stats["popularity_index"] == 1
    assert "population_count" not in stats, "RuleStatistics has no population_count"


# ── M5: JUMP_TO_APPLICATION Environment-category constraint documented ──


def test_jump_to_application_constraint_documented() -> None:
    from vmware_nsx_security.ops.dfw_rules import create_dfw_rule

    assert "Environment" in (create_dfw_rule.__doc__ or ""), (
        "create_dfw_rule docstring must document that JUMP_TO_APPLICATION "
        "is only allowed in Environment-category policies"
    )

    client = _mock_client()
    with pytest.raises(ValueError) as exc:
        create_dfw_rule(client, "pol1", "r1", "R1", action="NOPE")
    assert "JUMP_TO_APPLICATION" in str(exc.value)


# ── 踩坑 #34: MCP tool surface must match the declared 21 (10R/11W) ──────


def test_mcp_exposes_all_21_tools() -> None:
    import asyncio

    from mcp_server.server import mcp

    tools = asyncio.run(mcp.list_tools())
    names = sorted(t.name for t in tools)
    assert names == [
        "apply_vm_tag",
        "create_dfw_policy",
        "create_dfw_rule",
        "create_group",
        "delete_dfw_policy",
        "delete_dfw_rule",
        "delete_group",
        "get_dfw_policy",
        "get_dfw_rule_stats",
        "get_group",
        "get_idps_status",
        "get_traceflow_result",
        "list_dfw_policies",
        "list_dfw_rules",
        "list_groups",
        "list_idps_profiles",
        "list_vm_tags",
        "remove_vm_tag",
        "run_traceflow",
        "update_dfw_policy",
        "update_dfw_rule",
    ], "MCP tool surface drifted from the declared 21 tools (10 read / 11 write)"


# ---------------------------------------------------------------------------
# List ops: name_filter + limit/offset (issue #7) — list ops must default
# to limit=50 and support a display_name filter so they don't flood agent
# context on large estates. The connection-layer get_all safety cap stays
# intact; this trims the already-collected list before returning it.
# ---------------------------------------------------------------------------


def _named_items(n: int, prefix: str = "item") -> list[dict]:
    return [{"id": f"{prefix}-{i}", "display_name": f"{prefix}-{i}"} for i in range(n)]


@pytest.mark.parametrize(
    "import_path, fn_name",
    [
        ("vmware_nsx_security.ops.dfw_policy", "list_dfw_policies"),
        ("vmware_nsx_security.ops.security_group", "list_groups"),
        ("vmware_nsx_security.ops.idps", "list_idps_profiles"),
    ],
)
def test_list_ops_default_limit_caps_count(import_path, fn_name) -> None:
    import importlib

    fn = getattr(importlib.import_module(import_path), fn_name)
    client = _mock_client()
    client.get_all.return_value = _named_items(200)

    result = fn(client)
    assert result["returned"] == 50, "list ops must default to limit=50"
    assert result["truncated"] is True, "a capped page must say so"


@pytest.mark.parametrize(
    "import_path, fn_name",
    [
        ("vmware_nsx_security.ops.dfw_policy", "list_dfw_policies"),
        ("vmware_nsx_security.ops.security_group", "list_groups"),
        ("vmware_nsx_security.ops.idps", "list_idps_profiles"),
    ],
)
def test_list_ops_name_filter_narrows(import_path, fn_name) -> None:
    import importlib

    fn = getattr(importlib.import_module(import_path), fn_name)
    client = _mock_client()
    client.get_all.return_value = [
        {"id": "web-1", "display_name": "web-frontend"},
        {"id": "db-1", "display_name": "db-backend"},
        {"id": "web-2", "display_name": "web-api"},
    ]

    # substring match is case-insensitive
    result = fn(client, name_filter="WEB")
    names = {r["display_name"] for r in result["items"]}
    assert names == {"web-frontend", "web-api"}

    # glob pattern is supported
    result = fn(client, name_filter="*backend")
    assert {r["display_name"] for r in result["items"]} == {"db-backend"}


@pytest.mark.parametrize(
    "import_path, fn_name",
    [
        ("vmware_nsx_security.ops.dfw_policy", "list_dfw_policies"),
        ("vmware_nsx_security.ops.security_group", "list_groups"),
        ("vmware_nsx_security.ops.idps", "list_idps_profiles"),
    ],
)
def test_list_ops_offset_paginates(import_path, fn_name) -> None:
    import importlib

    fn = getattr(importlib.import_module(import_path), fn_name)
    client = _mock_client()
    client.get_all.return_value = _named_items(10)

    page1 = fn(client, limit=3, offset=0)
    page2 = fn(client, limit=3, offset=3)

    assert [r["id"] for r in page1["items"]] == ["item-0", "item-1", "item-2"]
    assert [r["id"] for r in page2["items"]] == ["item-3", "item-4", "item-5"]
    # windows do not overlap
    assert not (
        {r["id"] for r in page1["items"]} & {r["id"] for r in page2["items"]}
    )
