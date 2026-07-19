"""Regression evals for the centralized connection-layer error handling.

CLAUDE.md 踩坑 #37: REST-wrapper skills must translate HTTP errors into
teaching ``NsxApiError``s in ONE place (``NsxClient._request``), retry
transient gateway errors once for GETs only, re-auth exactly once on 401
(never on 403 — the old code dangerously re-sent writes after a 403), and
keep health probes from crashing when the platform is unhealthy.

These tests drive a real NsxClient against a mocked httpx.Client so the
retry / re-auth / translation logic is exercised end to end. Mirrors
VMware-NSX's connection-layer suite (踩坑 #21 — family fixes ship together).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from vmware_nsx_security.config import TargetConfig
from vmware_nsx_security.connection import NsxApiError, NsxClient


def _response(status_code: int, headers: dict | None = None, json_body: dict | None = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.content = b"{}" if json_body is not None else b""
    resp.json.return_value = json_body or {}
    return resp


def _target() -> TargetConfig:
    return TargetConfig(host="nsx.example.com", username="admin")


@pytest.fixture()
def client() -> NsxClient:
    """NsxClient with a mocked httpx transport and a pre-created session."""
    with patch("vmware_nsx_security.connection.httpx.Client") as client_cls:
        http = MagicMock()
        client_cls.return_value = http
        http.post.return_value = _response(200, headers={"x-xsrf-token": "tok-1"})
        nsx = NsxClient(_target(), "p@ss!word")
    nsx._test_http = http  # type: ignore[attr-defined]
    return nsx


# ── form-body auth regression (踩坑 #10 / #21) ───────────────────────────


def test_session_create_uses_form_body_auth(client: NsxClient) -> None:
    """Session create must POST urlencoded j_username/j_password — the
    Basic-Auth path 403s on special-character passwords (v1.4.9 fix)."""
    http = client._test_http  # type: ignore[attr-defined]
    args, kwargs = http.post.call_args
    assert args[0] == "/api/session/create"
    body = kwargs["content"].decode("utf-8")
    assert body.startswith("j_username=admin&j_password=")
    assert "p%40ss!word" in body  # '@' encoded, '!' literal (curl-compatible)
    assert kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert client._token == "tok-1"


def test_session_create_failure_raises_credential_hint() -> None:
    with patch("vmware_nsx_security.connection.httpx.Client") as client_cls:
        http = MagicMock()
        client_cls.return_value = http
        http.post.return_value = _response(403)
        with pytest.raises(NsxApiError) as exc:
            NsxClient(_target(), "wrong")
    msg = str(exc.value)
    assert "VMWARE_<TARGET>_PASSWORD" in msg
    assert exc.value.status_code == 403


# ── 404 → teaching NsxApiError, never retried ────────────────────────────


def test_get_404_raises_teaching_error_without_retry(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.request.return_value = _response(404)

    with pytest.raises(NsxApiError) as exc:
        client.get("/policy/api/v1/infra/domains/default/groups/nope")

    assert exc.value.status_code == 404
    msg = str(exc.value)
    assert "404" in msg
    assert "list_dfw_policies" in msg and "list_groups" in msg, (
        f"404 hint must teach the list-then-get pattern: {msg}"
    )
    assert http.request.call_count == 1, "4xx must never be retried"


# ── 503: GET retried exactly once; writes never retried ─────────────────


def test_get_503_retried_exactly_once_then_succeeds(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.request.side_effect = [
        _response(503),
        _response(200, json_body={"ok": True}),
    ]
    with patch("vmware_nsx_security.connection.time.sleep") as sleep:
        result = client.get("/policy/api/v1/infra/domains/default")
    assert result == {"ok": True}
    assert http.request.call_count == 2
    sleep.assert_called_once()


def test_get_503_twice_raises_after_single_retry(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.request.side_effect = [_response(503), _response(503)]
    with patch("vmware_nsx_security.connection.time.sleep"):
        with pytest.raises(NsxApiError) as exc:
            client.get("/policy/api/v1/infra/domains/default")
    assert exc.value.status_code == 503
    assert http.request.call_count == 2, "only ONE automatic retry allowed"


def test_post_503_not_retried(client: NsxClient) -> None:
    """A write that 5xx'd may already have been applied — never re-send."""
    http = client._test_http  # type: ignore[attr-defined]
    http.request.return_value = _response(503)
    with patch("vmware_nsx_security.connection.time.sleep") as sleep:
        with pytest.raises(NsxApiError) as exc:
            client.post("/policy/api/v1/infra/domains/default/groups/g1", {"x": 1})
    assert exc.value.status_code == 503
    assert http.request.call_count == 1, "writes must NOT be auto-retried"
    sleep.assert_not_called()


def test_get_transport_error_retried_once(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.request.side_effect = [
        httpx.ConnectError("boom"),
        _response(200, json_body={"ok": True}),
    ]
    with patch("vmware_nsx_security.connection.time.sleep"):
        assert client.get("/x") == {"ok": True}
    assert http.request.call_count == 2


def test_post_transport_error_not_retried(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.request.side_effect = httpx.ConnectTimeout("slow")
    with pytest.raises(NsxApiError) as exc:
        client.post("/x", {"a": 1})
    assert exc.value.status_code is None  # transport failure — no HTTP status
    assert http.request.call_count == 1


# ── 401: re-auth exactly once; 403 never re-auths ────────────────────────


def test_401_reauths_once_then_resends(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.post.return_value = _response(200, headers={"x-xsrf-token": "tok-2"})
    http.request.side_effect = [
        _response(401),
        _response(200, json_body={"ok": True}),
    ]
    assert client.get("/x") == {"ok": True}
    assert client._token == "tok-2", "session must be re-created on 401"
    assert http.request.call_count == 2


def test_second_401_after_reauth_raises_not_loops(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.post.return_value = _response(200, headers={"x-xsrf-token": "tok-2"})
    http.request.side_effect = [_response(401), _response(401)]
    with pytest.raises(NsxApiError) as exc:
        client.get("/x")
    assert exc.value.status_code == 401
    assert http.request.call_count == 2, "re-auth must be bounded to once"


def test_403_does_not_reauth_or_resend_write(client: NsxClient) -> None:
    """Old code re-created the session and RE-SENT the write on 403 —
    useless (RBAC denial) and dangerous (duplicate write)."""
    http = client._test_http  # type: ignore[attr-defined]
    session_posts_before = http.post.call_count
    http.request.return_value = _response(403)
    with pytest.raises(NsxApiError) as exc:
        client.put("/policy/api/v1/infra/domains/default/groups/g1", {"x": 1})
    assert exc.value.status_code == 403
    assert "Permission denied" in str(exc.value)
    assert http.request.call_count == 1, "403 must NOT trigger a re-send"
    assert http.post.call_count == session_posts_before, "403 must NOT re-auth"


def test_transport_failure_after_reauth_is_translated(client: NsxClient) -> None:
    """code-review HIGH from the Aria fix: the re-sent request after a 401
    re-auth must run inside the same protected loop — a connection drop
    there must surface as NsxApiError, not a raw httpx exception."""
    http = client._test_http  # type: ignore[attr-defined]
    http.post.return_value = _response(200, headers={"x-xsrf-token": "tok-2"})
    http.request.side_effect = [
        _response(401),
        httpx.ConnectError("dropped"),
        httpx.ConnectError("dropped"),
    ]
    with patch("vmware_nsx_security.connection.time.sleep"):
        with pytest.raises(NsxApiError):
            client.get("/x")


# ── get_all() safety cap (踩坑 #21 family-sync with vmware-nsx) ───────────


def test_get_all_stops_at_max_items_cap(client: NsxClient) -> None:
    # issue #9: get_all() was uncapped, unlike vmware-nsx's _MAX_ITEMS=1000.
    # An endless cursor must stop at the cap and not loop forever.
    from vmware_nsx_security.connection import _MAX_ITEMS

    http = client._test_http  # type: ignore[attr-defined]
    # Endless cursor: 100 results per page, forever.
    http.request.return_value = _response(
        200, json_body={"results": [{"i": 1}] * 100, "cursor": "next"}
    )

    results = client.get_all("/policy/api/v1/infra/domains/default/groups", max_items=250)
    assert len(results) == 250

    # Default cap is _MAX_ITEMS (1000).
    assert _MAX_ITEMS == 1000
    results = client.get_all("/policy/api/v1/infra/domains/default/groups")
    assert len(results) == _MAX_ITEMS


def test_get_all_logs_truncation_warning(client: NsxClient, caplog) -> None:
    # Hitting the cap must emit a warning telling the user to filter.
    import logging

    http = client._test_http  # type: ignore[attr-defined]
    http.request.return_value = _response(
        200, json_body={"results": [{"i": 1}] * 100, "cursor": "next"}
    )

    with caplog.at_level(logging.WARNING, logger="vmware-nsx-security.connection"):
        client.get_all("/policy/api/v1/infra/domains/default/groups", max_items=150)

    assert any("safety cap" in rec.message and "truncated" in rec.message for rec in caplog.records), (
        "get_all must warn when it truncates at the cap"
    )


# ── is_alive: probe must treat error statuses as signals, not crashes ───


def test_is_alive_uses_cheap_policy_probe_no_retry(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.request.return_value = _response(200, json_body={})
    assert client.is_alive() is True
    method, path = http.request.call_args.args[:2]
    assert method == "GET"
    assert path == "/policy/api/v1/infra/domains/default", (
        "liveness probe must use a cheap Policy-API GET, not the "
        "privileged /api/v1/cluster/status endpoint"
    )
    assert http.request.call_count == 1, "probe must use retries=0"


def test_is_alive_503_means_alive_401_means_dead(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    # 503 = manager not ready, but the session itself still works
    http.request.return_value = _response(503)
    assert client.is_alive() is True
    # 401 (even after the bounded re-auth) = session is dead
    http.post.return_value = _response(200, headers={"x-xsrf-token": "tok-2"})
    http.request.side_effect = [_response(401), _response(401)]
    assert client.is_alive() is False


def test_is_alive_transport_error_means_dead(client: NsxClient) -> None:
    http = client._test_http  # type: ignore[attr-defined]
    http.request.side_effect = httpx.ConnectError("gone")
    assert client.is_alive() is False


# ── ConnectionManager closes stale clients before replacing ─────────────


def test_connect_closes_stale_client_before_replacing() -> None:
    from vmware_nsx_security.connection import ConnectionManager

    mgr = ConnectionManager.__new__(ConnectionManager)
    stale = MagicMock()
    stale.is_alive.return_value = False
    mgr._clients = {"t1": stale}

    config = MagicMock()
    config.default_target = "t1"
    target_cfg = MagicMock()
    target_cfg.get_password.return_value = "pw"
    config.get_target.return_value = target_cfg
    mgr._config = config

    with patch("vmware_nsx_security.connection.NsxClient") as nsx_cls:
        fresh = MagicMock()
        nsx_cls.return_value = fresh
        result = mgr.connect("t1")

    stale.close.assert_called_once()
    assert result is fresh
    assert mgr._clients["t1"] is fresh


# ── MCP layer: NsxApiError passes through _safe_error ────────────────────


def test_safe_error_passes_nsx_api_error_through() -> None:
    from vmware_nsx_security.mcp_server.server import _safe_error

    err = NsxApiError(
        "NSX GET /x returned HTTP 404. Nothing exists at /x.",
        status_code=404, method="GET", path="/x",
    )
    out = _safe_error(err, "nsx-security")
    assert "404" in out and "/x" in out, "teaching message must reach the agent"

    generic = _safe_error(RuntimeError("internal gore"), "nsx-security")
    assert "internal gore" not in generic, "non-teaching errors stay generic"


# ── MCP write wrappers audit result=error on failure (was success-only) ──


def test_mcp_write_failure_is_audited_as_error() -> None:
    import vmware_nsx_security.mcp_server._shared as shared
    import vmware_nsx_security.mcp_server.server as server
    import vmware_nsx_security.mcp_server.tools.tags as tags

    # After the domain split the tool body lives in vmware_nsx_security.mcp_server.tools.tags and
    # binds `_get_connection` in that namespace; `_write_error` audits via the
    # `_audit` global in vmware_nsx_security.mcp_server._shared. Patch each at its real home.
    audit = MagicMock()
    with patch.object(shared, "_audit", audit), patch.object(
        tags, "_get_connection",
        side_effect=NsxApiError("NSX POST /x returned HTTP 503. Not ready.", status_code=503),
    ):
        result = server.apply_vm_tag(vm_id="vm-1", tag_scope="env", tag_value="prod")

    assert "error" in result
    audit.log.assert_called_once()
    assert audit.log.call_args.kwargs["result"] == "error"
    assert audit.log.call_args.kwargs["operation"] == "apply_vm_tag"
