"""NSX Manager REST API client with session management.

Uses httpx for HTTP communication. Authenticates via POST /api/session/create
with form-body credentials (j_username/j_password), then reuses X-XSRF-TOKEN
for subsequent requests.

Supports both Policy API (/policy/api/v1/) and Management API (/api/v1/).

All HTTP verbs route through a single ``_request()`` that translates HTTP
and transport errors into teaching ``NsxApiError``s instead of letting raw
httpx tracebacks bubble up (CLAUDE.md 踩坑 #37). Keep this file in sync with
VMware-NSX's connection.py — the two are intentionally near-verbatim copies
(踩坑 #21).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from vmware_nsx_security.config import AppConfig, TargetConfig, load_config

_log = logging.getLogger("vmware-nsx-security.connection")

# Transient gateway statuses worth one automatic retry (the manager may be
# busy or a service may still be coming up). Only GETs are retried — a write
# that returned 5xx may already have been applied, so auto-resending it is
# unsafe. 4xx client errors are never retried.
_TRANSIENT_STATUS = frozenset({502, 503, 504})
_RETRY_DELAY_SEC = 2.0

# Safety cap for paginated collection — search/filter beats dumping
# unbounded lists into agent context (family "search over list" rule).
_MAX_ITEMS = 1000


class NsxApiError(Exception):
    """An NSX Manager API call returned an error or failed to connect.

    Carries a teaching message (status + path + how to fix) so end users see
    an actionable line instead of a raw httpx traceback. ``status_code`` is
    None for transport/timeout failures (no HTTP response was received).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        method: str | None = None,
        path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.method = method
        self.path = path


def _hint_for_status(status_code: int, path: str) -> str:
    """Return a short, actionable remediation hint for an HTTP error status."""
    if status_code == 404:
        return (
            "Verify the id — run list_dfw_policies / list_groups (or the "
            f"matching list command) and copy an exact ID. Nothing exists at {path}."
        )
    if status_code == 400:
        return "Bad request — check the parameters and payload for this call."
    if status_code == 401:
        return "Authentication failed — check the username and the VMWARE_NSX_SECURITY_<TARGET>_PASSWORD env var for this target."
    if status_code == 403:
        return (
            "Permission denied — the account lacks the required NSX RBAC role "
            "for this operation. Check the role assignment in NSX Manager."
        )
    if status_code in (502, 503, 504):
        return "NSX Manager is busy or not ready (gateway error) — wait and retry shortly."
    if status_code >= 500:
        return "Server-side error — retry shortly; check NSX Manager health."
    return "Check the request and try again."


class NsxClient:
    """REST client for a single NSX Manager."""

    _target_name: str = ""
    """Config key this client was built from, e.g. ``prod-nsx``.

    Connection failures name this instead of the host they resolved to: the
    operator edits config by key, and the raw failure text (host:port,
    certificate subject) is not something ``_safe_error`` would redact. Declared
    at class level so instances built with ``__new__`` — the test doubles that
    skip ``__init__`` to avoid dialling out — still render a message.
    """

    def __init__(
        self, target: TargetConfig, password: str, username: str | None = None,
        *, target_name: str = "",
    ) -> None:
        """Initialise client and authenticate immediately.

        Args:
            target: Connection target configuration.
            password: Plaintext password (sourced from env var).
            username: Resolved username (env var override, else config). The
                caller resolves it alongside the password so both halves of the
                credential come from the same read; omitted means use config.
            target_name: Config key for this target, named by connection-failure
                messages in place of the resolved host.
        """
        self._target = target
        self._target_name = target_name
        self._password = password
        self._username = username or target.username
        self._base_url = f"https://{target.host}:{target.port}"
        self._token: str | None = None

        # Suppress urllib3's InsecureRequestWarning for self-signed certs.
        # urllib3.disable_warnings is class-targeted and idempotent; it avoids
        # the process-global side-effects of warnings.filterwarnings().
        if not target.verify_ssl:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # No client-level auth — credentials are sent via form body in
        # _create_session(); subsequent requests use session cookie + XSRF token.
        self._client = httpx.Client(
            base_url=self._base_url,
            verify=target.verify_ssl,
            timeout=30.0,
        )
        self._create_session()

    def _create_session(self) -> None:
        """Authenticate via form body and store the XSRF session token.

        NSX Manager's /api/session/create requires j_username and j_password
        as application/x-www-form-urlencoded body parameters.  Python's
        urllib.parse.urlencode encodes '!' -> '%21' and ')' -> '%29', but some
        NSX versions compare the raw encoded string against the stored password,
        causing spurious 403s for passwords that contain those characters.

        We construct the body manually using urllib.parse.quote() with an
        explicit safe set that preserves the characters curl passes literally
        (RFC 3986 unreserved set plus common sub-delimiters: ! ) * - . _ ~),
        so the on-wire representation matches what curl -d sends.

        Raises:
            NsxApiError: With a credential hint if session creation fails.
        """
        from urllib.parse import quote

        # Characters curl preserves unencoded in -d form data
        _SAFE = "!)*-._~"
        body = (
            "j_username="
            + quote(self._username, safe=_SAFE)
            + "&j_password="
            + quote(self._password, safe=_SAFE)
        )
        try:
            resp = self._client.post(
                "/api/session/create",
                content=body.encode("utf-8"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            # Kept short: the base message already names verify_ssl and the
            # config path, so this only has to say "it was the certificate".
            # The old wording repeated both and pushed the whole message to 345
            # characters, past the 300-char cap that then ate the target name.
            tls_hint = ""
            if "certificate" in str(exc).lower() or "ssl" in str(exc).lower():
                tls_hint = (
                    " This looks like a TLS certificate failure: set verify_ssl: "
                    "false for a self-signed lab manager."
                )
            # The raw ``exc`` is deliberately not interpolated. ``_safe_error``
            # passes ``NsxApiError`` through verbatim and ``sanitize`` redacts
            # nothing, so a TLS failure would hand the agent the certificate
            # subject and a DNS failure the resolved host:port. The full chain
            # still reaches the operator: ``_safe_error`` logs it with
            # ``exc_info``, and ``from exc`` keeps the cause attached.
            # Authored text first, config key last — the cap truncates the tail.
            raise NsxApiError(
                "NSX session creation could not connect. Check the host, port and "
                "verify_ssl for this target in ~/.vmware-nsx-security/config.yaml, "
                f"then run 'vmware-nsx-security doctor'.{tls_hint} "
                f"Target: '{self._target_name}'",
                method="POST",
                path="/api/session/create",
            ) from exc
        if resp.status_code >= 400:
            raise NsxApiError(
                f"NSX session creation failed with HTTP {resp.status_code} — "
                "usually wrong credentials (not special characters; "
                "form-body auth handles those). Check the username in "
                "config.yaml and "
                "VMWARE_NSX_SECURITY_<TARGET>_PASSWORD in "
                "~/.vmware-nsx-security/.env, or run 'vmware-nsx-security "
                f"init' to reset them. Target: {self._target.host}",
                status_code=resp.status_code,
                method="POST",
                path="/api/session/create",
            )
        self._token = resp.headers.get("x-xsrf-token")
        if not self._token:
            raise NsxApiError(
                "NSX session creation succeeded but returned no X-XSRF-TOKEN "
                "— a proxy or load balancer is most likely stripping "
                "headers. Check that this target's 'host' in "
                "~/.vmware-nsx-security/config.yaml points directly at NSX "
                "Manager, then re-run 'vmware-nsx-security doctor'. Target: "
                f"{self._target.host}",
                method="POST",
                path="/api/session/create",
            )
        _log.info("NSX session created for %s", self._target.host)

    def _headers(self) -> dict[str, str]:
        """Request headers with XSRF token."""
        h = {"Accept": "application/json"}
        if self._token:
            h["X-XSRF-TOKEN"] = self._token
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        retries: int = 1,
    ) -> httpx.Response:
        """Send one request, recovering from auth and transient failures.

        Layered per the error-recovery contract:

        1. Transport/timeout errors and transient gateway statuses
           (502/503/504) are retried once after a short delay — **GET only**.
           Writes are never auto-retried: a write that errored mid-flight may
           already have been applied on the manager.
        2. A 401 triggers a single session re-creation; the request is then
           re-sent through the top of the loop so the retry is covered by the
           same transport-error translation. 403 does **not** re-auth — it
           means RBAC rejected the call, and blindly re-sending a write after
           a 403 is both useless and dangerous.
        3. Any remaining error status is translated into a teaching
           ``NsxApiError`` so callers never surface a raw httpx traceback.
           4xx client errors (e.g. 404 for a bad id) are never retried.
        """
        is_get = method == "GET"
        attempt = 0
        reauthed = False
        while True:
            try:
                resp = self._client.request(method, path, headers=self._headers(), params=params, json=json_data)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if is_get and attempt < retries:
                    attempt += 1
                    time.sleep(_RETRY_DELAY_SEC)
                    continue
                # No raw ``exc``: see _create_session — it carries the resolved
                # host:port (and the certificate subject on a TLS failure), and
                # nothing downstream redacts it. Authored text first, the
                # unbounded path last so the 300-char cap eats context, not the
                # remedy.
                raise NsxApiError(
                    "NSX could not connect. Check the host, port and network for "
                    "this target in ~/.vmware-nsx-security/config.yaml, then run "
                    "'vmware-nsx-security doctor' to test reachability and TLS. "
                    f"Target: '{self._target_name}' ({method} {path})",
                    method=method,
                    path=path,
                ) from exc

            if resp.status_code == 401 and not reauthed:
                # Re-create the session once, then re-issue through the top of
                # the loop so the retry is covered by the same transport-error
                # handling (the `reauthed` flag bounds this to a single retry).
                _log.info("Session expired on %s %s, re-authenticating...", method, path)
                self._create_session()
                reauthed = True
                continue

            if resp.status_code in _TRANSIENT_STATUS and is_get and attempt < retries:
                attempt += 1
                time.sleep(_RETRY_DELAY_SEC)
                continue

            if resp.status_code >= 400:
                raise NsxApiError(
                    f"{_hint_for_status(resp.status_code, path)} (NSX {method} {path} returned HTTP {resp.status_code})",
                    status_code=resp.status_code,
                    method=method,
                    path=path,
                )
            return resp

    def get(self, path: str, params: dict[str, Any] | None = None, *, retries: int = 1) -> dict:
        """Single GET request. Returns JSON response.

        Pass retries=0 for probes where an error status is itself the answer
        (e.g. a liveness check) to skip the transient back-off.
        """
        resp = self._request("GET", path, params=params, retries=retries)
        return resp.json() if resp.content else {}

    def get_all(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        max_items: int = _MAX_ITEMS,
        *,
        page_size: int | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Paginated GET. Follows the cursor until enough results collected.

        Args:
            path: Collection endpoint path.
            params: Extra query parameters (a server-side filter goes here).
            max_items: Safety cap (default 1000) applied only when ``limit``
                is not given — it stops an unfiltered dump from flooding
                agent context.
            page_size: Optional NSX ``page_size`` query hint (server-side
                page size); the cursor is still followed until the effective
                cap is reached.
            limit: Stop following the cursor once this many items are
                collected. When set it *replaces* the ``max_items`` backstop,
                so a server-side-filtered query (e.g. the Search API) can
                collect matches past the default 1000 — hitting ``limit`` is
                expected and is not warned about.

        Returns:
            The collected result dicts, truncated to the effective cap.
        """
        effective_cap = limit if limit is not None else max_items
        all_results: list[dict] = []
        params = dict(params) if params else {}
        if page_size is not None:
            params["page_size"] = page_size
        while True:
            data = self.get(path, params=params)
            results = data.get("results", [])
            all_results.extend(results)
            if len(all_results) >= effective_cap:
                if limit is None:
                    _log.warning(
                        "get_all(%s) hit the %d-item safety cap; results "
                        "truncated. Use a server-side filter to narrow the "
                        "query.",
                        path,
                        effective_cap,
                    )
                return all_results[:effective_cap]
            cursor = data.get("cursor")
            if not cursor:
                break
            params["cursor"] = cursor
        return all_results

    def post(self, path: str, json_data: dict[str, Any] | None = None) -> dict:
        """POST request for write operations."""
        resp = self._request("POST", path, json_data=json_data)
        return resp.json() if resp.content else {}

    def put(self, path: str, json_data: dict[str, Any]) -> dict:
        """PUT request (create or replace)."""
        resp = self._request("PUT", path, json_data=json_data)
        return resp.json() if resp.content else {}

    def patch(self, path: str, json_data: dict[str, Any]) -> dict:
        """PATCH request (partial update)."""
        resp = self._request("PATCH", path, json_data=json_data)
        return resp.json() if resp.content else {}

    def delete(self, path: str) -> None:
        """DELETE request."""
        self._request("DELETE", path)

    def is_alive(self) -> bool:
        """Check if the cached session is still usable.

        Probes a cheap Policy-API object readable by any role
        (GET /policy/api/v1/infra/domains/default) instead of the old
        /api/v1/cluster/status Manager-API endpoint, which required high
        privileges — least-privilege accounts got 403 there and forced a
        brand-new session on every connect(). A reachable manager returning
        5xx is still "alive": the session works, the platform just isn't
        ready. Only auth failures (401/403) or transport errors mean the
        cached session is stale. retries=0 keeps the probe snappy.
        """
        try:
            self._request("GET", "/policy/api/v1/infra/domains/default", retries=0)
            return True
        except NsxApiError as exc:
            return exc.status_code is not None and exc.status_code not in (401, 403)
        except Exception:
            return False

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


class ConnectionManager:
    """Manages connections to multiple NSX Manager targets."""

    def __init__(self, config: AppConfig) -> None:
        """Initialise with an AppConfig.

        Args:
            config: Loaded application configuration.
        """
        self._config = config
        self._clients: dict[str, NsxClient] = {}

    @classmethod
    def from_config(cls, config: AppConfig | None = None) -> ConnectionManager:
        """Create a ConnectionManager from config, loading defaults if needed."""
        cfg = config or load_config()
        return cls(cfg)

    def connect(self, target_name: str | None = None) -> NsxClient:
        """Get or create an NsxClient for the specified target."""
        name = target_name or self._config.default_target
        if not name:
            configured = ", ".join(self._config.targets.keys())
            raise ValueError(
                "No target specified and no default target configured. Pass "
                "one of the names below as the target, or set "
                "'default_target' in ~/.vmware-nsx-security/config.yaml — run "
                "'vmware-nsx-security init' to create that file, or "
                "'vmware-nsx-security doctor' to check the one you have. "
                f"Available: {configured or '(none)'}"
            )

        cached = self._clients.get(name)
        if cached is not None:
            if cached.is_alive():
                return cached
            # Close the stale client before replacing it — otherwise the old
            # httpx connection pool leaks on every reconnect.
            cached.close()
            del self._clients[name]

        target_cfg = self._config.get_target(name)
        if target_cfg is None:
            available = ", ".join(self._config.targets.keys())
            raise ValueError(
                f"Target '{name}' not found. Copy an exact name from the list "
                "below, or add the target to the 'targets:' block of "
                "~/.vmware-nsx-security/config.yaml (run 'vmware-nsx-security "
                f"init' to add one interactively). Available: {available}"
            )

        # Resolve both halves of the credential together — a username left
        # behind by a rotation would pair with the new password and fail.
        password = target_cfg.get_password(name)
        username = target_cfg.get_username(name)
        client = NsxClient(target_cfg, password, username, target_name=name)
        self._clients[name] = client
        return client

    def disconnect(self, target_name: str) -> None:
        """Close and remove a client."""
        if target_name in self._clients:
            self._clients[target_name].close()
            del self._clients[target_name]

    def disconnect_all(self) -> None:
        """Disconnect from all targets."""
        for name in list(self._clients):
            self.disconnect(name)

    def list_targets(self) -> list[str]:
        """List available target names."""
        return list(self._config.targets.keys())

    def list_connected(self) -> list[str]:
        """List currently connected target names."""
        return list(self._clients.keys())
