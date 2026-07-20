"""Regression tests for onboarding: the `vmware-nsx-security init` wizard, the
doctor init reference (no false promise — 踩坑 #2), and teaching form-body
auth / TLS errors (踩坑 #10 / #21 — special-char passwords must not regress).

REST skill: NSX Manager Policy API over httpx, NOT pyVmomi. The env-var name
carries the ``NSX_SECURITY`` namespace, and config.yaml stores ``targets`` as a
dict keyed by name (not a list).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from vmware_nsx_security import init_wizard


# ── init wizard ──────────────────────────────────────────────────────────────


@pytest.fixture
def _wizard_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cfg_dir = tmp_path / ".vmware-nsx-security"
    monkeypatch.setattr(init_wizard, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(init_wizard, "CONFIG_FILE", cfg_dir / "config.yaml")
    monkeypatch.setattr(init_wizard, "ENV_FILE", cfg_dir / ".env")
    return cfg_dir


def _feed(monkeypatch: pytest.MonkeyPatch, answers: list[object], confirms: list[bool]) -> None:
    a = iter(answers)
    c = iter(confirms)
    monkeypatch.setattr(init_wizard.typer, "prompt", lambda *args, **kwargs: next(a))
    monkeypatch.setattr(init_wizard.typer, "confirm", lambda *args, **kwargs: next(c))


def test_init_writes_grep_safe_env(_wizard_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vmware_nsx_security.config import _decode_secret

    _feed(
        monkeypatch,
        # name, host, username, port, password
        answers=["nsx-lab", "10.1.2.3", "admin", 443, "S3cr3t!pw"],
        confirms=[True],  # verify_ssl
    )
    assert init_wizard.run_init(skip_test=True) == 0

    env_text = (_wizard_env / ".env").read_text()
    assert "VMWARE_NSX_SECURITY_NSX_LAB_PASSWORD=b64:" in env_text
    assert "S3cr3t!pw" not in env_text  # never plaintext on disk
    assert (_wizard_env / ".env").stat().st_mode & 0o777 == 0o600
    line = next(ln for ln in env_text.splitlines() if ln.startswith("VMWARE_NSX_SECURITY_NSX_LAB_PASSWORD="))
    assert _decode_secret(line.split("=", 1)[1]) == "S3cr3t!pw"


def test_init_writes_config_matching_load_config_shape(_wizard_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vmware_nsx_security.config import load_config

    _feed(
        monkeypatch,
        answers=["nsx-prod", "nsx.example.com", "admin", 443, "pw"],
        confirms=[False],  # verify_ssl off (self-signed)
    )
    assert init_wizard.run_init(skip_test=True) == 0

    raw = yaml.safe_load((_wizard_env / "config.yaml").read_text())
    # targets must be a dict keyed by name, matching load_config's parser.
    assert raw["targets"]["nsx-prod"]["host"] == "nsx.example.com"
    assert raw["targets"]["nsx-prod"]["verify_ssl"] is False
    assert raw["default_target"] == "nsx-prod"

    cfg = load_config(_wizard_env / "config.yaml")
    target = cfg.get_target_strict("nsx-prod")
    assert target.host == "nsx.example.com"
    assert target.username == "admin"
    assert target.port == 443
    assert target.verify_ssl is False


# ── doctor references a real init command (no false promise) ──────────────────


def _init_registered() -> bool:
    from vmware_nsx_security.cli import app

    return any(c.name == "init" for c in app.registered_commands)


def test_doctor_init_reference_is_backed_by_real_command() -> None:
    from vmware_nsx_security import doctor

    src = Path(doctor.__file__).read_text()
    if "vmware-nsx-security init" in src:
        assert _init_registered(), "doctor recommends init but no such command is registered"


def test_init_command_is_registered() -> None:
    assert _init_registered(), "the init command must be wired into the CLI"


# ── form-body auth errors teach where to fix the problem ─────────────────────


def test_session_create_failure_is_teaching() -> None:
    from unittest.mock import MagicMock, patch

    import httpx

    from vmware_nsx_security.config import TargetConfig
    from vmware_nsx_security.connection import NsxApiError, NsxClient

    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 403
    resp.headers = {}
    with patch("vmware_nsx_security.connection.httpx.Client") as client_cls:
        http = MagicMock()
        client_cls.return_value = http
        http.post.return_value = resp
        with pytest.raises(NsxApiError) as exc:
            NsxClient(TargetConfig(host="nsx.example.com", username="admin"), "p@ss!w0rd")

    msg = str(exc.value)
    assert "VMWARE_NSX_SECURITY_<TARGET>_PASSWORD" in msg
    assert "~/.vmware-nsx-security/.env" in msg
    assert "config.yaml" in msg  # names where the username lives
    # special-char passwords are handled by form-body — must not be blamed (踩坑 #21)
    assert "form-body" in msg


def test_tls_failure_hints_verify_ssl() -> None:
    from unittest.mock import MagicMock, patch

    import httpx

    from vmware_nsx_security.config import TargetConfig
    from vmware_nsx_security.connection import NsxApiError, NsxClient

    with patch("vmware_nsx_security.connection.httpx.Client") as client_cls:
        http = MagicMock()
        client_cls.return_value = http
        http.post.side_effect = httpx.ConnectError("certificate verify failed")
        with pytest.raises(NsxApiError) as exc:
            NsxClient(TargetConfig(host="nsx.example.com", username="admin"), "pw")

    assert "verify_ssl" in str(exc.value)
