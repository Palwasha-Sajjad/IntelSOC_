from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_windows_deployment_covers_current_detection_events():
    content = (
        ROOT / "deployment" / "windows" / "Install-IntelSOC-Agent.ps1"
    ).read_text(encoding="utf-8-sig")

    for event_id in (
        4624, 4625, 4648, 4688, 4698, 4702,
        4720, 4722, 4723, 4725, 4726, 4732, 4740, 1102,
    ):
        assert f"EventID={event_id}" in content
    assert "EventID=4104" in content
    assert "[switch]$MigrateExisting" in content
    assert "Reusing existing IntelSOC device identity" in content
    assert "--dry-run -c $ConfigPath" in content


def test_linux_deployment_bundle_contains_installer_and_ca():
    linux = ROOT / "deployment" / "linux"
    installer = linux / "install-intelsoc-agent.sh"
    ca = linux / "intelsoc-caddy-root.crt"

    assert installer.is_file()
    assert ca.is_file()

    content = installer.read_text(encoding="utf-8-sig")
    assert "--dry-run" in content
    assert "--migrate-existing" in content
    assert "Systemd_Filter    _SYSTEMD_UNIT=ssh.service" in content
    assert "Systemd_Filter    SYSLOG_IDENTIFIER=sudo" in content
    assert "No process EXECVE auditing enabled." in content
    assert "tls.verify_hostname On" in content


def test_legacy_windows_test_config_is_not_mistaken_for_deployment_config():
    content = (
        ROOT / "config" / "fluent-bit" / "windows-application.yaml"
    ).read_text(encoding="utf-8-sig")

    assert content.startswith("# LEGACY TEST-ONLY CONFIG")
