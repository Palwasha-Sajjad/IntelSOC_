from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_lanobert_start_script_is_explicit_and_isolated():
    path = ROOT / "Start-LAnoBERT.ps1"
    assert path.is_file()

    content = path.read_text(encoding="utf-8-sig")

    assert "[string]$Since" in content
    assert "[Parameter(Mandatory = $true)]" not in content
    assert ".venv-lanobert\\Scripts\\python.exe" in content
    assert "lanobert_v02.ai_monitor" in content
    assert "--write-results" in content
    assert "--since" in content
    assert "--limit" in content
    assert "--poll-seconds" in content
    assert "--model-dir" in content
    assert "Start-IntelSOC.ps1" not in content
    assert "app.workers.risk_worker" not in content
    assert "app.workers.ti_worker" not in content


def test_lanobert_start_script_defaults_to_five_minute_lookback():
    content = (ROOT / "Start-LAnoBERT.ps1").read_text(encoding="utf-8-sig")

    assert "[string]::IsNullOrWhiteSpace($Since)" in content
    assert "AddMinutes(-5)" in content
    assert "automatic 5-minute lookback" in content
    assert "manual override" in content


def test_lanobert_process_matching_uses_module_invocation():
    start = (ROOT / "Start-LAnoBERT.ps1").read_text(encoding="utf-8-sig")
    stop = (ROOT / "Stop-LAnoBERT.ps1").read_text(encoding="utf-8-sig")

    expected = r"(^|\s)-m\s+lanobert_v02\.ai_monitor(?:\s|$)"
    assert expected in start
    assert expected in stop
    assert "python(?:\\.exe)?" not in start
    assert "python(?:\\.exe)?" not in stop


def test_lanobert_start_script_prevents_duplicate_monitor():
    content = (ROOT / "Start-LAnoBERT.ps1").read_text(encoding="utf-8-sig")

    assert "Get-CimInstance Win32_Process" in content
    assert "LAnoBERT Monitor: already running" in content
    assert "Start-Process" in content
    assert "-PassThru" in content
    assert "$Process.HasExited" in content
    assert "process was not found after startup" in content


def test_lanobert_stop_script_targets_only_ai_monitor():
    path = ROOT / "Stop-LAnoBERT.ps1"
    assert path.is_file()

    content = path.read_text(encoding="utf-8-sig")

    assert "lanobert_v02\\.ai_monitor" in content
    assert "Stop-Process" in content
    assert "docker compose stop" not in content
    assert "uvicorn" not in content
    assert "app.workers.analysis_worker" not in content
    assert "app.workers.risk_worker" not in content
    assert "app.workers.ti_worker" not in content


def test_existing_core_runtime_scripts_are_not_replaced():
    assert (ROOT / "Start-IntelSOC.ps1").is_file()
    assert (ROOT / "Stop-IntelSOC.ps1").is_file()
