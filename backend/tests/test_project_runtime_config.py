from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_start_script_launches_both_workers():
    content = (ROOT / "Start-IntelSOC.ps1").read_text(encoding="utf-8-sig")

    assert "-m app.workers.event_worker" in content
    assert "-m app.workers.analysis_worker" in content


def test_stop_script_stops_both_workers():
    content = (ROOT / "Stop-IntelSOC.ps1").read_text(encoding="utf-8-sig")

    assert "app\\.workers\\.event_worker" in content
    assert "app\\.workers\\.analysis_worker" in content


def test_runtime_dependencies_are_declared():
    requirements = (ROOT / "backend" / "requirements.txt").read_text(
        encoding="utf-8-sig"
    )

    assert "redis==" in requirements
    assert "psycopg[binary]==3.2.13" in requirements
    assert "python-dotenv==" in requirements



def test_redis_runtime_has_bounded_network_timeouts():
    from app.core.config import get_redis_config

    config = get_redis_config()

    assert config["socket_connect_timeout"] == 5
    assert config["socket_timeout"] == 5
