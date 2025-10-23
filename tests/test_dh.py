import json
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _invoke_and_load(relative_script, *args):
    command = [
        sys.executable,
        str(BASE_DIR / relative_script),
        *args,
        "--log-dir",
        str(LOG_DIR),
    ]
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        cwd=BASE_DIR,
    )
    json_line = next(line for line in result.stdout.splitlines() if line.strip().startswith("{"))
    payload = json.loads(json_line)
    json_path = Path(payload["json_log_path"])
    if not json_path.is_absolute():
        json_path = BASE_DIR / json_path
    with json_path.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_dh_normal_exchange():
    data = _invoke_and_load(Path("DH") / "dh_key_exchange.py", "--mode", "demo")
    assert data["exchange_ok"] is True
    assert data["mitm_success"] is False


def test_dh_mitm_attack_success():
    data = _invoke_and_load(
        Path("DH") / "dh_attack.py",
        "--run",
        "mitm_demo",
        "--mode",
        "local",
    )
    assert data["mitm_success"] is True


def test_dh_defense_signed_detects_mitm():
    data = _invoke_and_load(Path("DH") / "dh_defense.py", "--demo", "signed_dh")
    assert data["mitm_detected"] is True
    assert data["exchange_ok"] is False
    pm = data.get("performance_metrics")
    assert pm is not None
    assert 0.88 <= pm["overall_score"] <= 0.95


def test_dh_defense_key_confirmation_detects_mitm():
    data = _invoke_and_load(Path("DH") / "dh_defense.py", "--demo", "key_confirmation")
    assert data["mitm_detected"] is True
    assert data["exchange_ok"] is False
    pm = data.get("performance_metrics")
    assert pm is not None
    assert 0.8 <= pm["overall_score"] <= 0.88


def test_dh_defense_pfs_signed_detects_mitm():
    data = _invoke_and_load(Path("DH") / "dh_defense.py", "--demo", "pfs_signed")
    assert data["mitm_detected"] is True
    assert data["pfs_enabled"] is True
    assert data["exchange_ok"] is True
    pm = data.get("performance_metrics")
    assert pm is not None
    assert 0.88 <= pm["overall_score"] <= 0.95
