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


def test_rsa_normal_exchange():
    data = _invoke_and_load(Path("RSA") / "rsa_key_exchange.py", "--mode", "demo")
    assert data["exchange_ok"] is True
    assert data["key_size_bits"] >= 2048
    assert data["padding_scheme"] == "OAEP-SHA256"


def test_rsa_timing_attack_success():
    data = _invoke_and_load(
        Path("RSA") / "rsa_attack.py",
        "--run",
        "timing_demo",
        "--samples",
        "400",
    )
    assert data["success_rate"] > 0.7
    assert data["correlation_found"] is True
    assert data["modulus_bits"] >= 2048


def test_rsa_blinding_defense_mitigates():
    data = _invoke_and_load(
        Path("RSA") / "rsa_defense.py",
        "--demo",
        "blinding",
        "--samples",
        "400",
    )
    assert data["attack_success_rate"] < 0.05
    assert data["timing_vulnerability_mitigated"] is True
    assert data["modulus_bits"] >= 2048
    pm = data.get("performance_metrics")
    assert pm is not None
    assert 0.75 <= pm["overall_score"] <= 0.9


def test_rsa_constant_time_defense_mitigates():
    data = _invoke_and_load(
        Path("RSA") / "rsa_defense.py",
        "--demo",
        "constant_time",
        "--samples",
        "400",
    )
    assert data["attack_success_rate"] < 0.05
    assert data["timing_vulnerability_mitigated"] is True
    assert data["modulus_bits"] >= 2048
    pm = data.get("performance_metrics")
    assert pm is not None
    assert 0.9 <= pm["overall_score"] <= 0.98


def test_rsa_hardened_oaep_compliance():
    data = _invoke_and_load(
        Path("RSA") / "rsa_defense.py",
        "--demo",
        "hardened_oaep",
    )
    assert data["exchange_ok"] is True
    assert data["modulus_bits"] >= 2048
    assert data["padding_scheme"] == "OAEP-SHA256"
    assert data["resists_factoring"] is True
    pm = data.get("performance_metrics")
    assert pm is not None
    assert pm["overall_score"] >= 0.95
