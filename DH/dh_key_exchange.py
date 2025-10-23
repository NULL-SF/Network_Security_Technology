import argparse
import secrets
import json
import sys
from pathlib import Path
from typing import Dict

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from common.utils import info, save_json_result


DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
DEFAULT_G = 2


def generate_private_value(p: int) -> int:
    return secrets.randbelow(p - 3) + 2


def perform_exchange(p: int, g: int) -> Dict[str, object]:
    info("Generating Diffie-Hellman key pair for Alice and Bob.")
    a = generate_private_value(p)
    b = generate_private_value(p)
    A = pow(g, a, p)
    B = pow(g, b, p)
    info("Computing shared secrets.")
    alice_shared = pow(B, a, p)
    bob_shared = pow(A, b, p)
    shared_match = alice_shared == bob_shared
    info("Computed shared secrets match." if shared_match else "Shared secrets mismatch detected.")
    return {
        "protocol": "dh",
        "mode": "demo",
        "mitm_success": False,
        "mitm_detected": False,
        "exchange_ok": shared_match,
        "alice_shared": hex(alice_shared),
        "bob_shared": hex(bob_shared),
        "recovered_key_bits": [],
        "success_rate": None,
        "timing_vulnerability_mitigated": None,
        "parameters": {
            "p_bits": p.bit_length(),
            "g": g,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Diffie-Hellman key exchange demonstration.")
    parser.add_argument("--mode", default="demo", choices=["demo"], help="Execution mode.")
    parser.add_argument("--log-dir", default="logs", help="Directory to store JSON logs.")
    args = parser.parse_args()

    if args.mode != "demo":
        raise ValueError("Unsupported mode.")

    result = perform_exchange(DEFAULT_P, DEFAULT_G)
    _, payload = save_json_result(result, args.log_dir, "dh_normal")
    print(json.dumps(payload), flush=True)


if __name__ == "__main__":
    main()
