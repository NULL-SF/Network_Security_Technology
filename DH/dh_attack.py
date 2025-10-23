import argparse
import json
import secrets
import sys
from hashlib import sha256
from pathlib import Path
from typing import Dict

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
MESSAGE_PATH = ROOT_DIR / "message.txt"

from common.utils import info, save_json_result


DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
DEFAULT_G = 2


def derive_key(shared_secret: int) -> bytes:
    return sha256(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")).digest()


def xor_cipher(message: bytes, key_material: bytes) -> bytes:
    key_stream = key_material * (len(message) // len(key_material) + 1)
    return bytes(m ^ k for m, k in zip(message, key_stream))


def load_message() -> bytes:
    if MESSAGE_PATH.exists():
        return MESSAGE_PATH.read_text(encoding="utf-8").encode("utf-8")
    return b"Meet at dawn"


def simulate_mitm(mode: str) -> Dict[str, object]:
    if mode != "local":
        raise ValueError("Only local MITM simulation is implemented in this demo.")

    info("Setting up Diffie-Hellman MITM demonstration.")
    p = DEFAULT_P
    g = DEFAULT_G

    a = secrets.randbelow(p - 3) + 2
    b = secrets.randbelow(p - 3) + 2
    mallory_to_alice = secrets.randbelow(p - 3) + 2
    mallory_to_bob = secrets.randbelow(p - 3) + 2

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, mallory_to_bob, p)
    M2 = pow(g, mallory_to_alice, p)

    info("Mallory intercepts Alice's public value and replaces it for Bob.")
    alice_shared = pow(M2, a, p)
    info("Mallory computes shared secret with Alice.")
    mallory_shared_alice = pow(A, mallory_to_alice, p)
    info("Mallory intercepts Bob's public value and replaces it for Alice.")
    bob_shared = pow(M1, b, p)
    info("Mallory computes shared secret with Bob.")
    mallory_shared_bob = pow(B, mallory_to_bob, p)

    plaintext = load_message()
    info("Alice encrypts a message using the derived shared key.")
    alice_key = derive_key(alice_shared)
    ciphertext = xor_cipher(plaintext, alice_key)

    info("Mallory decrypts Alice's ciphertext with her shared key.")
    mallory_key = derive_key(mallory_shared_alice)
    recovered_plaintext = xor_cipher(ciphertext, mallory_key)
    mitm_success = recovered_plaintext == plaintext

    result = {
        "protocol": "dh",
        "mode": mode,
        "attack": "mitm",
        "mitm_success": mitm_success,
        "mitm_detected": False,
        "exchange_ok": False,
        "alice_public": hex(A),
        "bob_public": hex(B),
        "alice_shared": hex(alice_shared),
        "bob_shared": hex(bob_shared),
        "mallory_shared_with_alice": hex(mallory_shared_alice),
        "mallory_shared_with_bob": hex(mallory_shared_bob),
        "recovered_message": recovered_plaintext.decode("utf-8"),
        "success_rate": 1.0 if mitm_success else 0.0,
        "recovered_key_bits": [],
        "timing_vulnerability_mitigated": None,
        "evidence": "Mallory read plaintext" if mitm_success else "Mallory failed to read plaintext",
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Diffie-Hellman MITM attack demonstration.")
    parser.add_argument("--run", default="mitm_demo", choices=["mitm_demo"], help="Demo selector.")
    parser.add_argument("--mode", default="local", choices=["local"], help="Execution mode.")
    parser.add_argument("--log-dir", default="logs", help="Directory to store JSON logs.")
    args = parser.parse_args()

    if args.run != "mitm_demo":
        raise ValueError("Unsupported run target.")

    result = simulate_mitm(args.mode)
    _, payload = save_json_result(result, args.log_dir, "dh_attack_mitm")
    print(json.dumps(payload), flush=True)


if __name__ == "__main__":
    main()
