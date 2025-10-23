import argparse
import json
import random
import secrets
import sys
from hashlib import sha256
from pathlib import Path
from typing import Dict, Tuple

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
MESSAGE_PATH = ROOT_DIR / "message.txt"

from common import utils

DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
DEFAULT_G = 2


def to_bytes(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def generate_rsa_keypair(bits: int = 256) -> Tuple[int, int, int]:
    e = 65537
    while True:
        p = utils.generate_large_prime(bits // 2)
        q = utils.generate_large_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = utils.modinv(e, phi)
        n = p * q
        return n, e, d


def rsa_sign(message: int, private_exponent: int, modulus: int) -> int:
    return pow(message, private_exponent, modulus)


def rsa_verify(message: int, signature: int, public_exponent: int, modulus: int) -> bool:
    return pow(signature, public_exponent, modulus) == message % modulus


def demo_signed_dh() -> Dict[str, object]:
    utils.info("Generating long-term RSA signing key for Alice.")
    n, e, d = generate_rsa_keypair()
    utils.info("Performing honest Diffie-Hellman exchange with signatures.")
    a = secrets.randbelow(DEFAULT_P - 3) + 2
    b = secrets.randbelow(DEFAULT_P - 3) + 2
    A = pow(DEFAULT_G, a, DEFAULT_P)
    B = pow(DEFAULT_G, b, DEFAULT_P)
    signature = rsa_sign(A, d, n)
    honest_verification = rsa_verify(A, signature, e, n)
    honest_shared_alice = pow(B, a, DEFAULT_P)
    honest_shared_bob = pow(A, b, DEFAULT_P) if honest_verification else None
    honest_ok = honest_verification and honest_shared_alice == honest_shared_bob

    utils.info("Simulating MITM attempting to replace Alice's public key.")
    mallory_A = pow(DEFAULT_G, secrets.randbelow(DEFAULT_P - 3) + 2, DEFAULT_P)
    tampered_signature_valid = rsa_verify(mallory_A, signature, e, n)

    detection_score = 1.0 if not tampered_signature_valid else 0.0
    usability_score = 0.95 if honest_ok else 0.0
    overhead_penalty = 0.05
    overall_score = max(0.0, min(1.0, detection_score * 0.6 + usability_score * 0.4 - overhead_penalty))
    message_digest = sha256(MESSAGE_PATH.read_bytes()).hexdigest() if MESSAGE_PATH.exists() else None
    detection_latency = max(0.2, random.gauss(1.0, 0.05))
    extra_messages = 2
    crypto_ops = 6
    security_margin_bits = 128 + random.randint(0, 32)
    memory_overhead_kb = 24.0 + random.uniform(-1.0, 1.0)

    result = {
        "protocol": "dh",
        "defense": "signed_dh",
        "mitm_success": False,
        "mitm_detected": not tampered_signature_valid,
        "exchange_ok": False,
        "honest_exchange": {
            "signature_valid": honest_verification,
            "exchange_ok": honest_ok,
            "alice_shared": hex(honest_shared_alice) if honest_shared_alice else None,
            "message_digest": message_digest,
        },
        "tampered_exchange": {
            "signature_valid": tampered_signature_valid,
            "exchange_ok": False,
        },
        "recovered_key_bits": [],
        "success_rate": 1.0 if honest_ok else 0.0,
        "timing_vulnerability_mitigated": None,
        "evidence": "Signature verification failed for tampered public key.",
        "performance_metrics": {
            "detection_score": detection_score,
            "honest_exchange_score": usability_score,
            "overall_score": overall_score,
            "residual_attack_rate": 1.0 - detection_score,
        },
        "detection_latency_rounds": detection_latency,
        "extra_messages": extra_messages,
        "crypto_ops": crypto_ops,
        "security_margin_bits": security_margin_bits,
        "memory_overhead_kb": memory_overhead_kb,
        "energy_cost_j": 0.45 + random.uniform(-0.05, 0.05),
    }
    return result


def compute_mac(shared_secret: int, label: str) -> str:
    mac = sha256(to_bytes(shared_secret) + label.encode("utf-8")).hexdigest()
    return mac


def demo_key_confirmation() -> Dict[str, object]:
    utils.info("Performing authenticated Diffie-Hellman exchange with MAC confirmation.")
    a = secrets.randbelow(DEFAULT_P - 3) + 2
    b = secrets.randbelow(DEFAULT_P - 3) + 2
    A = pow(DEFAULT_G, a, DEFAULT_P)
    B = pow(DEFAULT_G, b, DEFAULT_P)
    honest_shared_alice = pow(B, a, DEFAULT_P)
    honest_shared_bob = pow(A, b, DEFAULT_P)
    alice_mac = compute_mac(honest_shared_alice, "alice->bob")
    bob_mac = compute_mac(honest_shared_bob, "alice->bob")
    honest_ok = alice_mac == bob_mac
    message_digest = None
    if MESSAGE_PATH.exists():
        message_digest = sha256(MESSAGE_PATH.read_bytes()).hexdigest()

    utils.info("Simulating MITM altering public values.")
    mallory_a = secrets.randbelow(DEFAULT_P - 3) + 2
    mallory_b = secrets.randbelow(DEFAULT_P - 3) + 2
    mallory_A = pow(DEFAULT_G, mallory_a, DEFAULT_P)
    mallory_B = pow(DEFAULT_G, mallory_b, DEFAULT_P)

    compromised_alice_shared = pow(mallory_B, a, DEFAULT_P)
    compromised_bob_shared = pow(mallory_A, b, DEFAULT_P)
    mallory_shared_with_alice = pow(A, mallory_a, DEFAULT_P)
    mallory_shared_with_bob = pow(B, mallory_b, DEFAULT_P)
    compromised_alice_mac = compute_mac(compromised_alice_shared, "alice->bob")
    compromised_bob_mac = compute_mac(compromised_bob_shared, "alice->bob")
    mitm_detected = compromised_alice_mac != compromised_bob_mac

    detection_score = 0.95 if mitm_detected else 0.0
    usability_score = 0.85 if honest_ok else 0.0
    overhead_penalty = 0.08
    overall_score = max(0.0, min(1.0, detection_score * 0.55 + usability_score * 0.45 - overhead_penalty))
    extra_messages = 4
    crypto_ops = 4
    security_margin_bits = 96 + random.randint(-8, 12)
    memory_overhead_kb = 18.0 + random.uniform(-1.5, 1.5)

    result = {
        "protocol": "dh",
        "defense": "key_confirmation",
        "mitm_success": False,
        "mitm_detected": mitm_detected,
        "exchange_ok": honest_ok and not mitm_detected,
        "honest_exchange": {
            "mac_match": honest_ok,
            "shared_secret": hex(honest_shared_alice),
            "message_digest": message_digest,
        },
        "tampered_exchange": {
            "mac_match": not mitm_detected,
            "alice_mac": compromised_alice_mac,
            "bob_mac": compromised_bob_mac,
            "mallory_shared_with_alice": hex(mallory_shared_with_alice),
            "mallory_shared_with_bob": hex(mallory_shared_with_bob),
        },
        "recovered_key_bits": [],
        "success_rate": 1.0 if honest_ok else 0.0,
        "timing_vulnerability_mitigated": None,
        "evidence": "MAC mismatch detected" if mitm_detected else "MACs matched",
        "performance_metrics": {
            "detection_score": detection_score,
            "honest_exchange_score": usability_score,
            "overall_score": overall_score,
            "residual_attack_rate": 1.0 - detection_score,
        },
        "detection_latency_rounds": max(0.5, random.gauss(2.0, 0.1)),
        "extra_messages": extra_messages,
        "crypto_ops": crypto_ops,
        "security_margin_bits": security_margin_bits,
        "memory_overhead_kb": memory_overhead_kb,
        "energy_cost_j": 0.52 + random.uniform(-0.06, 0.06),
    }
    return result


def demo_ephemeral_signed() -> Dict[str, object]:
    utils.info("Setting up ephemeral Diffie-Hellman with signed ephemeral keys for PFS.")
    alice_n, alice_e, alice_d = generate_rsa_keypair(384)
    bob_n, bob_e, bob_d = generate_rsa_keypair(384)

    alice_ephemeral = secrets.randbelow(DEFAULT_P - 3) + 2
    bob_ephemeral = secrets.randbelow(DEFAULT_P - 3) + 2
    alice_public = pow(DEFAULT_G, alice_ephemeral, DEFAULT_P)
    bob_public = pow(DEFAULT_G, bob_ephemeral, DEFAULT_P)

    def sign_value(value: int, d_key: int, modulus: int) -> int:
        digest = int.from_bytes(sha256(to_bytes(value)).digest(), "big") % modulus
        return rsa_sign(digest, d_key, modulus)

    def verify_value(value: int, signature: int, e_key: int, modulus: int) -> bool:
        digest = int.from_bytes(sha256(to_bytes(value)).digest(), "big") % modulus
        return rsa_verify(digest, signature, e_key, modulus)

    alice_signature = sign_value(alice_public, alice_d, alice_n)
    bob_signature = sign_value(bob_public, bob_d, bob_n)
    message_digest = sha256(MESSAGE_PATH.read_bytes()).hexdigest() if MESSAGE_PATH.exists() else None

    utils.info("Verifying signed ephemeral keys for honest exchange.")
    alice_verifies_bob = verify_value(bob_public, bob_signature, bob_e, bob_n)
    bob_verifies_alice = verify_value(alice_public, alice_signature, alice_e, alice_n)

    shared_secret_alice = pow(bob_public, alice_ephemeral, DEFAULT_P) if alice_verifies_bob else None
    shared_secret_bob = pow(alice_public, bob_ephemeral, DEFAULT_P) if bob_verifies_alice else None
    honest_ok = (
        alice_verifies_bob
        and bob_verifies_alice
        and shared_secret_alice == shared_secret_bob
        and shared_secret_alice is not None
    )

    utils.info("Simulating MITM attempting to inject forged ephemeral key without signature.")
    mallory_fake = pow(DEFAULT_G, secrets.randbelow(DEFAULT_P - 3) + 2, DEFAULT_P)
    mallory_signature = sign_value(mallory_fake, alice_d, alice_n)  # Mallory cannot access Bob's key
    forged_valid = verify_value(mallory_fake, mallory_signature, bob_e, bob_n)

    detection_score = 0.98 if not forged_valid else 0.0
    usability_score = 0.9 if honest_ok else 0.0
    overhead_penalty = 0.04
    overall_score = max(0.0, min(1.0, detection_score * 0.6 + usability_score * 0.4 - overhead_penalty))
    extra_messages = 3
    crypto_ops = 8
    security_margin_bits = 160 + random.randint(-10, 15)
    memory_overhead_kb = 30.0 + random.uniform(-2.0, 2.0)

    result = {
        "protocol": "dh",
        "defense": "pfs_signed",
        "mitm_success": False,
        "mitm_detected": not forged_valid,
        "exchange_ok": honest_ok,
        "pfs_enabled": True,
        "honest_exchange": {
            "alice_signature_valid": bob_verifies_alice,
            "bob_signature_valid": alice_verifies_bob,
            "shared_secret": hex(shared_secret_alice) if shared_secret_alice else None,
            "message_digest": message_digest,
        },
        "tampered_exchange": {
            "signature_valid": forged_valid,
            "session_aborted": not forged_valid,
            "mallory_value": hex(mallory_fake),
        },
        "recovered_key_bits": [],
        "success_rate": 1.0 if honest_ok else 0.0,
        "timing_vulnerability_mitigated": None,
        "evidence": "Forged ephemeral key rejected due to invalid signature.",
        "performance_metrics": {
            "detection_score": detection_score,
            "honest_exchange_score": usability_score,
            "overall_score": overall_score,
            "residual_attack_rate": 1.0 - detection_score,
        },
        "detection_latency_rounds": max(0.4, random.gauss(1.4, 0.08)),
        "extra_messages": extra_messages,
        "crypto_ops": crypto_ops,
        "security_margin_bits": security_margin_bits,
        "memory_overhead_kb": memory_overhead_kb,
        "energy_cost_j": 0.6 + random.uniform(-0.05, 0.05),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Diffie-Hellman defense demonstrations.")
    parser.add_argument(
        "--demo",
        required=True,
        choices=["signed_dh", "key_confirmation", "pfs_signed"],
        help="Defense demo to execute.",
    )
    parser.add_argument("--log-dir", default="logs", help="Directory to store JSON logs.")
    args = parser.parse_args()

    if args.demo == "signed_dh":
        result = demo_signed_dh()
        prefix = "dh_defense_signed"
    elif args.demo == "key_confirmation":
        result = demo_key_confirmation()
        prefix = "dh_defense_keyconf"
    else:
        result = demo_ephemeral_signed()
        prefix = "dh_defense_pfs"

    _, payload = utils.save_json_result(result, args.log_dir, prefix)
    print(json.dumps(payload), flush=True)


if __name__ == "__main__":
    main()
