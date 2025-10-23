import argparse
import json
import secrets
import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from common import utils
from RSA import rsa_utils

MESSAGE_PATH = ROOT_DIR / "message.txt"


def load_message_bytes() -> bytes:
    if MESSAGE_PATH.exists():
        return MESSAGE_PATH.read_text(encoding="utf-8").encode("utf-8")
    return b"RSA demo message"


def demo_rsa_exchange(bits: int = 2048) -> dict:
    utils.info(f"Generating RSA key pair ({bits}-bit modulus).")
    n, e, d = rsa_utils.generate_rsa_keypair(bits)
    message = load_message_bytes()
    utils.info("Encrypting sample message with OAEP padding.")
    ciphertext = rsa_utils.oaep_encrypt(message, e, n)
    utils.info("Decrypting ciphertext with OAEP padding.")
    decrypted = rsa_utils.oaep_decrypt(ciphertext, d, n)
    exchange_ok = decrypted == message
    utils.info("RSA exchange completed successfully." if exchange_ok else "RSA exchange failed.")

    return {
        "protocol": "rsa",
        "mode": "demo",
        "mitm_success": None,
        "mitm_detected": None,
        "exchange_ok": exchange_ok,
        "message_hex": message.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "decrypted_hex": decrypted.hex(),
        "key_size_bits": n.bit_length(),
        "padding_scheme": "OAEP-SHA256",
        "success_rate": 1.0 if exchange_ok else 0.0,
        "recovered_key_bits": [],
        "timing_vulnerability_mitigated": None,
        "plaintext_preview": MESSAGE_PATH.read_text(encoding="utf-8") if MESSAGE_PATH.exists() else message.decode("utf-8", "ignore"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="RSA key exchange demonstration.")
    parser.add_argument("--mode", default="demo", choices=["demo"], help="Execution mode.")
    parser.add_argument("--bits", type=int, default=2048, help="Length of RSA modulus in bits.")
    parser.add_argument("--log-dir", default="logs", help="Directory to store JSON logs.")
    args = parser.parse_args()

    if args.mode != "demo":
        raise ValueError("Unsupported mode.")

    result = demo_rsa_exchange(args.bits)
    _, payload = utils.save_json_result(result, args.log_dir, "rsa_normal")
    print(json.dumps(payload), flush=True)


if __name__ == "__main__":
    main()
