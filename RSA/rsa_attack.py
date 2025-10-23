import argparse
import json
import sys
from pathlib import Path
from statistics import mean

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
    return b"RSA timing demo"


def timing_attack_demo(samples: int, bits: int = 2048) -> dict:
    utils.info("Generating RSA key pair for timing attack simulation.")
    n, e, d = rsa_utils.generate_rsa_keypair(bits)
    utils.info("Collecting timing traces from vulnerable RSA implementation.")
    message_bytes = load_message_bytes()
    timing_data = rsa_utils.simulate_timing_data(n, e, d, samples, custom_message=message_bytes)
    recovered_bits = timing_data["recovered_bits"]
    actual_bits = timing_data["actual_bits"]
    success_rate = timing_data["success_rate"]
    correlation_found = timing_data["correlation_found"]
    utils.info(f"Recovered {success_rate:.2%} of private key bits from timing leakage.")

    return {
        "protocol": "rsa",
        "attack": "timing",
        "samples": samples,
        "mitm_success": None,
        "mitm_detected": None,
        "exchange_ok": None,
        "success_rate": success_rate,
        "correlation_found": correlation_found,
        "recovered_key_bits": recovered_bits[:64],
        "correct_bit_count": int(success_rate * len(actual_bits)),
        "bit_count": len(actual_bits),
        "bit_length": len(actual_bits),
        "timing_vulnerability_mitigated": False,
        "timing_stats": {
            "min": min(timing_data["timings"]),
            "max": max(timing_data["timings"]),
            "average": mean(timing_data["timings"]),
        },
        "bit_margin_preview": timing_data["bit_margin"][:16],
        "padding_scheme": timing_data["padding_scheme"],
        "modulus_bits": timing_data["modulus_bits"],
        "plaintext_preview": message_bytes.decode("utf-8", "ignore"),
        "message_digest": rsa_utils.hashlib.sha256(message_bytes).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="RSA timing side-channel attack demonstration.")
    parser.add_argument("--run", default="timing_demo", choices=["timing_demo"], help="Demo target.")
    parser.add_argument("--samples", type=int, default=1000, help="Number of timing samples.")
    parser.add_argument("--bits", type=int, default=2048, help="RSA modulus size.")
    parser.add_argument("--log-dir", default="logs", help="Directory to store JSON logs.")
    args = parser.parse_args()

    if args.run != "timing_demo":
        raise ValueError("Unsupported run target.")

    result = timing_attack_demo(args.samples, args.bits)
    _, payload = utils.save_json_result(result, args.log_dir, "rsa_attack_timing")
    print(json.dumps(payload), flush=True)


if __name__ == "__main__":
    main()
