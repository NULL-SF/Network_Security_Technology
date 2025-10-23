import json
import os
import secrets
import sys
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple


def info(message: str) -> None:
    print(f"[INFO] {message}", flush=True)


def warning(message: str) -> None:
    print(f"[WARNING] {message}", flush=True)


def error(message: str) -> None:
    print(f"[ERROR] {message}", flush=True, file=sys.stderr)


def current_timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def save_json_result(
    data: Dict[str, Any],
    log_dir: str,
    prefix: str,
) -> Tuple[Path, Dict[str, Any]]:
    """
    Save structured JSON data into the logs directory and return the saved path
    together with the data payload that includes the json_log_path field.
    """
    ensure_directory(Path(log_dir))
    logfile = Path(log_dir) / f"{prefix}_{current_timestamp()}_{os.getpid()}.json"
    payload = deepcopy(data)
    payload["json_log_path"] = str(logfile)
    with logfile.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return logfile, payload


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    if any((n % p) == 0 for p in small_primes):
        return False
    # write n-1 as 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits: int = 256) -> int:
    """
    Generate a probable prime number with the specified bit length using
    Miller-Rabin rounds sufficient for educational demonstration.
    """
    assert bits >= 8, "Bit length too small for prime generation"
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def exp_mod(base: int, exponent: int, modulus: int) -> int:
    return pow(base, exponent, modulus)


def chunk_bits(value: int, chunk_size: int) -> Iterable[int]:
    while value:
        yield value & ((1 << chunk_size) - 1)
        value >>= chunk_size


def monotonic_time() -> float:
    return time.perf_counter()


__all__ = [
    "chunk_bits",
    "current_timestamp",
    "ensure_directory",
    "error",
    "exp_mod",
    "generate_large_prime",
    "info",
    "modinv",
    "monotonic_time",
    "save_json_result",
    "warning",
]
