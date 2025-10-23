import hashlib
import math
import random
import secrets
from typing import Dict, List, Tuple

from common import utils


def generate_rsa_keypair(bits: int = 2048) -> Tuple[int, int, int]:
    e = 65537
    while True:
        p = utils.generate_large_prime(bits // 2)
        q = utils.generate_large_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        d = utils.modinv(e, phi)
        n = p * q
        if n.bit_length() < bits:
            continue
        return n, e, d


def encrypt(message: int, public_exponent: int, modulus: int) -> int:
    return pow(message, public_exponent, modulus)


def decrypt(ciphertext: int, private_exponent: int, modulus: int) -> int:
    return pow(ciphertext, private_exponent, modulus)


def i2osp(value: int, length: int) -> bytes:
    if value < 0:
        raise ValueError("negative integer")
    if value >= 256 ** length:
        raise ValueError("integer too large")
    return value.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def mgf1(seed: bytes, length: int, hash_algorithm=hashlib.sha256) -> bytes:
    hlen = hash_algorithm().digest_size
    counter = 0
    output = bytearray()
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output.extend(hash_algorithm(seed + c).digest())
        counter += 1
    return bytes(output[:length])


def oaep_encode(
    message: bytes,
    k: int,
    *,
    label: bytes = b"",
    hash_algorithm=hashlib.sha256,
    randfunc=None,
) -> bytes:
    hlen = hash_algorithm().digest_size
    if len(message) > k - 2 * hlen - 2:
        raise ValueError("message too long for OAEP")
    lhash = hash_algorithm(label).digest()
    ps = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message
    if randfunc is None:
        seed = secrets.token_bytes(hlen)
    else:
        seed = randfunc(hlen)
    db_mask = mgf1(seed, k - hlen - 1, hash_algorithm)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hlen, hash_algorithm)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(
    encoded: bytes,
    *,
    label: bytes = b"",
    hash_algorithm=hashlib.sha256,
) -> bytes:
    hlen = hash_algorithm().digest_size
    if len(encoded) < 2 * hlen + 2:
        raise ValueError("encoded message too short")
    if encoded[0] != 0:
        raise ValueError("decryption error")
    masked_seed = encoded[1 : 1 + hlen]
    masked_db = encoded[1 + hlen :]
    seed_mask = mgf1(masked_db, hlen, hash_algorithm)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, len(masked_db), hash_algorithm)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    lhash = hash_algorithm(label).digest()
    if db[:hlen] != lhash:
        raise ValueError("label hash mismatch")
    idx = db.find(b"\x01", hlen)
    if idx == -1:
        raise ValueError("invalid padding")
    return db[idx + 1 :]


def oaep_encrypt(
    message: bytes,
    public_exponent: int,
    modulus: int,
    *,
    label: bytes = b"",
    hash_algorithm=hashlib.sha256,
    randfunc=None,
) -> bytes:
    k = (modulus.bit_length() + 7) // 8
    encoded = oaep_encode(message, k, label=label, hash_algorithm=hash_algorithm, randfunc=randfunc)
    ciphertext = pow(os2ip(encoded), public_exponent, modulus)
    return i2osp(ciphertext, k)


def oaep_decrypt(
    ciphertext: bytes,
    private_exponent: int,
    modulus: int,
    *,
    label: bytes = b"",
    hash_algorithm=hashlib.sha256,
) -> bytes:
    k = (modulus.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("invalid ciphertext length")
    plaintext_int = pow(os2ip(ciphertext), private_exponent, modulus)
    encoded = i2osp(plaintext_int, k)
    return oaep_decode(encoded, label=label, hash_algorithm=hash_algorithm)


def simulate_timing_data(
    n: int,
    e: int,
    d: int,
    samples: int,
    *,
    base_time: float = 5e-5,
    extra_time: float = 1.5e-4,
    noise: float = 2e-5,
    blinding: bool = False,
    constant_time: bool = False,
    jitter: float = 0.0,
    seed: int = 2024,
    custom_message: bytes | None = None,
) -> Dict[str, object]:
    rng = random.Random(seed)
    d_bits = bin(d)[2:]
    actual_bits = [int(bit) for bit in d_bits]
    bit_samples: List[List[float]] = [[] for _ in actual_bits]
    total_times: List[float] = []
    k = (n.bit_length() + 7) // 8
    hash_len = hashlib.sha256().digest_size
    max_msg_len = k - 2 * hash_len - 2
    if max_msg_len <= 0:
        raise ValueError("modulus too small for OAEP")

    for _ in range(samples):
        if custom_message:
            msg_bytes = custom_message[:max_msg_len]
            if not msg_bytes:
                msg_bytes = b"\x00"
        else:
            message_len = max(1, min(max_msg_len, 32))
            msg_bytes = rng.randbytes(message_len) if hasattr(rng, "randbytes") else bytes(
                rng.getrandbits(8) for _ in range(message_len)
            )
        ciphertext_bytes = oaep_encrypt(
            msg_bytes,
            e,
            n,
            randfunc=lambda size, _rng=rng: (
                _rng.randbytes(size) if hasattr(_rng, "randbytes") else bytes(_rng.getrandbits(8) for _ in range(size))
            ),
        )
        decrypted_bytes = oaep_decrypt(ciphertext_bytes, d, n)
        assert decrypted_bytes == msg_bytes
        ciphertext = os2ip(ciphertext_bytes)

        sample_times: List[float] = []
        for idx, bit in enumerate(actual_bits):
            step_time = base_time + abs(rng.gauss(0, noise))
            if constant_time:
                extra_component = abs(rng.gauss(0, noise))
            elif blinding:
                extra_component = abs(rng.gauss(0, extra_time))
            else:
                if bit == 1:
                    extra_component = extra_time + abs(rng.gauss(0, noise / 2))
                else:
                    extra_component = abs(rng.gauss(0, noise / 2))
            step_time += extra_component
            bit_samples[idx].append(step_time)
            sample_times.append(step_time)
        total_time = sum(sample_times)
        if jitter:
            total_time += rng.uniform(0, jitter)
        total_times.append(total_time)

    averages = [sum(values) / len(values) for values in bit_samples]
    min_avg = min(averages)
    max_avg = max(averages)
    threshold = (min_avg + max_avg) / 2 if max_avg != min_avg else max_avg
    recovered_bits = [1 if value > threshold else 0 for value in averages]
    correct_bits = sum(1 for a, b in zip(actual_bits, recovered_bits) if a == b)
    success_rate = correct_bits / len(actual_bits)
    correlation_found = success_rate > 0.7
    leakage_strength = max_avg - min_avg

    bit_margin = [avg - threshold for avg in averages]

    return {
        "actual_bits": actual_bits,
        "recovered_bits": recovered_bits,
        "success_rate": success_rate,
        "correlation_found": correlation_found,
        "timings": total_times,
        "average_bit_times": averages,
        "bit_margin": bit_margin,
        "threshold": threshold,
        "base_time": base_time,
        "extra_time": extra_time,
        "leakage_strength": leakage_strength,
        "padding_scheme": "OAEP-SHA256",
        "modulus_bits": n.bit_length(),
    }


__all__ = [
    "decrypt",
    "encrypt",
    "generate_rsa_keypair",
    "oaep_encrypt",
    "oaep_decrypt",
    "simulate_timing_data",
]
