#!/usr/bin/env python3

"""
Metrics aggregator for key-exchange demos.

Parses per-trial JSON outputs and produces aggregate metrics aligned with the
specifications: Attack Success Rate, Detection Rate, Key Confirmation Rate,
Runtime statistics (with bootstrap CI), Overhead, and Bit Accuracy.
Also generates scenario "cards" summarising important information.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def percentile(values: List[float], q: float) -> float:
    if not values:
        raise ValueError("empty data")
    values = sorted(values)
    k = (len(values) - 1) * q
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return values[int(k)]
    d0 = values[int(f)] * (c - k)
    d1 = values[int(c)] * (k - f)
    return d0 + d1


def wilson_interval(successes: int, total: int, confidence: float = 0.95) -> Optional[Tuple[float, float, float]]:
    if total <= 0:
        return None
    z = {
        0.80: 1.2816,
        0.85: 1.4395,
        0.90: 1.6449,
        0.95: 1.96,
        0.975: 2.2414,
        0.99: 2.5758,
    }.get(confidence, 1.96)
    phat = successes / total
    denom = 1 + (z ** 2) / total
    centre = phat + (z ** 2) / (2 * total)
    margin = z * math.sqrt((phat * (1 - phat) + (z ** 2) / (4 * total)) / total)
    low = (centre - margin) / denom
    high = (centre + margin) / denom
    return phat, max(0.0, low), min(1.0, high)


def bootstrap_mean_ci(values: List[float], iterations: int = 2000, confidence: float = 0.95) -> Optional[Tuple[float, float, float, float]]:
    if not values:
        return None
    if len(values) == 1:
        mean_val = values[0]
        return mean_val, 0.0, mean_val, mean_val
    rnd = random.Random(1337)
    means = []
    n = len(values)
    for _ in range(iterations):
        sample = [rnd.choice(values) for _ in range(n)]
        means.append(sum(sample) / n)
    alpha = 1 - confidence
    mean_val = statistics.mean(values)
    std_dev = statistics.pstdev(values)
    low = percentile(means, alpha / 2)
    high = percentile(means, 1 - alpha / 2)
    return mean_val, std_dev, low, high


def bootstrap_overhead(defense: List[float], baseline: List[float], iterations: int = 4000, confidence: float = 0.95) -> Optional[Tuple[float, float, float]]:
    if not defense or not baseline:
        return None
    rnd = random.Random(2024)
    n_def = len(defense)
    n_base = len(baseline)
    basemean = statistics.mean(baseline)
    if basemean == 0:
        return None
    overhead = (statistics.mean(defense) - basemean) / basemean * 100.0
    samples = []
    for _ in range(iterations):
        d_sample = [rnd.choice(defense) for _ in range(n_def)]
        b_sample = [rnd.choice(baseline) for _ in range(n_base)]
        b_mean = sum(b_sample) / n_base
        if b_mean == 0:
            continue
        samples.append((sum(d_sample) / n_def - b_mean) / b_mean * 100.0)
    if not samples:
        return overhead, overhead, overhead
    alpha = 1 - confidence
    low = percentile(samples, alpha / 2)
    high = percentile(samples, 1 - alpha / 2)
    return overhead, low, high


def fisher_exact(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact test for 2x2 contingency table."""
    total = a + b + c + d
    row1 = a + b
    row2 = c + d
    col1 = a + c
    col2 = b + d
    if min(row1, row2, col1, col2) < 0:
        return 1.0

    def hypergeom(x: int) -> float:
        return math.comb(col1, x) * math.comb(col2, row1 - x) / math.comb(total, row1)

    p_obs = hypergeom(a)
    prob = 0.0
    for x in range(max(0, row1 - col2), min(col1, row1) + 1):
        p = hypergeom(x)
        if p <= p_obs + 1e-12:
            prob += p
    return min(1.0, prob)


def mann_whitney_u(x: List[float], y: List[float]) -> float:
    """Two-sided Mann-Whitney U test (approximate for larger samples)."""
    n1, n2 = len(x), len(y)
    if n1 == 0 or n2 == 0:
        return 1.0
    all_vals = [(val, 0) for val in x] + [(val, 1) for val in y]
    all_vals.sort(key=lambda item: item[0])
    ranks = {}
    i = 0
    while i < len(all_vals):
        j = i
        while j < len(all_vals) and all_vals[j][0] == all_vals[i][0]:
            j += 1
        avg_rank = (i + j + 1) / 2.0
        for k in range(i, j):
            ranks.setdefault(k, avg_rank)
        i = j
    rank_sum_x = sum(ranks[idx] for idx, (_, grp) in enumerate(all_vals) if grp == 0)
    u1 = rank_sum_x - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    mu = n1 * n2 / 2.0
    sigma = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12.0)
    if sigma == 0:
        return 1.0
    z = abs((u1 - mu) / sigma)
    # two-sided p-value using normal approximation
    return 2 * (1 - 0.5 * (1 + math.erf(z / math.sqrt(2))))


def benjamini_hochberg(pvalues: Dict[str, float]) -> Dict[str, float]:
    items = [(k, v) for k, v in pvalues.items() if v is not None]
    if not items:
        return {}
    items.sort(key=lambda item: item[1])
    m = len(items)
    adjusted = {}
    prev = 1.0
    for i, (name, pval) in enumerate(reversed(items), start=1):
        rank = m - i + 1
        adj = min(prev, pval * m / rank)
        prev = adj
        adjusted[name] = adj
    return adjusted


def determine_attack_success(data: Dict[str, Any]) -> Optional[bool]:
    if data.get("attack"):
        if "mitm_success" in data and data["mitm_success"] is not None:
            return bool(data["mitm_success"])
        success_rate = data.get("success_rate")
        if success_rate is not None:
            return success_rate > 0.7
        perf = data.get("performance_metrics") or {}
        residual = perf.get("residual_attack_rate")
        if residual is not None:
            return residual > 0.5
        return None
    if data.get("defense"):
        if "mitm_success" in data and data["mitm_success"] is not None:
            return bool(data["mitm_success"])
        if "attack_success_rate" in data and data["attack_success_rate"] is not None:
            return data["attack_success_rate"] > 0.1
        perf = data.get("performance_metrics") or {}
        residual = perf.get("residual_attack_rate")
        if residual is not None:
            return residual > 0.1
        success_rate = data.get("success_rate")
        if success_rate is not None:
            return success_rate > 0.1
    return None


def compute_bit_accuracy(data: Dict[str, Any]) -> Optional[float]:
    bit_count = data.get("bit_count")
    correct = data.get("correct_bit_count")
    if bit_count and correct is not None:
        if bit_count == 0:
            return None
        return correct / bit_count
    success_rate = data.get("success_rate")
    if success_rate is not None and 0 <= success_rate <= 1:
        return success_rate
    return None


def build_cards(data: Dict[str, Any], scenario: str) -> Dict[str, Any]:
    primary: Dict[str, Any] = {}
    secondary: Dict[str, Any] = {}
    if data.get("attack"):
        compromised = bool(determine_attack_success(data))
        primary = {
            "status": "compromised" if compromised else "resisted",
            "attack_success_rate": data.get("success_rate"),
            "mitm_success": data.get("mitm_success"),
        }
        secondary = {
            "plaintext_preview": data.get("recovered_message") or data.get("plaintext_preview"),
            "evidence": data.get("evidence"),
        }
    elif data.get("defense"):
        perf = data.get("performance_metrics") or {}
        primary = {
            "status": "safe" if perf.get("overall_score", 0) >= 0.9 else "needs-attention",
            "overall_score": perf.get("overall_score"),
            "residual_attack_rate": perf.get("residual_attack_rate"),
            "mitm_detected": data.get("mitm_detected"),
        }
        secondary = {
            "evidence": data.get("evidence"),
            "message_digest": data.get("message_digest")
            or data.get("honest_exchange", {}).get("message_digest")
            if isinstance(data.get("honest_exchange"), dict)
            else None,
        }
    else:
        primary = {
            "status": "ok" if data.get("exchange_ok") else "issue",
            "exchange_ok": data.get("exchange_ok"),
        }
        secondary = {
            "parameters": data.get("parameters"),
            "plaintext_preview": data.get("plaintext_preview"),
        }
    return {
        "scenario": scenario,
        "primary": primary,
        "secondary": secondary,
        "source_log": data.get("json_log_path"),
        "trial_index": data.get("trial_index"),
        "runtime_sec": data.get("runtime_sec"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate metrics from demo JSON outputs.")
    parser.add_argument("--protocol", required=True, help="Protocol to filter (dh|rsa).")
    parser.add_argument("--trials", type=int, default=1, help="Number of repetitions per scenario.")
    parser.add_argument("--output", help="Optional path to write summary JSON.")
    parser.add_argument("--list-file", help="File containing newline-separated JSON paths.")
    parser.add_argument("json_paths", nargs="*", help="JSON artifact paths.")
    args = parser.parse_args()

    protocol = args.protocol.lower()
    json_paths: List[Path] = [Path(p) for p in args.json_paths]
    if args.list_file:
        list_path = Path(args.list_file)
        if list_path.exists():
            lines = [line.strip() for line in list_path.read_text(encoding="utf-8").splitlines()]
            json_paths.extend(Path(line) for line in lines if line)

    scenario_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "attack_success": 0,
        "attack_total": 0,
        "detected": 0,
        "sessions": 0,
        "confirmed": 0,
        "runtime": [],
        "bit_accuracy": [],
        "records": [],
        "json_paths": [],
        "detected_total": 0,
        "detection_latency": [],
        "leakage_strength": [],
        "throughput": [],
        "extra_messages": [],
        "crypto_ops": [],
        "security_margin_bits": [],
        "memory_overhead_kb": [],
        "energy_cost_j": [],
    })
    cards: List[Dict[str, Any]] = []

    for path in json_paths:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("protocol") != protocol:
            continue
        scenario_key: str
        if data.get("attack"):
            scenario_key = "attack"
        elif data.get("defense"):
            scenario_key = f"defense:{data['defense']}"
        else:
            scenario_key = "normal"

        stats = scenario_stats[scenario_key]
        stats["json_paths"].append(str(path))
        stats["records"].append(data)

        attack_success = determine_attack_success(data)
        if attack_success is not None:
            stats["attack_total"] += 1
            if attack_success:
                stats["attack_success"] += 1

        detected = data.get("mitm_detected")
        if detected is not None and scenario_key != "normal":
            stats["detected_total"] += 1
            if detected:
                stats["detected"] += 1

        exchange_ok = data.get("exchange_ok")
        if exchange_ok is not None:
            stats["sessions"] += 1
            if exchange_ok:
                stats["confirmed"] += 1

        runtime = data.get("runtime_sec")
        if runtime is not None:
            stats["runtime"].append(float(runtime))
            if runtime > 0:
                stats["throughput"].append(1.0 / float(runtime))

        bit_acc = compute_bit_accuracy(data)
        if bit_acc is not None:
            stats["bit_accuracy"].append(bit_acc)

        latency = data.get("detection_latency_rounds")
        if latency is not None:
            stats["detection_latency"].append(float(latency))

        leakage = data.get("leakage_strength")
        if leakage is not None:
            stats["leakage_strength"].append(float(leakage))

        for key in ("extra_messages", "crypto_ops", "security_margin_bits", "memory_overhead_kb", "energy_cost_j"):
            if key in data and data[key] is not None:
                stats[key].append(float(data[key]))

        cards.append(build_cards(data, scenario_key))

    if not scenario_stats:
        print("[INFO] No matching JSON artifacts for protocol:", protocol)
        return

    baseline_runtime = scenario_stats.get("normal", {}).get("runtime", [])
    metrics_summary: Dict[str, Any] = {}
    p_values: Dict[str, float] = {}

    total_trials = args.trials

    for scenario, stats in scenario_stats.items():
        metric_entry: Dict[str, Any] = {}

        asr = wilson_interval(stats["attack_success"], stats["attack_total"])
        if asr:
            value, low, high = asr
            metric_entry["attack_success_rate"] = {
                "value": value,
                "ci95": [low, high],
                "successes": stats["attack_success"],
                "total": stats["attack_total"],
            }

        dr_total = stats.get("detected_total", stats["attack_total"])
        if dr_total:
            dr = wilson_interval(stats["detected"], dr_total)
            if dr:
                value, low, high = dr
                metric_entry["detection_rate"] = {
                    "value": value,
                    "ci95": [low, high],
                    "detected": stats["detected"],
                    "total": dr_total,
                }

        if stats["sessions"]:
            kcr = wilson_interval(stats["confirmed"], stats["sessions"])
            if kcr:
                value, low, high = kcr
                metric_entry["key_confirmation_rate"] = {
                    "value": value,
                    "ci95": [low, high],
                    "confirmed": stats["confirmed"],
                    "total": stats["sessions"],
                }

        if stats["runtime"]:
            runtime_stats = bootstrap_mean_ci(stats["runtime"])
            if runtime_stats:
                mean_val, std_dev, low, high = runtime_stats
                metric_entry["runtime_sec"] = {
                    "mean": mean_val,
                    "std": std_dev,
                    "ci95": [low, high],
                    "samples": len(stats["runtime"]),
                }

        if stats["throughput"]:
            tp_stats = bootstrap_mean_ci(stats["throughput"])
            if tp_stats:
                mean_val, std_dev, low, high = tp_stats
                metric_entry["throughput_per_sec"] = {
                    "mean": mean_val,
                    "std": std_dev,
                    "ci95": [low, high],
                }

        if scenario.startswith("defense:") and baseline_runtime:
            overhead_stats = bootstrap_overhead(stats["runtime"], baseline_runtime)
            if overhead_stats:
                ov, low, high = overhead_stats
                metric_entry["overhead_percent"] = {
                    "value": ov,
                    "ci95": [low, high],
                }

        if stats["bit_accuracy"]:
            bitacc_stats = bootstrap_mean_ci(stats["bit_accuracy"])
            if bitacc_stats:
                mean_val, std_dev, low, high = bitacc_stats
                metric_entry["bit_accuracy"] = {
                    "mean": mean_val,
                    "std": std_dev,
                    "ci95": [low, high],
                }

        if stats["detection_latency"]:
            latency_stats = bootstrap_mean_ci(stats["detection_latency"])
            if latency_stats:
                mean_val, std_dev, low, high = latency_stats
                metric_entry["detection_latency_rounds"] = {
                    "mean": mean_val,
                    "std": std_dev,
                    "ci95": [low, high],
                }

        if stats["leakage_strength"]:
            leak_stats = bootstrap_mean_ci(stats["leakage_strength"])
            if leak_stats:
                mean_val, std_dev, low, high = leak_stats
                metric_entry["leakage_strength"] = {
                    "mean": mean_val,
                    "std": std_dev,
                    "ci95": [low, high],
                }

        for key in ("extra_messages", "crypto_ops", "security_margin_bits", "memory_overhead_kb", "energy_cost_j"):
            if stats[key]:
                val = bootstrap_mean_ci(stats[key])
                if val:
                    mean_val, std_dev, low, high = val
                    metric_entry[key] = {
                        "mean": mean_val,
                        "std": std_dev,
                        "ci95": [low, high],
                    }

        metrics_summary[scenario] = metric_entry

    # Statistical comparisons (defenses vs baseline attack)
    attack_stats = scenario_stats.get("attack", {})
    baseline_attack_total = attack_stats.get("attack_total", 0)
    baseline_attack_success = attack_stats.get("attack_success", 0)
    baseline_detect_total = attack_stats.get("detected_total", 0)
    baseline_detect = attack_stats.get("detected", 0)

    for scenario, stats in scenario_stats.items():
        if not scenario.startswith("defense:"):
            continue
        key = scenario.split(":", 1)[1]
        # ASR comparison
        if baseline_attack_total and stats["attack_total"]:
            table = (
                stats["attack_success"],
                stats["attack_total"] - stats["attack_success"],
                baseline_attack_success,
                baseline_attack_total - baseline_attack_success,
            )
            p_values[f"ASR::{key}"] = fisher_exact(*table)
        # Detection comparison
        defense_detect_total = stats.get("detected_total", 0)
        if baseline_detect_total and defense_detect_total:
            table = (
                stats["detected"],
                defense_detect_total - stats["detected"],
                baseline_detect,
                baseline_detect_total - baseline_detect,
            )
            p_values[f"DR::{key}"] = fisher_exact(*table)
        # Runtime comparison via Mann-Whitney
        if attack_stats.get("runtime") and stats["runtime"]:
            p_values[f"RT::{key}"] = mann_whitney_u(stats["runtime"], attack_stats["runtime"])
        # Bit accuracy comparison
        if attack_stats.get("bit_accuracy") and stats["bit_accuracy"]:
            p_values[f"BitAcc::{key}"] = mann_whitney_u(stats["bit_accuracy"], attack_stats["bit_accuracy"])

    adjusted = benjamini_hochberg(p_values)

    print(f"[INFO] Metrics summary for protocol {protocol.upper()}")
    for scenario, entry in metrics_summary.items():
        print(f"  Scenario: {scenario}")
        if "attack_success_rate" in entry:
            asr = entry["attack_success_rate"]
            print(f"    ASR: {asr['value']:.3f} (95% CI {asr['ci95'][0]:.3f}-{asr['ci95'][1]:.3f})")
        if "detection_rate" in entry:
            dr = entry["detection_rate"]
            print(f"    Detection Rate: {dr['value']:.3f} (95% CI {dr['ci95'][0]:.3f}-{dr['ci95'][1]:.3f})")
        if "key_confirmation_rate" in entry:
            kcr = entry["key_confirmation_rate"]
            print(f"    Key Confirmation Rate: {kcr['value']:.3f} (95% CI {kcr['ci95'][0]:.3f}-{kcr['ci95'][1]:.3f})")
        if "runtime_sec" in entry:
            rt = entry["runtime_sec"]
            print(f"    Runtime: {rt['mean']:.4f}s ± {rt['std']:.4f}s (95% CI {rt['ci95'][0]:.4f}-{rt['ci95'][1]:.4f})")
        if "throughput_per_sec" in entry:
            tp = entry["throughput_per_sec"]
            print(f"    Throughput: {tp['mean']:.3f}/s (95% CI {tp['ci95'][0]:.3f}-{tp['ci95'][1]:.3f})")
        if "overhead_percent" in entry:
            oc = entry["overhead_percent"]
            print(f"    Overhead: {oc['value']:.2f}% (95% CI {oc['ci95'][0]:.2f}-{oc['ci95'][1]:.2f})")
        if "bit_accuracy" in entry:
            ba = entry["bit_accuracy"]
            print(f"    Bit Accuracy: {ba['mean']:.3f} (95% CI {ba['ci95'][0]:.3f}-{ba['ci95'][1]:.3f})")
        if "detection_latency_rounds" in entry:
            lat = entry["detection_latency_rounds"]
            print(f"    Detection Latency: {lat['mean']:.3f} rounds (95% CI {lat['ci95'][0]:.3f}-{lat['ci95'][1]:.3f})")
        if "leakage_strength" in entry:
            leak = entry["leakage_strength"]
            print(f"    Leakage Strength: {leak['mean']:.3e} (95% CI {leak['ci95'][0]:.3e}-{leak['ci95'][1]:.3e})")
        if "extra_messages" in entry:
            em = entry["extra_messages"]
            print(f"    Extra Messages: {em['mean']:.2f} (95% CI {em['ci95'][0]:.2f}-{em['ci95'][1]:.2f})")
        if "crypto_ops" in entry:
            co = entry["crypto_ops"]
            print(f"    Crypto Ops: {co['mean']:.2f} (95% CI {co['ci95'][0]:.2f}-{co['ci95'][1]:.2f})")
        if "security_margin_bits" in entry:
            sm = entry["security_margin_bits"]
            print(f"    Security Margin: {sm['mean']:.1f} bits (95% CI {sm['ci95'][0]:.1f}-{sm['ci95'][1]:.1f})")
        if "memory_overhead_kb" in entry:
            mo = entry["memory_overhead_kb"]
            print(f"    Memory Overhead: {mo['mean']:.1f} KB (95% CI {mo['ci95'][0]:.1f}-{mo['ci95'][1]:.1f})")
        if "energy_cost_j" in entry:
            ec = entry["energy_cost_j"]
            print(f"    Energy Cost: {ec['mean']:.3f} J (95% CI {ec['ci95'][0]:.3f}-{ec['ci95'][1]:.3f})")

    if adjusted:
        print("  Adjusted p-values (Benjamini-Hochberg):")
        for name, pval in adjusted.items():
            print(f"    {name}: p_adj={pval:.4g}")

    summary = {
        "protocol": protocol,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "trials": total_trials,
        "cards": cards,
        "metrics": metrics_summary,
        "p_values": adjusted,
    }

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[INFO] Metrics summary written to {out_path}")


if __name__ == "__main__":
    main()
