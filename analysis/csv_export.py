#!/usr/bin/env python3

"""Convert aggregated metrics JSON into CSV rows."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict


def flatten_metrics(protocol: str, metrics: Dict[str, Any]) -> None:
    fieldnames = [
        "protocol",
        "scenario",
        "metric",
        "value",
        "ci95_low",
        "ci95_high",
    ]
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()
    for scenario, values in metrics.items():
        for metric, payload in values.items():
            if isinstance(payload, dict) and "mean" in payload:
                writer.writerow(
                    {
                        "protocol": protocol,
                        "scenario": scenario,
                        "metric": metric,
                        "value": payload["mean"],
                        "ci95_low": payload["ci95"][0],
                        "ci95_high": payload["ci95"][1],
                    }
                )
            elif isinstance(payload, dict) and "value" in payload:
                writer.writerow(
                    {
                        "protocol": protocol,
                        "scenario": scenario,
                        "metric": metric,
                        "value": payload["value"],
                        "ci95_low": payload["ci95"][0],
                        "ci95_high": payload["ci95"][1],
                    }
                )


if __name__ == "__main__":
    import sys

    parser = argparse.ArgumentParser(description="Metrics JSON to CSV")
    parser.add_argument("summary_json", help="Path to ALL_SUMMARY_*.json")
    args = parser.parse_args()

    data = json.loads(Path(args.summary_json).read_text(encoding="utf-8"))
    flatten_metrics(data.get("protocol", "unknown"), data.get("metrics", {}))
