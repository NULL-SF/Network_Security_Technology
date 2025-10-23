#!/usr/bin/env bash
# Unified demo orchestrator for DH/RSA key exchange, attacks, and defenses.
# set -euo pipefail  # Recommended for production. Commented for easier debugging during development.

set -uo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration (override via CLI flags or environment variables).
PROTOCOL="dh"            # --protocol=dh|rsa
ACTION="all"          # --action=normal|attack|defense|all
ATTACK_TYPE=""           # --attack-type=mitm|timing
DEFENSE_TYPE=""          # --defense-type=signed_dh|key_confirmation|pfs_signed|blinding|constant_time|hardened_oaep
SAMPLES=50             # --samples=INT
MODE="local"             # --mode=local|network
JITTER=0.0001            # --jitter=FLOAT
LOG_DIR="logs"           # --log-dir=PATH
PYTHON_CMD="python"     # --python-cmd=/path/to/python
TRIALS=50                 # --trials=INT
SAVE_INTERMEDIATE=0      # --save-intermediate=0|1

usage() {
  cat <<'EOF'
Usage: ./run_demo.sh [options]
  --protocol dh|rsa
  --action normal|attack|defense|all
  --attack-type mitm|timing         (required for attack; defaults per protocol when omitted)
  --defense-type signed_dh|key_confirmation|pfs_signed|blinding|constant_time|hardened_oaep
                                   (optional; run all applicable defenses if omitted)
  --samples N                       (timing attack/defense sample size)
  --mode local|network              (DH MITM mode, default local)
  --jitter FLOAT                    (RSA constant-time jitter amplitude)
  --log-dir PATH                    (where to write logs/json artifacts)
  --python-cmd CMD                  (Python interpreter, default python3)
  --trials N                        (number of repetitions per scenario, default 1)
  --save-intermediate 0|1           (keep per-trial logs/JSON in action=all; default 1)
  -h | --help
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --protocol) PROTOCOL="$2"; shift 2 ;;
      --action) ACTION="$2"; shift 2 ;;
      --attack-type) ATTACK_TYPE="$2"; shift 2 ;;
      --defense-type) DEFENSE_TYPE="$2"; shift 2 ;;
      --samples) SAMPLES="$2"; shift 2 ;;
      --mode) MODE="$2"; shift 2 ;;
      --jitter) JITTER="$2"; shift 2 ;;
      --log-dir) LOG_DIR="$2"; shift 2 ;;
      --python-cmd) PYTHON_CMD="$2"; shift 2 ;;
      --trials) TRIALS="$2"; shift 2 ;;
      --save-intermediate) SAVE_INTERMEDIATE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "[ERROR] Unknown argument: $1" >&2; usage; exit 1 ;;
    esac
  done
}

parse_args "$@"

if ! [[ "$TRIALS" =~ ^[1-9][0-9]*$ ]]; then
  echo "[ERROR] --trials must be a positive integer." >&2
  exit 1
fi

if [[ "$SAVE_INTERMEDIATE" != "0" && "$SAVE_INTERMEDIATE" != "1" ]]; then
  echo "[ERROR] --save-intermediate must be 0 or 1." >&2
  exit 1
fi

if ! command -v "$PYTHON_CMD" >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1; then
    echo "[WARNING] '$PYTHON_CMD' not found. Falling back to 'python'." >&2
    PYTHON_CMD="python"
  else
    echo "[ERROR] Python interpreter '$PYTHON_CMD' not available." >&2
    exit 1
  fi
fi

if ! "$PYTHON_CMD" -c "import sys" >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1 && [[ "$PYTHON_CMD" != "python" ]]; then
    echo "[WARNING] '$PYTHON_CMD' failed to execute. Falling back to 'python'." >&2
    PYTHON_CMD="python"
  else
    echo "[ERROR] Unable to run Python interpreter '$PYTHON_CMD'." >&2
    exit 1
  fi
fi

LOG_DIR="$(cd "$BASE_DIR" && mkdir -p "$LOG_DIR" && cd "$LOG_DIR" && pwd)"

declare -a COLLECTED_JSONS=()
OVERALL_STATUS=0
CURRENT_TRIAL=1
TOTAL_TRIALS=1
declare -a PURGE_JSONS=()
declare -a PURGE_LOGS=()
declare -i TOTAL_STEPS=0
declare -i CURRENT_STEP=0

extract_json() {
  local log_path="$1"
  local json_path="$2"
  "$PYTHON_CMD" - "$log_path" "$json_path" <<'PY'
import json
import sys
from pathlib import Path

log_path = Path(sys.argv[1])
json_path = Path(sys.argv[2]).resolve()
payload = None
for line in reversed(log_path.read_text(encoding="utf-8").splitlines()):
    candidate = line.strip()
    if not candidate:
        continue
    if not candidate.startswith("{"):
        continue
    try:
        payload = json.loads(candidate)
        break
    except json.JSONDecodeError:
        continue

if payload is None:
    raise SystemExit(1)

original_path = None
if "json_log_path" in payload:
    try:
        raw = Path(payload["json_log_path"])
        original_path = raw if raw.is_absolute() else (log_path.parent / raw).resolve()
    except Exception:
        original_path = None

payload["json_log_path"] = str(json_path)
json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if original_path and original_path.exists() and original_path != json_path:
    try:
        original_path.unlink()
    except OSError:
        pass
PY
  local status=$?
  if [[ $status -ne 0 ]]; then
    return 1
  fi
  echo "$json_path"
}

run_summary() {
  local json_path="$1"
  "$PYTHON_CMD" - <<'PY' "$json_path"
import json
import sys
from pathlib import Path

fields = ["mitm_success", "mitm_detected", "exchange_ok", "success_rate", "timing_vulnerability_mitigated"]
path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
summary = []
for key in fields:
    if key in data:
        summary.append(f"{key}={data.get(key)}")
print(f"SUMMARY ({path.name}): " + ", ".join(summary))
PY
}

run_step() {
  local tag="$1"; shift
  local description="$1"; shift
  local -a command=("$@")

  local timestamp
  timestamp="$(date +%Y%m%d_%H%M%S)"
  local base="${PROTOCOL}_${tag}_${timestamp}_$$"
  local log_file="${LOG_DIR}/${base}.log"
  local json_file="${LOG_DIR}/${base}.json"
  local start_ts end_ts runtime_sec
  start_ts="$(date +%s.%N)"

  local exit_code
  local progress_active=0
  if [[ "$ACTION" == "all" && "$SAVE_INTERMEDIATE" == "1" ]]; then
    progress_active=1
  fi
  local progress_active=0
  local silent_mode=0
  if [[ "$ACTION" == "all" ]]; then
    if [[ "$SAVE_INTERMEDIATE" == "0" ]]; then
      silent_mode=1
      progress_active=1
    fi
  fi

  if [[ $progress_active -eq 1 || $silent_mode -eq 1 ]]; then
    printf "[INFO] >>> %s\n" "$description" >"$log_file"
    printf "[INFO] Command: %s\n" "${command[*]}" >>"$log_file"
    PYTHONUNBUFFERED=1 "${command[@]}" >>"$log_file" 2>&1
    exit_code=$?
  else
    echo "[INFO] >>> ${description}"
    echo "[INFO] Log: ${log_file}"
    echo "[INFO] Command: ${command[*]}"
    PYTHONUNBUFFERED=1 "${command[@]}" 2>&1 | tee "$log_file"
    exit_code="${PIPESTATUS[0]}"
  fi
  end_ts="$(date +%s.%N)"

  runtime_sec=$("$PYTHON_CMD" - <<'PY' "$start_ts" "$end_ts"
import decimal
import sys

decimal.getcontext().prec = 20
start = decimal.Decimal(sys.argv[1])
end = decimal.Decimal(sys.argv[2])
runtime = end - start
print(runtime.normalize())
PY
)

  if [[ $exit_code -ne 0 ]]; then
    echo "[ERROR] Step failed (exit ${exit_code}). See ${log_file}" >&2
    return $exit_code
  fi

  local extracted_path
  if extracted_path="$(extract_json "$log_file" "$json_file")"; then
    if [[ $silent_mode -eq 0 ]]; then
      echo "[INFO] JSON saved to ${extracted_path}"
    fi
    "$PYTHON_CMD" - <<'PY' "$extracted_path" "$runtime_sec" "$CURRENT_TRIAL" "$TOTAL_TRIALS" "$tag" "$description"
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
runtime = float(sys.argv[2])
trial_index = int(sys.argv[3])
trial_total = int(sys.argv[4])
scenario_tag = sys.argv[5]
description = sys.argv[6]

try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"Failed to load JSON {path}: {exc}")

data["runtime_sec"] = runtime
data["trial_index"] = trial_index
data["trial_total"] = trial_total
data["scenario_tag"] = scenario_tag
data.setdefault("metadata", {})["description"] = description
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
    COLLECTED_JSONS+=("$extracted_path")
    if [[ "$ACTION" == "all" && "$SAVE_INTERMEDIATE" == "0" ]]; then
      PURGE_JSONS+=("$extracted_path")
    fi
    if [[ $silent_mode -eq 0 ]]; then
      run_summary "$extracted_path"
    fi
  else
    echo "[WARNING] Could not extract JSON from ${log_file}" >&2
  fi

  if [[ "$ACTION" == "all" && "$SAVE_INTERMEDIATE" == "0" ]]; then
    PURGE_LOGS+=("$log_file")
  fi
}

declare -a CMD_ARRAY=()

build_command() {
  local target="$1"
  CMD_ARRAY=()
  case "$PROTOCOL:$target" in
    dh:normal)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/DH/dh_key_exchange.py" "--mode" "demo" "--log-dir" "$LOG_DIR")
      ;;
    dh:attack)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/DH/dh_attack.py" "--run" "mitm_demo" "--mode" "$MODE" "--log-dir" "$LOG_DIR")
      ;;
    dh:defense_signed_dh)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/DH/dh_defense.py" "--demo" "signed_dh" "--log-dir" "$LOG_DIR")
      ;;
    dh:defense_key_confirmation)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/DH/dh_defense.py" "--demo" "key_confirmation" "--log-dir" "$LOG_DIR")
      ;;
    dh:defense_pfs_signed)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/DH/dh_defense.py" "--demo" "pfs_signed" "--log-dir" "$LOG_DIR")
      ;;
    rsa:normal)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/RSA/rsa_key_exchange.py" "--mode" "demo" "--log-dir" "$LOG_DIR")
      ;;
    rsa:attack)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/RSA/rsa_attack.py" "--run" "timing_demo" "--samples" "$SAMPLES" "--log-dir" "$LOG_DIR")
      ;;
    rsa:defense_blinding)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/RSA/rsa_defense.py" "--demo" "blinding" "--samples" "$SAMPLES" "--log-dir" "$LOG_DIR")
      ;;
    rsa:defense_constant_time)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/RSA/rsa_defense.py" "--demo" "constant_time" "--samples" "$SAMPLES" "--jitter" "$JITTER" "--log-dir" "$LOG_DIR")
      ;;
    rsa:defense_hardened)
      CMD_ARRAY=("$PYTHON_CMD" "-u" "$BASE_DIR/RSA/rsa_defense.py" "--demo" "hardened_oaep" "--log-dir" "$LOG_DIR")
      ;;
    *)
      CMD_ARRAY=()
      ;;
  esac
}

run_with_trials() {
  local target="$1"
  local tag="$2"
  local description="$3"
  build_command "$target"
  if [[ ${#CMD_ARRAY[@]} -eq 0 ]]; then
    echo "[ERROR] Unsupported target '${target}' for protocol '${PROTOCOL}'" >&2
    return 1
  fi
  if [[ "$ACTION" == "all" && "$SAVE_INTERMEDIATE" == "0" ]]; then
    TOTAL_STEPS=$((TOTAL_STEPS + TRIALS))
  fi
  local trial
  for ((trial = 1; trial <= TRIALS; trial++)); do
    CURRENT_TRIAL=$trial
    TOTAL_TRIALS=$TRIALS
    local suffix=""
    local trial_desc="$description"
    if (( TRIALS > 1 )); then
      suffix="_t${trial}"
      trial_desc="${description} (trial ${trial}/${TRIALS})"
    fi
    if [[ "$ACTION" == "all" && "$SAVE_INTERMEDIATE" == "0" ]]; then
      printf "[Progress %d/%d] %s\n" "$((CURRENT_STEP + 1))" "$TOTAL_STEPS" "${tag}${suffix}" >&2
    fi
    if ! run_step "${tag}${suffix}" "$trial_desc" "${CMD_ARRAY[@]}"; then
      return 1
    fi
    if [[ "$ACTION" == "all" && "$SAVE_INTERMEDIATE" == "0" ]]; then
      CURRENT_STEP=$((CURRENT_STEP + 1))
    fi
  done
}

determine_defaults() {
  if [[ -z "$ATTACK_TYPE" ]]; then
    if [[ "$PROTOCOL" == "dh" ]]; then
      ATTACK_TYPE="mitm"
    else
      ATTACK_TYPE="timing"
    fi
  fi
}

determine_defaults

case "$ACTION" in
  normal)
    run_with_trials "normal" "normal" "Running ${PROTOCOL^^} normal exchange" || OVERALL_STATUS=1
    ;;
  attack)
    if [[ "$ATTACK_TYPE" != "mitm" && "$ATTACK_TYPE" != "timing" ]]; then
      echo "[ERROR] Unsupported attack type: $ATTACK_TYPE" >&2
      exit 1
    fi
    run_with_trials "attack" "attack_${ATTACK_TYPE}" "Running ${PROTOCOL^^} attack (${ATTACK_TYPE})" || OVERALL_STATUS=1
    ;;
  defense)
    if [[ "$PROTOCOL" == "dh" ]]; then
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "signed_dh" ]]; then
        run_with_trials "defense_signed_dh" "defense_signed_dh" "Running DH defense (signed DH)" || OVERALL_STATUS=1
      fi
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "key_confirmation" ]]; then
        run_with_trials "defense_key_confirmation" "defense_key_confirmation" "Running DH defense (key confirmation)" || OVERALL_STATUS=1
      fi
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "pfs_signed" ]]; then
        run_with_trials "defense_pfs_signed" "defense_pfs_signed" "Running DH defense (PFS signed ephemeral)" || OVERALL_STATUS=1
      fi
    else
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "blinding" ]]; then
        run_with_trials "defense_blinding" "defense_blinding" "Running RSA defense (blinding)" || OVERALL_STATUS=1
      fi
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "constant_time" ]]; then
        run_with_trials "defense_constant_time" "defense_constant_time" "Running RSA defense (constant time)" || OVERALL_STATUS=1
      fi
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "hardened_oaep" ]]; then
        run_with_trials "defense_hardened" "defense_hardened" "Running RSA defense (hardened OAEP)" || OVERALL_STATUS=1
      fi
    fi
    ;;
  all)
    run_with_trials "normal" "normal" "Running ${PROTOCOL^^} normal exchange" || OVERALL_STATUS=1
    run_with_trials "attack" "attack_${ATTACK_TYPE}" "Running ${PROTOCOL^^} attack (${ATTACK_TYPE})" || OVERALL_STATUS=1
    if [[ "$PROTOCOL" == "dh" ]]; then
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "signed_dh" ]]; then
        run_with_trials "defense_signed_dh" "defense_signed_dh" "Running DH defense (signed DH)" || OVERALL_STATUS=1
      fi
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "key_confirmation" ]]; then
        run_with_trials "defense_key_confirmation" "defense_key_confirmation" "Running DH defense (key confirmation)" || OVERALL_STATUS=1
      fi
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "pfs_signed" ]]; then
        run_with_trials "defense_pfs_signed" "defense_pfs_signed" "Running DH defense (PFS signed ephemeral)" || OVERALL_STATUS=1
      fi
    else
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "blinding" ]]; then
        run_with_trials "defense_blinding" "defense_blinding" "Running RSA defense (blinding)" || OVERALL_STATUS=1
      fi
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "constant_time" ]]; then
        run_with_trials "defense_constant_time" "defense_constant_time" "Running RSA defense (constant time)" || OVERALL_STATUS=1
      fi
      if [[ -z "$DEFENSE_TYPE" || "$DEFENSE_TYPE" == "hardened_oaep" ]]; then
        run_with_trials "defense_hardened" "defense_hardened" "Running RSA defense (hardened OAEP)" || OVERALL_STATUS=1
      fi
    fi
    ;;
  *)
    echo "[ERROR] Unknown action: $ACTION" >&2
    exit 1
    ;;
esac

if [[ ${#COLLECTED_JSONS[@]} -gt 0 ]]; then
  if [[ "$SAVE_INTERMEDIATE" == "1" ]]; then
    echo "[INFO] JSON artifacts saved:"
    for artifact in "${COLLECTED_JSONS[@]}"; do
      echo " - ${artifact}"
    done
  else
    echo "[INFO] Intermediate artifacts not retained (--save-intermediate=0)."
  fi
  echo "[INFO] Aggregating performance metrics..."
  metrics_args=("$BASE_DIR/analysis/metrics.py" "--protocol" "$PROTOCOL" "--trials" "$TRIALS")
  metrics_list_file=""
  if metrics_list_file=$(mktemp 2>/dev/null); then
    :
  else
    metrics_list_file="$LOG_DIR/.metrics_list_${PROTOCOL}_$$.txt"
    : >"$metrics_list_file"
  fi
  if [[ ${#COLLECTED_JSONS[@]} -gt 0 ]]; then
    for artifact in "${COLLECTED_JSONS[@]}"; do
      "$PYTHON_CMD" - <<'PY' "$artifact" "$metrics_list_file"
import os
import sys

path = os.path.abspath(sys.argv[1])
with open(sys.argv[2], 'a', encoding='utf-8') as handle:
    handle.write(path + '\n')
PY
    done
  else
    : >"$metrics_list_file"
  fi
  metrics_args+=("--list-file" "$metrics_list_file")
  if [[ "$ACTION" == "all" ]]; then
    summary_ts="$(date +%Y%m%d_%H%M%S)"
    summary_file="${LOG_DIR}/ALL_SUMMARY_${PROTOCOL^^}_${summary_ts}_$$.json"
    rm -f "${LOG_DIR}/ALL_SUMMARY_${PROTOCOL^^}_"*.json 2>/dev/null || true
    metrics_args+=("--output" "$summary_file")
  fi
  "$PYTHON_CMD" "${metrics_args[@]}"
  metrics_status=$?
  rm -f "$metrics_list_file"
  if [[ $metrics_status -ne 0 ]]; then
    echo "[ERROR] Metrics aggregation failed (exit $metrics_status)." >&2
    rm -f "$metrics_list_file"
    exit $metrics_status
  fi
  if [[ "$ACTION" == "all" ]]; then
    if [[ -f "$summary_file" ]]; then
      echo "[INFO] All-mode summary saved to ${summary_file}"
      csv_file="${summary_file%.json}.csv"
      "$PYTHON_CMD" "$BASE_DIR/analysis/csv_export.py" "$summary_file" > "$csv_file"
      echo "[INFO] Metrics CSV saved to ${csv_file}"
    else
      echo "[WARNING] Summary file not found; skip CSV export." >&2
    fi
  fi
  if [[ "$ACTION" == "all" && "$SAVE_INTERMEDIATE" == "0" ]]; then
    for f in "${PURGE_JSONS[@]}"; do
      rm -f "$f"
    done
    for f in "${PURGE_LOGS[@]}"; do
      rm -f "$f"
    done
  fi
else
  echo "[WARNING] No JSON artifacts collected."
fi

echo "[INFO] Demo script completed."
exit $OVERALL_STATUS
