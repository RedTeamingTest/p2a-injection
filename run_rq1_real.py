"""
RQ1 Real Backend Experiment Runner (v2 - Full 52 attacks)
==========================================================
Runs all 52 attacks per system against real backend systems
via the local p2a_demo.py Flask server (USE_REAL_BACKEND=1).

5 Systems × 52 attacks × 4 models = 1040 unique experiments.

Usage:
  python run_rq1_real.py --system portal --model llama3:latest --n 1
  python run_rq1_real.py --system all --model all --n 1
"""

import json, math, os, sys, time
from pathlib import Path
import requests

# ── Attack ID imports ─────────────────────────────────────────────────────────
from attacks import ATTACK_IDS as PORTAL_IDS
from ecommerce_attacks import EC_ATTACK_IDS
from gitea_attacks import GITEA_ATTACK_IDS
from ha_attacks import HA_ATTACK_IDS
from directus_attacks import DIRECTUS_ATTACK_IDS

# ── Config ────────────────────────────────────────────────────────────────────
DEMO_URL = os.environ.get("DEMO_URL", "http://localhost:8888")
RUN_URL  = f"{DEMO_URL}/api/run"
TIMEOUT  = 300
PAUSE    = 1.0
MODEL    = os.environ.get("OLLAMA_MODEL", "llama3:latest")
N_TRIALS = int(os.environ.get("N_TRIALS", "1"))

# Map system name -> (testbed, attack_ids)
SYSTEMS = {
    "portal":        ("portal",        PORTAL_IDS),
    "ecommerce":     ("ecommerce",     EC_ATTACK_IDS),
    "gitea":         ("gitea",         GITEA_ATTACK_IDS),
    "homeassistant": ("homeassistant", HA_ATTACK_IDS),
    "directus":      ("directus",      DIRECTUS_ATTACK_IDS),
}

ALL_MODELS = [
    "llama3:latest",
    "qwen2.5:latest",
    "ministral-3:latest",
    "qwen2.5-coder:14b",
]

RESULTS_BASE = Path(__file__).parent / "results" / "RQ1"


def wilson_ci(successes, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo = round(max(0.0, center - margin) * 100, 1)
    hi = round(min(1.0, center + margin) * 100, 1)
    return (lo, hi)


def do_trial(atk_id, testbed, model):
    payload = {"testbed": testbed, "atk_id": atk_id, "model": model}
    try:
        r = requests.post(RUN_URL, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json()
        return {
            "success": bool(d.get("success", False)),
            "t_total": d.get("t_total", 0),
            "t_gen": d.get("t_gen", 0),
            "t_exec": d.get("t_exec", 0),
            "t_reflect": d.get("t_reflect", 0),
            "t_ans": d.get("t_ans", 0),
            "generated_call": d.get("generated_call"),
            "status_code": d.get("status_code"),
            "api_response_snippet": str(d.get("api_response", ""))[:500],
            "followup_call": d.get("followup_call"),
            "followup_status": d.get("followup_status"),
            "llm_answer_snippet": str(d.get("llm_answer", ""))[:500],
            "reflection_raw": str(d.get("reflection_raw", ""))[:300],
            "error": d.get("error"),
        }
    except Exception as e:
        return {"success": False, "t_total": 0, "generated_call": None, "error": str(e)}


def run_attacks(system_name, testbed, attack_ids, model, n_trials, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    total = len(attack_ids) * n_trials
    done = 0
    t0 = time.time()
    all_results = {}
    summary = {}

    print(f"\n{'='*70}")
    print(f"  System: {system_name}  |  Testbed: {testbed}  |  Model: {model}")
    print(f"  Attacks: {len(attack_ids)}  |  Trials: {n_trials}  |  Total runs: {total}")
    print(f"{'='*70}\n")

    for atk_id in attack_ids:
        trials = []
        for i in range(n_trials):
            done += 1
            elapsed = time.time() - t0
            eta = elapsed / done * (total - done) if done > 0 else 0
            result = do_trial(atk_id, testbed, model)
            trials.append(result)
            badge = "✓" if result["success"] else "✗"
            print(
                f"  {badge} {atk_id:<12} trial {i+1:>2}/{n_trials}  "
                f"t={result.get('t_total',0):.1f}s  "
                f"({done}/{total}  ETA {eta/60:.1f}min)",
                flush=True,
            )
            time.sleep(PAUSE)

        successes = sum(1 for t in trials if t["success"])
        asr = round(successes / n_trials * 100, 1)
        ci_lo, ci_hi = wilson_ci(successes, n_trials)
        summary[atk_id] = {"n": n_trials, "successes": successes, "asr": asr, "ci_lo": ci_lo, "ci_hi": ci_hi}
        all_results[atk_id] = trials
        print(f"  >> {atk_id}: ASR = {asr}%  CI = [{ci_lo}, {ci_hi}]\n")

    output = {
        "system": system_name,
        "testbed": testbed,
        "model": model,
        "n_trials": n_trials,
        "n_attacks": len(attack_ids),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_time_sec": round(time.time() - t0, 1),
        "summary": summary,
        "raw_trials": all_results,
    }

    fname = f"rq1_{system_name}_{model.replace(':', '_').replace('/', '_')}.json"
    out_path = out_dir / fname
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False, default=str))
    print(f"  Results saved => {out_path}")

    print(f"\n{'─'*55}")
    print(f"  {'Attack':<12} {'ASR':>6}  {'95% CI':<20} {'Succ':>5}/{n_trials}")
    print(f"{'─'*55}")
    for atk_id in attack_ids:
        s = summary[atk_id]
        print(f"  {atk_id:<12} {s['asr']:>5}%  [{s['ci_lo']:>5}, {s['ci_hi']:>5}]  {s['successes']:>5}/{s['n']}")
    overall_asr = round(sum(s["asr"] for s in summary.values()) / len(summary), 1)
    print(f"{'─'*55}")
    print(f"  {'Overall':<12} {overall_asr:>5}%")
    print()
    return summary


def main():
    import argparse
    ap = argparse.ArgumentParser(description="RQ1 Real Backend Experiments (52 attacks per system)")
    ap.add_argument("--system", choices=list(SYSTEMS.keys()) + ["all"], default="all")
    ap.add_argument("--n", type=int, default=N_TRIALS, help="Trials per attack")
    ap.add_argument("--model", default=MODEL, help="Model name or 'all'")
    args = ap.parse_args()

    # Verify demo is running with real backend
    try:
        r = requests.get(f"{DEMO_URL}/api/backend_status", timeout=10)
        status = r.json()
        if not status.get("use_real_backend"):
            print("ERROR: Demo is NOT running in real backend mode!")
            print("Start with: USE_REAL_BACKEND=1 PORT=8888 python3 p2a_demo.py")
            sys.exit(1)
        print("Backend status:")
        for name, info in status.get("backends", {}).items():
            ok = "✓" if info.get("ok") else "✗"
            print(f"  {ok} {name}: {info.get('url')} (status {info.get('status', 'N/A')})")
    except Exception as e:
        print(f"ERROR: Cannot reach demo at {DEMO_URL}: {e}")
        sys.exit(1)

    # Determine systems and models to run
    systems_to_run = list(SYSTEMS.keys()) if args.system == "all" else [args.system]
    models_to_run = ALL_MODELS if args.model == "all" else [args.model]

    t_start = time.time()

    for model in models_to_run:
        for sys_name in systems_to_run:
            testbed, attack_ids = SYSTEMS[sys_name]
            run_attacks(
                system_name=sys_name,
                testbed=testbed,
                attack_ids=attack_ids,
                model=model,
                n_trials=args.n,
                out_dir=RESULTS_BASE / sys_name,
            )

    total_min = (time.time() - t_start) / 60
    print(f"\n{'='*70}")
    print(f"  ALL EXPERIMENTS COMPLETED in {total_min:.1f} minutes")
    print(f"  Systems: {systems_to_run}")
    print(f"  Models: {models_to_run}")
    print(f"  Results in: {RESULTS_BASE}/")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
