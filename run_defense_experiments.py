"""
Defense Experiments Runner (RQ3)
=================================
Runs all 52 attacks × 5 systems × 6 defenses (none, D1-D5)
against the real backends via p2a_demo.py Flask API.

Uses llama3:latest as primary model (confirmed highest baseline ASR).
Results saved to: results/defense/{defense}/{system}_{model}.json

Usage:
  python run_defense_experiments.py --defense all --system all --model llama3:latest
  python run_defense_experiments.py --defense D3 --system portal
  python run_defense_experiments.py --defense all --system all --model all
"""

import json, math, os, sys, time
from pathlib import Path
import requests

# ── Attack ID imports ─────────────────────────────────────
from attacks import ATTACK_IDS as PORTAL_IDS
from ecommerce_attacks import EC_ATTACK_IDS
from gitea_attacks import GITEA_ATTACK_IDS
from ha_attacks import HA_ATTACK_IDS
from directus_attacks import DIRECTUS_ATTACK_IDS

# ── Config ────────────────────────────────────────────────
DEMO_URL = os.environ.get("DEMO_URL", "http://localhost:8888")
RUN_URL  = f"{DEMO_URL}/api/run"
TIMEOUT  = 300
PAUSE    = 0.5

DEFENSES = ["none", "D1", "D2", "D3", "D4", "D5"]

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

RESULTS_BASE = Path(__file__).parent / "results" / "defense"


def do_trial(atk_id, testbed, model, defense):
    payload = {
        "testbed": testbed,
        "atk_id": atk_id,
        "model": model,
        "defense": defense,
    }
    try:
        r = requests.post(RUN_URL, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json()
        return {
            "success": bool(d.get("success", False)),
            "t_total": d.get("t_total", 0),
            "defense": d.get("defense", defense),
            "defense_action": d.get("defense_action", ""),
            "defense_stage": d.get("defense_stage", ""),
            "defense_reason": d.get("defense_reason", ""),
            "defense_latency_ms": d.get("defense_latency_ms", 0),
            "generated_call": d.get("generated_call"),
            "status_code": d.get("status_code"),
            "api_response_snippet": str(d.get("api_response", ""))[:300],
            "followup_call": d.get("followup_call"),
            "llm_answer_snippet": str(d.get("llm_answer", ""))[:300],
            "category": d.get("category", ""),
            "error": d.get("error"),
        }
    except Exception as e:
        return {"success": False, "t_total": 0, "error": str(e)}


def run_defense_experiment(system_name, testbed, attack_ids, model, defense, out_dir):
    """Run all attacks for one (system, model, defense) combination."""
    out_dir.mkdir(parents=True, exist_ok=True)
    total = len(attack_ids)
    t0 = time.time()
    results = {}
    summary = {}

    print(f"\n{'='*70}")
    print(f"  Defense: {defense}  |  System: {system_name}  |  Model: {model}")
    print(f"  Attacks: {total}")
    print(f"{'='*70}")

    for idx, atk_id in enumerate(attack_ids, 1):
        elapsed = time.time() - t0
        eta = elapsed / idx * (total - idx) if idx > 0 else 0

        result = do_trial(atk_id, testbed, model, defense)
        results[atk_id] = result

        badge = "✓" if result["success"] else "✗"
        blocked = " [BLOCKED]" if result.get("defense_action") == "BLOCK" else ""
        print(
            f"  {badge} {atk_id:<12} "
            f"t={result.get('t_total',0):.1f}s{blocked}  "
            f"({idx}/{total}  ETA {eta/60:.1f}min)",
            flush=True,
        )
        time.sleep(PAUSE)

    # Aggregate
    successes = sum(1 for r in results.values() if r["success"])
    blocks = sum(1 for r in results.values() if r.get("defense_action") == "BLOCK")
    asr = round(successes / total * 100, 1)
    block_rate = round(blocks / total * 100, 1)

    # Per-category breakdown
    cat_stats = {}
    for atk_id, r in results.items():
        cat = r.get("category", "Unknown")
        if cat not in cat_stats:
            cat_stats[cat] = {"n": 0, "success": 0, "blocked": 0}
        cat_stats[cat]["n"] += 1
        if r["success"]:
            cat_stats[cat]["success"] += 1
        if r.get("defense_action") == "BLOCK":
            cat_stats[cat]["blocked"] += 1

    output = {
        "defense": defense,
        "system": system_name,
        "testbed": testbed,
        "model": model,
        "n_attacks": total,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_time_sec": round(time.time() - t0, 1),
        "asr": asr,
        "block_rate": block_rate,
        "successes": successes,
        "blocks": blocks,
        "category_stats": cat_stats,
        "raw_results": results,
    }

    fname = f"{system_name}_{model.replace(':', '_').replace('/', '_')}.json"
    out_path = out_dir / fname
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False, default=str))

    print(f"\n  ASR = {asr}% ({successes}/{total})  |  Blocked = {block_rate}% ({blocks}/{total})")
    print(f"  Category Breakdown:")
    for cat, cs in sorted(cat_stats.items()):
        cat_asr = round(cs["success"]/cs["n"]*100, 1) if cs["n"] else 0
        print(f"    {cat:<25} ASR={cat_asr:>5}%  blocked={cs['blocked']:>2}/{cs['n']}")
    print(f"  Saved => {out_path}")

    return output


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Defense Experiments (RQ3)")
    ap.add_argument("--defense", default="all",
                    help="Defense name (D1-D5, none) or 'all'")
    ap.add_argument("--system", choices=list(SYSTEMS.keys()) + ["all"], default="all")
    ap.add_argument("--model", default="llama3:latest",
                    help="Model name or 'all'")
    args = ap.parse_args()

    # Verify demo is running
    try:
        r = requests.get(f"{DEMO_URL}/api/backend_status", timeout=10)
        status = r.json()
        if not status.get("use_real_backend"):
            print("ERROR: Demo not in real backend mode!")
            sys.exit(1)
        print("Backends OK:")
        for name, info in status.get("backends", {}).items():
            ok = "✓" if info.get("ok") else "✗"
            print(f"  {ok} {name}")
    except Exception as e:
        print(f"ERROR: Cannot reach demo at {DEMO_URL}: {e}")
        sys.exit(1)

    # Determine what to run
    defenses = DEFENSES if args.defense == "all" else [args.defense]
    systems_to_run = list(SYSTEMS.keys()) if args.system == "all" else [args.system]
    models_to_run = ALL_MODELS if args.model == "all" else [args.model]

    t_start = time.time()
    grand_results = []

    for model in models_to_run:
        for defense in defenses:
            for sys_name in systems_to_run:
                testbed, attack_ids = SYSTEMS[sys_name]
                result = run_defense_experiment(
                    system_name=sys_name,
                    testbed=testbed,
                    attack_ids=attack_ids,
                    model=model,
                    defense=defense,
                    out_dir=RESULTS_BASE / defense,
                )
                grand_results.append(result)

    # Grand summary
    total_min = (time.time() - t_start) / 60
    print(f"\n{'='*70}")
    print(f"  ALL DEFENSE EXPERIMENTS COMPLETED in {total_min:.1f} minutes")
    print(f"{'='*70}")
    print(f"\n  {'Defense':<10} {'System':<15} {'Model':<22} {'ASR':>6} {'Blocked':>8}")
    print(f"  {'─'*65}")
    for r in grand_results:
        print(f"  {r['defense']:<10} {r['system']:<15} {r['model']:<22} "
              f"{r['asr']:>5}% {r['block_rate']:>6}%")

    # Save grand summary
    summary_path = RESULTS_BASE / "grand_summary.json"
    summary_path.write_text(json.dumps(grand_results, indent=2, ensure_ascii=False, default=str))
    print(f"\n  Grand summary => {summary_path}")


if __name__ == "__main__":
    main()
