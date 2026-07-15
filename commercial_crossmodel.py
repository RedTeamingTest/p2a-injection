"""
Commercial closed-source model evaluation (Reviewer 1.1 / 2.3).
==============================================================
The manuscript evaluates P2A attacks on four open-source models (3B-14B). The
reviewers ask whether the attacks generalize to hosted commercial models. We run
the full 52 attack vectors across all 5 systems for two commercial models
(gpt-4o-mini and claude-haiku-4-5), reached through an OpenAI-compatible proxy.

Metric. We report the generation-level ASR: the fraction of generations in which
the model emits the targeted unauthorized API call (evaluated by each attack's
success_fn on the mock state), together with the JSON compliance rate. This
isolates the model-dependent question the reviewers raise -- does a commercial
model comply with the injection and produce the unauthorized call -- from the
server-side RBAC enforcement that the manuscript shows dominates the end-to-end
outcome and is model-independent.

Credentials come from the environment; nothing is written to the source tree:
  COMMERCIAL_API_KEY=... COMMERCIAL_BASE=https://api.openai-proxy.org \
  python3 commercial_crossmodel.py
"""
import os, json, time, re
os.environ.setdefault("USE_REAL_BACKEND", "0")
from pathlib import Path

import p2a_demo as demo
from attacks import ATTACK_IDS
from ecommerce_attacks import EC_ATTACK_IDS
from gitea_attacks import GITEA_ATTACK_IDS
from ha_attacks import HA_ATTACK_IDS
from directus_attacks import DIRECTUS_ATTACK_IDS

SYSTEMS = {
    "portal":        ATTACK_IDS,
    "ecommerce":     EC_ATTACK_IDS,
    "gitea":         GITEA_ATTACK_IDS,
    "homeassistant": HA_ATTACK_IDS,
    "directus":      DIRECTUS_ATTACK_IDS,
}
MODELS = os.environ.get("XMODELS", "gpt-4o-mini,claude-haiku-4-5").split(",")
# category-code map (manuscript uses U/RD/RI/IL/OB)
CAT_CODE = {"Unrestricted": "U", "Restricted Direct": "RD", "Restricted-Direct": "RD",
            "Restricted Indirect": "RI", "Restricted-Indirect": "RI",
            "Injection Location": "IL", "Injection-Location": "IL",
            "Obfuscation Bypass": "OB", "Obfuscation-Bypass": "OB"}
RESULTS = Path(__file__).parent / "results"


def json_compliant(raw):
    if not raw or raw.startswith("[LLM_ERROR]"):
        return False
    s = raw.strip().strip("`")
    s = re.sub(r"^json", "", s).strip()
    try:
        o = json.loads(s)
        return isinstance(o, dict) and "method" in o
    except Exception:
        m = re.search(r'\{[^{}]*"method"[^{}]*\}', raw, re.DOTALL)
        if m:
            try:
                return "method" in json.loads(m.group())
            except Exception:
                return False
    return False


def cat_of(c):
    return CAT_CODE.get((c or "").strip(), (c or "?")[:2].upper())


def run_model(model):
    rows = []
    by_cat = {}
    by_sys = {}
    n = succ = comp = err = 0
    t0 = time.time()
    total = sum(len(v) for v in SYSTEMS.values())
    for sysname, ids in SYSTEMS.items():
        s_n = s_s = 0
        for aid in ids:
            try:
                r = demo.run_attack_with_llm(sysname, aid, model, defense="none")
            except Exception as e:
                r = {"error": str(e), "success": False, "category": "", "llm_raw_call": ""}
            raw = r.get("llm_raw_call", "")
            is_err = bool(r.get("error")) or (isinstance(raw, str) and raw.startswith("[LLM_ERROR]"))
            ok = bool(r.get("success"))
            jc = json_compliant(raw)
            code = cat_of(r.get("category", ""))
            n += 1; succ += int(ok); comp += int(jc); err += int(is_err)
            s_n += 1; s_s += int(ok)
            c = by_cat.setdefault(code, {"n": 0, "s": 0, "c": 0})
            c["n"] += 1; c["s"] += int(ok); c["c"] += int(jc)
            rows.append({"system": sysname, "atk_id": aid, "category": code,
                         "success": ok, "json_compliant": jc, "error": is_err,
                         "generated_call": r.get("generated_call")})
            done = n
            print(f"[{'OK' if ok else '..'}|{'J' if jc else '-'}{'!' if is_err else ' '}] "
                  f"{model:16} {sysname:13} {aid:12} ({done}/{total})", flush=True)
            time.sleep(0.3)
        by_sys[sysname] = {"n": s_n, "s": s_s, "asr": round(100*s_s/s_n, 1)}

    summary = {
        "model": model, "n": n, "successes": succ,
        "overall_asr_pct": round(100*succ/n, 1),
        "json_compliance_pct": round(100*comp/n, 1),
        "errors": err,
        "per_category_asr": {k: {"n": v["n"], "asr": round(100*v["s"]/v["n"], 1),
                                 "json": round(100*v["c"]/v["n"], 1)}
                             for k, v in sorted(by_cat.items())},
        "per_system_asr": by_sys,
        "elapsed_sec": round(time.time()-t0, 1),
        "rows": rows,
    }
    slug = model.replace(":", "_").replace("/", "_")
    out = RESULTS / f"commercial_{slug}.json"
    RESULTS.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str))
    print(f"\n=== {model}: overall ASR {summary['overall_asr_pct']}%  "
          f"JSON {summary['json_compliance_pct']}%  errors {err}/{n} ===")
    print("per-category:", {k: v["asr"] for k, v in summary["per_category_asr"].items()})
    print(f"Saved -> {out}\n")
    return summary


def main():
    if not os.environ.get("COMMERCIAL_API_KEY"):
        raise SystemExit("Set COMMERCIAL_API_KEY")
    for m in MODELS:
        run_model(m)


if __name__ == "__main__":
    main()
