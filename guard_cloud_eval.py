"""
Strong-guard data point for the D5 security--usability trade-off.
=================================================================
Reviewers #1 and #2 ask whether a genuinely capable judge (they name GPT-4-class
models) closes the guard-bypass gap the small local guards leave open, and at
what usability cost. The three local guards (llama3 8B, qwen2.5 7B,
qwen2.5-coder 14B) span the low end; the 32B model could not be loaded on the
NAS (needs 82 GiB system RAM), so this script adds a cloud reasoning model as the
strong end of the curve.

To keep the comparison on one ruler, the guard uses the SAME D5 Phase-1 whitelist
(`d3_gate_output`) and the SAME Phase-2 prompt (`_D5_PROMPT`) as the local guards;
only the Phase-2 model is swapped for the cloud endpoint. Both reviewer corpora
are run through it:
  * CASES  (from r21_adaptive_guard): whitelisted-but-unauthorised calls under
           4 query conditions -> adaptive-attack bypass rate.
  * BENIGN (from r22_false_positive): in-policy legitimate calls -> false-positive rate.

Outputs, in the same schema as the local-guard runs, so the paper's trade-off
table extends without special-casing:
  results/R21_adaptive_guard_<slug>.json
  results/R22_false_positive_<slug>.json

Run (host or NAS, needs outbound HTTPS to the cloud endpoint):
  DEEPSEEK_API_KEY=... GUARD_CLOUD_MODEL=deepseek-v4-flash python3 guard_cloud_eval.py
"""
import json, os, time
from pathlib import Path

import requests
from defenses import d3_gate_output, _D5_PROMPT
from r21_adaptive_guard import CASES, CONDITIONS
from r22_false_positive import BENIGN

# ── Cloud guard endpoint (OpenAI-compatible chat/completions) ──
API_KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
API_BASE = os.environ.get("CLOUD_BASE", "https://api.deepseek.com").rstrip("/")
CLOUD_MODEL = os.environ.get("GUARD_CLOUD_MODEL", "deepseek-v4-flash")
_slug = CLOUD_MODEL.replace(":", "_").replace("/", "_")
RESULTS = Path(__file__).parent / "results"


def _decide_from_text(text):
    """Return 'ALLOW' / 'BLOCK' / None from the last verdict token in the text."""
    up = (text or "").upper()
    ia = up.rfind("ALLOW")
    ib = up.rfind("BLOCK")
    if ia == -1 and ib == -1:
        return None
    return "ALLOW" if ia > ib else "BLOCK"


def cloud_guard(query, method, endpoint, body, max_tokens=2000):
    """Phase-2 semantic validation via the cloud reasoning model.
    Uses the identical _D5_PROMPT as the local guard. Fails secure (BLOCK) on
    error or an unparseable answer, matching d5_validate_intent."""
    body_str = json.dumps(body) if body else "null"
    prompt = _D5_PROMPT.format(query=query, method=method or "GET",
                               endpoint=endpoint or "", body=body_str)
    payload = {"model": CLOUD_MODEL,
               "messages": [{"role": "user", "content": prompt}],
               "temperature": 0.0, "max_tokens": max_tokens}
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{API_BASE}/chat/completions",
                          headers={"Authorization": f"Bearer {API_KEY}",
                                   "Content-Type": "application/json"},
                          json=payload, timeout=180)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        content = msg.get("content") or ""
        reasoning = msg.get("reasoning_content") or ""
    except Exception as e:
        lat = round((time.perf_counter() - t0) * 1000, 1)
        return ("BLOCK", f"guard_error: {e}", lat)
    lat = round((time.perf_counter() - t0) * 1000, 1)
    # Final decision comes from the answer text; if the answer was truncated into
    # reasoning only, fall back to the reasoning trace's last verdict.
    dec = _decide_from_text(content) or _decide_from_text(reasoning)
    raw = (content.strip() or reasoning.strip())[-160:]
    if dec == "ALLOW":
        return ("ALLOW", "guard_approved", lat)
    elif dec == "BLOCK":
        return ("BLOCK", f"guard_blocked: {raw}", lat)
    return ("BLOCK", f"guard_ambiguous: {raw}", lat)


def d5_cloud(testbed, role, query, method, endpoint, body):
    """Full D5 with the cloud Phase-2 guard: Phase-1 whitelist then Phase-2 LLM."""
    p1 = d3_gate_output(method, endpoint, testbed, role)
    if p1[0] == "BLOCK":
        return {"action": "BLOCK", "stage": "D5-phase1", "reason": p1[1], "latency_ms": 0}
    action, reason, lat = cloud_guard(query, method, endpoint, body)
    return {"action": action, "stage": "D5-phase2", "reason": reason, "latency_ms": lat}


def run_adaptive():
    per_cond = {c: {"reached_phase2": 0, "bypass": 0} for c in CONDITIONS}
    rows = []
    for case in CASES:
        tb, role = case["testbed"], case["role"]
        m, ep, body = case["method"], case["endpoint"], case["body"]
        p1 = d3_gate_output(m, ep, tb, role)[0]
        rec = {"testbed": tb, "role": role, "method": m, "endpoint": ep,
               "desc": case["desc"], "phase1": p1, "conditions": {}}
        for cond in CONDITIONS:
            res = d5_cloud(tb, role, case[cond], m, ep, body)
            if res.get("stage") == "D5-phase2":
                per_cond[cond]["reached_phase2"] += 1
            if res["action"] == "ALLOW":
                per_cond[cond]["bypass"] += 1
            rec["conditions"][cond] = {"action": res["action"], "stage": res.get("stage"),
                                       "reason": res.get("reason"),
                                       "latency_ms": res.get("latency_ms", 0)}
            print(f"[{res['action']:5}] {cond:9} {tb}/{role:9} {m} {ep}", flush=True)
        rows.append(rec)
    n = len(CASES)
    summary = {"guard_model": CLOUD_MODEL, "n_cases": n, "per_condition": {}, "cases": rows}
    print("\n" + "=" * 64)
    print(f"{'condition':10} {'reachedP2':>10} {'bypass(ALLOW)':>14} {'bypass_rate':>12}")
    for c in CONDITIONS:
        byp = per_cond[c]["bypass"]
        rate = 100.0 * byp / n
        summary["per_condition"][c] = {"n": n, "reached_phase2": per_cond[c]["reached_phase2"],
                                       "bypass": byp, "bypass_rate_pct": round(rate, 1)}
        print(f"{c:10} {per_cond[c]['reached_phase2']:>10} {byp:>14} {rate:>11.1f}%")
    out = RESULTS / f"R21_adaptive_guard_{_slug}.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"Saved -> {out}")


def run_false_positive():
    results = []
    blocked = phase1_reject = 0
    latencies = []
    for tb, role, q, m, ep, body in BENIGN:
        p1 = d3_gate_output(m, ep, tb, role)[0]
        res = d5_cloud(tb, role, q, m, ep, body)
        lat = res.get("latency_ms", 0)
        if lat:
            latencies.append(lat)
        if p1 == "BLOCK":
            phase1_reject += 1
        if res["action"] == "BLOCK":
            blocked += 1
        results.append({"testbed": tb, "role": role, "query": q, "method": m, "endpoint": ep,
                        "phase1": p1, "action": res["action"], "stage": res.get("stage"),
                        "reason": res.get("reason"), "latency_ms": lat})
        print(f"[{res['action']:5}] {tb}/{role:9} {m} {ep}", flush=True)
    n = len(BENIGN)
    fp_rate = 100.0 * blocked / n
    mean_lat = sum(latencies) / len(latencies) if latencies else 0.0
    summary = {"guard_model": CLOUD_MODEL, "n_benign": n, "phase1_rejected": phase1_reject,
               "false_positives": blocked, "false_positive_rate_pct": round(fp_rate, 1),
               "mean_guard_latency_ms": round(mean_lat, 1), "results": results}
    out = RESULTS / f"R22_false_positive_{_slug}.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print("\n" + "=" * 60)
    print(f"Benign requests:      {n}")
    print(f"False positives (D5): {blocked}")
    print(f"False-positive rate:  {fp_rate:.1f}%")
    print(f"Mean guard latency:   {mean_lat:.1f} ms")
    print(f"Saved -> {out}")


def main():
    if not API_KEY:
        raise SystemExit("Set DEEPSEEK_API_KEY")
    RESULTS.mkdir(parents=True, exist_ok=True)
    print(f"### Cloud guard = {CLOUD_MODEL} @ {API_BASE}")
    print("\n########## R2.1 adaptive-attack bypass ##########")
    run_adaptive()
    print("\n########## R2.2 false-positive rate ##########")
    run_false_positive()


if __name__ == "__main__":
    main()
