"""Assemble the D5 guard-capacity trade-off from the R21/R22 result JSONs.

Orders the guards by capacity, discards the 32B artifact runs (all guard_error
because the model could not be loaded), and reports:
  * adaptive-attack bypass rate per condition (R21);
  * the same split into two failure modes:
      A = semantic-reasoning test  (malicious effect hidden in the body / a
          cross-user id; the plain query is neutral, so ALLOW is a guard miss),
      B = consistency != authorization (the plain query itself names the
          unauthorized target, so query==call is textually consistent and the
          Phase-1 whitelist, not the guard, is what must stop it);
  * false-positive rate and mean guard latency (R22).
"""
import json, glob, os

HERE = os.path.dirname(__file__)
RES = os.path.join(HERE, "results")

# capacity-ordered; (slug, label, params)
GUARDS = [
    ("llama3_latest",        "LLaMA-3",        "8B"),
    ("qwen2.5_latest",       "Qwen2.5",        "7B"),
    ("qwen2.5-coder_14b",    "Qwen2.5-Coder",  "14B"),
    ("deepseek-v4-flash",    "DeepSeek-V4",    "cloud"),
]

# case index -> failure-mode group (from the CASES order in r21_adaptive_guard.py)
GROUP = {0:"A",1:"A",2:"B",3:"B",4:"A",5:"B",6:"A",7:"B",8:"A",9:"A"}
CONDS = ["plain", "align", "inject", "authority"]


def load(slug, kind):
    p = os.path.join(RES, f"{kind}_{slug}.json")
    return json.load(open(p)) if os.path.exists(p) else None


print("=" * 84)
print("R2.1  Adaptive-attack bypass rate (guard returns ALLOW on an unauthorized call)")
print("=" * 84)
print(f"{'guard':22} {'plain':>8} {'align':>8} {'inject':>8} {'authority':>10}   note")
for slug, label, params in GUARDS:
    d = load(slug, "R21_adaptive_guard")
    if not d:
        continue
    # detect artifact runs: every phase-2 reason is a guard_error
    reasons = [c.get("reason", "") for cs in d["cases"] for c in cs["conditions"].values()]
    artifact = reasons and all("guard_error" in r for r in reasons)
    pc = d["per_condition"]
    cells = " ".join(f"{pc[c]['bypass_rate_pct']:>7.0f}%" for c in CONDS[:3]) + f" {pc['authority']['bypass_rate_pct']:>9.0f}%"
    note = "  <-- DISCARD (model could not load; all guard_error)" if artifact else ""
    print(f"{label+' '+params:22} {cells}{note}")

print()
print("Split by failure mode (valid guards only), bypass count / n:")
print(f"{'guard':22} | {'A: reasoning test (n/cond)':>26} | {'B: consistency!=authz':>22}")
for slug, label, params in GUARDS:
    d = load(slug, "R21_adaptive_guard")
    if not d:
        continue
    reasons = [c.get("reason", "") for cs in d["cases"] for c in cs["conditions"].values()]
    if reasons and all("guard_error" in r for r in reasons):
        continue
    # per group, count bypass (ALLOW) across the 4 conditions
    a_by = a_n = b_by = b_n = 0
    for i, cs in enumerate(d["cases"]):
        g = GROUP[i]
        for c in CONDS:
            allow = cs["conditions"][c]["action"] == "ALLOW"
            if g == "A":
                a_n += 1; a_by += int(allow)
            else:
                b_n += 1; b_by += int(allow)
    print(f"{label+' '+params:22} | {a_by:>10}/{a_n:<3} = {100*a_by/a_n:>5.1f}%      | {b_by:>6}/{b_n:<3} = {100*b_by/b_n:>5.1f}%")

print()
print("=" * 84)
print("R2.2  False-positive rate on 43 in-policy legitimate requests, and guard latency")
print("=" * 84)
print(f"{'guard':22} {'FP/n':>10} {'FP rate':>9} {'mean latency':>14}")
for slug, label, params in GUARDS:
    d = load(slug, "R22_false_positive")
    if not d:
        continue
    reasons = [r.get("reason", "") for r in d["results"]]
    artifact = reasons and all(("guard_error" in (x or "")) for r in d["results"] for x in [r.get("reason")] if r["action"] == "BLOCK") and d["false_positives"] == len(d["results"])
    note = "   <-- DISCARD (all guard_error)" if artifact else ""
    print(f"{label+' '+params:22} {str(d['false_positives'])+'/'+str(d['n_benign']):>10} {d['false_positive_rate_pct']:>8.1f}% {d['mean_guard_latency_ms']:>12.0f}ms{note}")
