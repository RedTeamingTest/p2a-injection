"""Assemble the generation-level cross-model table for Comment 1.1/2.3.

Reads the per-model generation-level result JSONs (same harness, 260 scenarios)
and prints a per-category ASR table plus overall ASR and JSON compliance, ready
to transcribe into the manuscript. The two commercial models are compared with
the open-source LLaMA-3 anchor evaluated identically; the four open-source
models' end-to-end ASR remains in the manuscript's Table 6.
"""
import json, os

HERE = os.path.dirname(__file__)
RES = os.path.join(HERE, "results")
CATS = ["U", "RD", "RI", "IL", "OB"]

# (slug, label, kind)
MODELS = [
    ("llama3_latest",     "LLaMA-3 (8B, open)",   "open"),
    ("gpt-4o-mini",       "GPT-4o-mini (comm.)",  "comm"),
    ("claude-haiku-4-5",  "Claude-Haiku-4.5 (comm.)", "comm"),
]


def load(slug):
    p = os.path.join(RES, f"commercial_{slug}.json")
    return json.load(open(p)) if os.path.exists(p) else None


print(f"{'Model':26} " + " ".join(f"{c:>6}" for c in CATS) + f" {'Overall':>8} {'JSON':>6} {'n':>5}")
print("-" * 80)
for slug, label, kind in MODELS:
    d = load(slug)
    if not d:
        print(f"{label:26} [missing]")
        continue
    pc = d["per_category_asr"]
    cells = " ".join(f"{pc.get(c, {}).get('asr', float('nan')):>6.1f}" for c in CATS)
    print(f"{label:26} {cells} {d['overall_asr_pct']:>8.1f} {d['json_compliance_pct']:>6.1f} {d['n']:>5}")

print("\nPer-system ASR:")
for slug, label, kind in MODELS:
    d = load(slug)
    if not d:
        continue
    ps = d["per_system_asr"]
    print(f"  {label:26} " + " ".join(f"{k[:4]}={v['asr']:.0f}" for k, v in ps.items()))
