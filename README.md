# P2A: Prompt-to-API-Call Injection Attacks and the D5 Semantic Intent Validator

Research artifact for the JSS 2026 submission *"Prompt-to-API-Call Injection
Attacks"*. It contains the attack-vector generation framework, the end-to-end
attack/defense harness, the five defense strategies (D1–D5), and all result
data used in the manuscript.

> **Scope and intended use.** This is defensive-security research. The attacks
> are executed only against **local, disposable testbed instances** that ship
> with (and are torn down after) the experiments. Do **not** run these payloads
> against systems you do not own or operate. The D5 Semantic Intent Validator is
> the mitigation proposed and evaluated here.

---

## 1. What P2A is

An LLM agent that holds a user's session credentials translates natural-language
requests into REST API calls. A **Prompt-to-API-Call (P2A)** injection makes the
agent emit an *unauthorized* API call under the user's legitimate identity — a
"confused deputy" at the LLM-agent layer. The study builds **52 attack vectors**
in 5 categories (Unrestricted, Restricted-Direct, Restricted-Indirect,
Injection-Location, Obfuscation-Bypass), adapts them to **5 heterogeneous
backends** (Strapi portal, E-Commerce, Gitea, Home Assistant, Directus), yielding
**260 end-to-end scenarios**, and evaluates them on 4 open-source LLMs
(LLaMA-3 8B, Qwen2.5 7B, Ministral 3B, Qwen2.5-Coder 14B) plus two commercial
models.

---

## 2. Repository layout

```
p2a_demo.py               Flask harness: attack generation → call → defense → execute → reflect
                          (POST /api/run is the single entry point the runners call)
attacks.py                52 base attack vectors + per-category operators
{ecommerce,directus,gitea,ha}_attacks.py   per-testbed attack adaptations
defenses.py               D1–D5 implementations (D5 = Phase-1 whitelist + Phase-2 guard LLM)
api_server.py, ecommerce_api_server.py     mock/local backend servers

# Runners
run_rq1_real.py           RQ1/RQ2 baseline: 52 × 5 systems × 4 models = 1,040 runs → results/RQ2/
run_defense_experiments.py RQ3: 52 × 5 systems × 6 defenses (LLaMA-3) = 1,560 runs → results/defense/
r12_strategy_ablation.py  R1.2 operator selection vs. combination ablation
r21_adaptive_guard.py     R2.1 adaptive-attack robustness of the D5 guard ("who guards the guardian")
r22_false_positive.py     R2.2 false-positive rate / security–usability trade-off of D5
guard_cloud_eval.py       strong-end guard data point (cloud reasoning model)
commercial_crossmodel.py  commercial closed-source models (GPT-4o-mini, Claude-Haiku)

# Analysis
build_commercial_table.py, analyze_guard_capacity.py   assemble manuscript tables

results/                  all output data (see §5)
```

`.gitignore` excludes `.env` and local testbed deployments; the testbeds are
stood up separately (see §3).

---

## 3. Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install flask flask-cors requests          # Python 3.11

# Local LLMs via Ollama (https://ollama.com)
ollama pull llama3:latest        # 8B, primary defense model
ollama pull qwen2.5:latest       # 7B
ollama pull ministral-3:latest   # 3B
ollama pull qwen2.5-coder:14b    # 14B
```

Deploy the five backends locally (Strapi, a Flask E-Commerce server, Gitea,
Home Assistant, Directus) and point the harness at them. **All credentials and
endpoints are read from environment variables — never hard-code them.**

| Variable | Purpose |
|---|---|
| `OLLAMA_URL`, `OLLAMA_MODEL`, `LLM_TIMEOUT` | local LLM endpoint / default model |
| `USE_REAL_BACKEND=1` | execute against real backends (vs. mock) |
| `STRAPI_URL`, `ECOMMERCE_URL`, `GITEA_URL`, `HA_URL`, `DIRECTUS_URL` | testbed base URLs |
| `GITEA_TOKEN`, `HA_REFRESH_TOKEN` | testbed admin credentials (set your own) |
| `COMMERCIAL_API_KEY`, `COMMERCIAL_BASE` | commercial-model endpoint (OpenAI-compatible) |
| `DEEPSEEK_API_KEY`, `GUARD_CLOUD_MODEL`, `CLOUD_BASE` | cloud reasoning guard |
| `GUARD_MODEL` | Phase-2 guard model for D5 (default `llama3:latest`) |
| `DEMO_URL`, `PORT` | harness address the runners call |

> The scripts fall back to placeholder demo tokens for the throwaway local
> testbeds; override every credential via the environment for any real run.

---

## 4. Reproducing the results

Start the harness, then run the phases:

```bash
# 0. harness
USE_REAL_BACKEND=1 python p2a_demo.py            # serves POST /api/run

# 1. RQ1 (JSON compliance) + RQ2 (cross-model ASR)  → results/RQ2/
python run_rq1_real.py --system all --model all --n 1

# 2. RQ3 (five defenses, LLaMA-3)                    → results/defense/
python run_defense_experiments.py --defense all --system all --model llama3:latest

# 3. Revision experiments
python r12_strategy_ablation.py                                  # → results/R12_strategy_ablation.json
OLLAMA_MODEL=llama3:latest python r21_adaptive_guard.py          # → results/R21_adaptive_guard_*.json
OLLAMA_MODEL=llama3:latest python r22_false_positive.py          # → results/R22_false_positive_*.json
DEEPSEEK_API_KEY=... GUARD_CLOUD_MODEL=deepseek-v4-flash python guard_cloud_eval.py
COMMERCIAL_API_KEY=... python commercial_crossmodel.py           # → results/commercial_*.json
```

Decoding is greedy (`temperature=0.0`); each `⟨model, system, attack⟩` cell is a
single deterministic generation, so the 52 attack vectors are the unit of
replication (Wilson 95% CIs are over this population, not repeated sampling).

---

## 5. Result → manuscript mapping

| Data | Manuscript |
|---|---|
| `results/RQ2/*/rq1_*_*.json` | RQ1 JSON compliance (Table 2); RQ2 cross-model ASR (Tables 6, 7) |
| `results/defense/{none,D1..D5}/*_llama3_latest.json` | RQ3 residual ASR / block rate (Tables 9, 10, 11) |
| `results/R12_strategy_ablation.json` | Strategy selection vs. combination (Table 4) |
| `results/commercial_*.json` | Commercial closed-source models (Table 8) |
| `results/R21_adaptive_guard_*.json`, `results/R22_false_positive_*.json` | D5 guard robustness / usability (Table 12) |

Each per-run JSON records, per attack, the generated call, the defense decision
(`defense_action`, `defense_stage`, `defense_latency_ms`), the backend
`status_code`/response, the reflection step, and the success verdict, so every
aggregate in the manuscript can be recomputed from raw data.

---

## 6. The D5 defense (two phases)

1. **Phase 1 — deterministic whitelist** (`d3_gate_output`): an O(1) check of the
   generated `⟨method, endpoint⟩` against the role's minimal-privilege whitelist.
   Non-whitelisted calls are blocked with no model call.
2. **Phase 2 — semantic guard LLM** (`d5_validate_intent`): every whitelist-admitted
   call is checked by a guard model for semantic consistency between the user's
   query and the generated action; inconsistent calls are blocked. This catches
   the "intent-drift" attacks (legitimate endpoint, unauthorized intent) that a
   whitelist cannot.

---

## 7. Citation

If you use this artifact, please cite the JSS 2026 paper (see the manuscript for
the current reference). Report issues via the repository's issue tracker.
