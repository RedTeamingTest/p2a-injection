"""Live experiment runner – RQ1 + RQ2 + RQ3 via remote Flask API."""

import json, math, sys, time, statistics
from pathlib import Path
import requests

RUN_URL  = "http://43.135.164.97/api/run"
TIMEOUT  = 150
PAUSE    = 0.3

PAPER_ATTACKS = [
    "U.1","U.2","U.3","U.4","U.5",
    "RD.1","RD.2","RD.3","RD.4",
    "RI.1","RI.2","RI.3","RI.4","RI.5",
]

MODELS = {
    "LLaMA-3":     "llama3:latest",
    "Qwen2.5":     "qwen2.5:latest",
    "Ministral-3": "ministral-3:latest",
    "QwC-14B":     "qwen2.5-coder:14b",
}

DEFENSES = ["none","D1","D2","D3","D4","D5"]

OUT = Path(__file__).parent / "results_live"
OUT.mkdir(exist_ok=True)

def do_trial(atk_id, model, defense="none"):
    payload = {"testbed":"portal","atk_id":atk_id,"model":model,"n_trials":1}
    if defense != "none":
        payload["defense"] = defense
    try:
        r = requests.post(RUN_URL, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json()
        return {"success": bool(d.get("success",False)),
                "t_total": d.get("t_total",0),
                "generated_call": d.get("generated_call"),
                "error": None}
    except Exception as e:
        return {"success": False, "t_total": 0, "generated_call": None, "error": str(e)}

def run_batch(label, attacks, model, n, defense="none"):
    results = {}
    total = len(attacks)*n; done = 0; t0 = time.time()
    for atk in attacks:
        results[atk] = []
        for i in range(n):
            done += 1
            res = do_trial(atk, model, defense)
            results[atk].append(res)
            el = time.time()-t0
            eta = el/done*(total-done) if done else 0
            badge = "OK" if res["success"] else "--"
            print(f"  [{label}] {atk} t{i+1}/{n} {badge}  ({done}/{total} ETA {eta/60:.1f}min)", flush=True)
            time.sleep(PAUSE)
    return results

def asr(trials):
    if not trials: return 0.0
    return round(sum(t["success"] for t in trials)/len(trials)*100, 1)

def wilson(s, n, z=1.96):
    if n==0: return (0.0,0.0)
    p=s/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d
    m=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return (round(max(0.0,c-m)*100,1), round(min(100.0,c+m)*100,1))

def save_json(data, name):
    p = OUT/name
    p.write_text(json.dumps(data, indent=2, default=str))
    print(f"  Saved => {p}")

def run_rq1(n=10):
    print(f"\n{'='*60}\nRQ1  14 attacks x {n} trials  (llama3, no defense)\n{'='*60}")
    raw = run_batch("RQ1", PAPER_ATTACKS, MODELS["LLaMA-3"], n)
    summary = {}
    for atk in PAPER_ATTACKS:
        s = sum(t["success"] for t in raw[atk]); nn=len(raw[atk])
        lo,hi = wilson(s,nn)
        summary[atk] = {"n":nn,"successes":s,"asr":asr(raw[atk]),"ci_lo":lo,"ci_hi":hi}
    save_json({"rq":"RQ1","model":MODELS["LLaMA-3"],"n_trials":n,
               "summary":summary,"raw":raw}, "rq1_live.json")
    print(f"\n{'Atk':<7} {'ASR':>6}  95%CI")
    print("-"*35)
    for atk in PAPER_ATTACKS:
        r=summary[atk]
        print(f"{atk:<7} {r['asr']:>5}%  [{r['ci_lo']},{r['ci_hi']}]")
    return summary

def run_rq2(n=5):
    print(f"\n{'='*60}\nRQ2  14 attacks x 4 models x {n} trials\n{'='*60}")
    matrix={}; all_raw={}
    for mlabel,mname in MODELS.items():
        print(f"\n--- {mlabel} ({mname}) ---")
        raw = run_batch(f"RQ2/{mlabel}", PAPER_ATTACKS, mname, n)
        all_raw[mlabel]=raw
        for atk in PAPER_ATTACKS:
            matrix.setdefault(atk,{})[mlabel] = asr(raw[atk])
    means = {ml: round(statistics.mean(matrix[a][ml] for a in PAPER_ATTACKS),1) for ml in MODELS}
    save_json({"rq":"RQ2","n_trials":n,"attacks":PAPER_ATTACKS,
               "asr_matrix":matrix,"model_means":means,"raw":all_raw}, "rq2_live.json")
    mk=list(MODELS.keys())
    print("\n"+"Atk".ljust(7)+"  ".join(k.rjust(11) for k in mk))
    print("-"*60)
    for atk in PAPER_ATTACKS:
        print(atk.ljust(7)+"  ".join(f"{matrix[atk].get(k,0):>10.1f}%" for k in mk))
    print("Mean".ljust(7)+"  ".join(f"{means[k]:>10.1f}%" for k in mk))
    return matrix, means

def run_rq3(n=5):
    print(f"\n{'='*60}\nRQ3  14 attacks x 6 defenses x {n} trials  (llama3)\n{'='*60}")
    model=MODELS["LLaMA-3"]; asr_mat={}; all_raw={}
    for d in DEFENSES:
        print(f"\n--- Defense: {d} ---")
        raw = run_batch(f"RQ3/{d}", PAPER_ATTACKS, model, n, defense=d)
        all_raw[d]=raw
        asr_mat[d]={atk:asr(raw[atk]) for atk in PAPER_ATTACKS}
    baseline=asr_mat.get("none",{})
    def_stats={}
    for d in DEFENSES:
        residuals=[asr_mat[d][a] for a in PAPER_ATTACKS]
        mean_r=round(statistics.mean(residuals),1)
        vuln=[a for a in PAPER_ATTACKS if baseline.get(a,100)>0]
        blocked=[a for a in vuln if asr_mat[d][a]==0]
        br=round(len(blocked)/len(vuln)*100,1) if vuln else 0.0
        def_stats[d]={"block_rate":br,"mean_residual_asr":mean_r,"blocked_attacks":blocked}
    save_json({"rq":"RQ3","model":model,"n_trials":n,"attacks":PAPER_ATTACKS,
               "asr_matrix":asr_mat,"defense_stats":def_stats,"raw":all_raw}, "rq3_live.json")
    print(f"\n{'Def':<6} {'BlockRate':>10}  {'ResidualASR':>12}")
    print("-"*35)
    for d in DEFENSES:
        s=def_stats[d]
        print(f"{d:<6} {s['block_rate']:>9}%  {s['mean_residual_asr']:>11}%")
    return asr_mat, def_stats

if __name__ == "__main__":
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--rq",choices=["rq1","rq2","rq3","all"],default="all")
    ap.add_argument("--n1",type=int,default=10)
    ap.add_argument("--n2",type=int,default=5)
    ap.add_argument("--n3",type=int,default=5)
    args=ap.parse_args()
    t0=time.time()
    if args.rq in ("rq1","all"): run_rq1(args.n1)
    if args.rq in ("rq2","all"): run_rq2(args.n2)
    if args.rq in ("rq3","all"): run_rq3(args.n3)
    print(f"\nAll done in {(time.time()-t0)/60:.1f} min  => {OUT}/")
