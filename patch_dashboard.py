#!/usr/bin/env python3
"""Patch p2a_demo.py to add /api/results endpoint and serve dashboard.html"""
import os, sys, shutil, json

DEMO_DIR = "/home/qyb/TongBu/prompt_to_api_call_injection/demo"
PY_FILE = os.path.join(DEMO_DIR, "p2a_demo.py")

with open(PY_FILE, "r") as f:
    content = f.read()

shutil.copy2(PY_FILE, PY_FILE + ".bak6")
print(f"[+] Backup created: {PY_FILE}.bak6")

lines = content.split('\n')

route_idx = None
for i, line in enumerate(lines):
    if line.strip() == '@app.route("/")':
        route_idx = i
        break

if route_idx is None:
    print("[-] Could not find @app.route('/') - aborting"); sys.exit(1)

print(f"[+] Found @app.route('/') at line {route_idx + 1}")

results_api_code = '''
@app.route("/api/results")
def api_results():
    results_dir = os.path.join(os.path.dirname(__file__), "results", "RQ1")
    out = {}
    if not os.path.isdir(results_dir):
        return jsonify(out)
    for sys_dir in os.listdir(results_dir):
        sys_path = os.path.join(results_dir, sys_dir)
        if not os.path.isdir(sys_path):
            continue
        for fname in os.listdir(sys_path):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(sys_path, fname)
            try:
                with open(fpath) as f:
                    data = json.load(f)
                system = data.get("system") or data.get("testbed", sys_dir)
                model = data.get("model", "unknown")
                key = f"{system}_{model}"
                summary = data.get("summary", {})
                total_s = sum(v.get("successes", 0) for v in summary.values())
                total_n = sum(v.get("n", 0) for v in summary.values())
                overall_asr = 100.0 * total_s / total_n if total_n > 0 else 0
                out[key] = {
                    "system": system, "model": model,
                    "overall_asr": overall_asr,
                    "total_successes": total_s, "total_trials": total_n,
                    "attacks": {
                        aid: {"asr": v.get("asr", 0), "successes": v.get("successes", 0),
                              "n": v.get("n", 0), "ci_lo": v.get("ci_lo", 0), "ci_hi": v.get("ci_hi", 0)}
                        for aid, v in summary.items()
                    },
                }
            except Exception:
                pass
    return jsonify(out)


@app.route("/")
def index():
    html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()
'''

html_template_start = None
html_template_end = None
for i, line in enumerate(lines):
    if line.startswith('HTML_TEMPLATE = """'):
        html_template_start = i
    elif html_template_start is not None and line.strip() == '"""' and i > html_template_start + 10:
        html_template_end = i
        break

if html_template_start is None:
    print("[-] Could not find HTML_TEMPLATE start"); sys.exit(1)

print(f"[+] HTML_TEMPLATE: lines {html_template_start+1} to {html_template_end+1}")

idx_func_end = route_idx + 1
while idx_func_end < len(lines):
    idx_func_end += 1
    if idx_func_end >= len(lines):
        break
    line = lines[idx_func_end]
    if line.strip() == '':
        continue
    if not line.startswith(' ') and not line.startswith('\t'):
        break

print(f"[+] Old index(): lines {route_idx+1} to {idx_func_end}")

new_lines = lines[:route_idx]
new_lines.append(results_api_code)
rest_start = html_template_end + 1
new_lines.extend(lines[rest_start:])

content = '\n'.join(new_lines)

with open(PY_FILE, "w") as f:
    f.write(content)

print(f"[+] File patched! New: {content.count(chr(10))} lines (was {len(lines)})")

import py_compile
try:
    py_compile.compile(PY_FILE, doraise=True)
    print("[+] Python syntax check PASSED")
except py_compile.PyCompileError as e:
    print(f"[-] Syntax error: {e}")
    shutil.copy2(PY_FILE + ".bak6", PY_FILE)
    print("[+] Restored from backup")
    sys.exit(1)
