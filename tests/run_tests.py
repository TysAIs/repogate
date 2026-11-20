#!/usr/bin/env python3
"""RepoGate fixture tests: clean repo must pass, malicious skill must BLOCK."""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "repogate.py"

def run(target):
    out = ROOT / "tests" / "last-report.json"
    p = subprocess.run([sys.executable, str(TOOL), str(target), "--json", str(out)],
                       capture_output=True, text=True)
    report = json.loads(out.read_text()) if out.exists() else {}
    return p.returncode, report, p.stdout

fails = []
code, rep, _ = run(ROOT / "fixtures" / "clean-repo")
print(f"clean-repo: exit={code} verdict={rep.get('verdict')} score={rep.get('score')}")
if code != 0 or rep.get("verdict") != "CLEAN":
    fails.append(f"clean-repo expected CLEAN/0, got {rep.get('verdict')}/{code}")

code, rep, _ = run(ROOT / "fixtures" / "malicious-skill")
ids = {f["rule_id"] for f in rep.get("findings", [])}
chains = {f["rule_id"] for f in rep.get("findings", []) if f.get("chain")}
print(f"malicious-skill: exit={code} verdict={rep.get('verdict')} score={rep.get('score')}")
print(f"  chains: {sorted(chains)}")
if code != 2 or rep.get("verdict") != "BLOCK":
    fails.append(f"malicious-skill expected BLOCK/2, got {rep.get('verdict')}/{code}")
for want in ("chain-stealer", "chain-autorun-dropper", "chain-prompt-exfil"):
    if want not in chains:
        fails.append(f"malicious-skill missing chain {want}")
for want in ("pi-ignore-instructions", "auto-vscode-folderopen", "hook-npm-lifecycle"):
    if want not in ids:
        fails.append(f"malicious-skill missing finding {want}")

# --- independent-verifier evasion set (fixtures/evasion, added v1.2) ------
# Every fixture is a working attack shape; all must verdict BLOCK (exit 2).
import glob as _glob
for _fx in sorted(_glob.glob(str(ROOT / "fixtures" / "evasion" / "*"))):
    _code, _rep, _ = run(_fx)
    print(f"{'evasion/' + Path(_fx).name}: exit={_code} verdict={_rep.get('verdict')}")
    if _code != 2 or _rep.get("verdict") != "BLOCK":
        fails.append(f"evasion/{Path(_fx).name} expected BLOCK/2, "
                     f"got {_rep.get('verdict')}/{_code}")

if fails:
    print("\nFAILURES:"); [print(" -", f) for f in fails]; sys.exit(1)
print("\nAll fixture tests passed.")
