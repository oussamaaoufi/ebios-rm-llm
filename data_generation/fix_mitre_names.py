"""
fix_mitre_names.py
------------------
Root cause: the Phase 3 generator paired correct MITRE technique IDs with WRONG
technique names (e.g. T1598 labelled "Hardware" instead of "Phishing for
Information"). The model faithfully learned this, so run 2 reproduces the errors.

Fix: rebuild an authoritative {id -> name} map from raw_data/mitre_complete.json
(your own Phase 2 collection) and overwrite every mitre_name in the dataset.

Writes a corrected dataset and a report of what changed (evidence for the paper).

Run:
    python scripts\\fix_mitre_names.py
"""

import json
import re
from pathlib import Path
from collections import Counter

from config import BASE_DIR as BASE
RAW = BASE / "raw_data"
PROC = BASE / "processed_data"
EVAL = BASE / "evaluation_results"

# ---------------------------------------------------------------- authoritative map
mitre = json.loads((RAW / "mitre_complete.json").read_text(encoding="utf-8"))
id2name = {}
for t in mitre.get("techniques", []):
    tid, name = t.get("id"), t.get("name")
    if tid and name:
        id2name[tid] = name
print(f"Authoritative MITRE techniques loaded: {len(id2name)}")
if len(id2name) < 100:
    raise SystemExit("MITRE map looks too small — check raw_data/mitre_complete.json")

# ---------------------------------------------------------------- fix walker
stats = {"names_fixed": 0, "names_already_ok": 0, "unknown_ids": Counter(),
         "examples": []}


def fix(obj):
    if isinstance(obj, dict):
        tid = obj.get("mitre_id")
        if tid and "mitre_name" in obj:
            if tid in id2name:
                correct = id2name[tid]
                if obj["mitre_name"] != correct:
                    if len(stats["examples"]) < 25:
                        stats["examples"].append(
                            {"id": tid, "was": obj["mitre_name"], "now": correct})
                    obj["mitre_name"] = correct
                    stats["names_fixed"] += 1
                else:
                    stats["names_already_ok"] += 1
            else:
                stats["unknown_ids"][tid] += 1
        # validate bare ID lists too (report only, don't alter)
        for key in ("mitre_techniques", "mitre_references"):
            v = obj.get(key)
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, str) and re.match(r"^T\d{4}", x) and x not in id2name:
                        stats["unknown_ids"][x] += 1
        for v in obj.values():
            fix(v)
    elif isinstance(obj, list):
        for v in obj:
            fix(v)


# ---------------------------------------------------------------- apply
src = PROC / "dataset_clean.json"
data = json.loads(src.read_text(encoding="utf-8"))
samples = data["samples"] if isinstance(data, dict) and "samples" in data else data

for s in samples:
    fix(s)

# save corrected
out = PROC / "dataset_clean_fixed.json"
payload = {"samples": samples} if isinstance(data, dict) and "samples" in data else samples
out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

# ---------------------------------------------------------------- report
print(f"\nMITRE name corrections: {stats['names_fixed']}")
print(f"Already correct:        {stats['names_already_ok']}")
print(f"Distinct unknown IDs:   {len(stats['unknown_ids'])}")

print("\nSample corrections (was -> now):")
for e in stats["examples"][:15]:
    print(f"  {e['id']}:  '{e['was']}'  ->  '{e['now']}'")

if stats["unknown_ids"]:
    print("\nTop IDs not found in your MITRE data (left unchanged, review these):")
    for tid, n in stats["unknown_ids"].most_common(15):
        print(f"  {tid}  x{n}")

report = {
    "names_fixed": stats["names_fixed"],
    "names_already_ok": stats["names_already_ok"],
    "unknown_ids": dict(stats["unknown_ids"]),
    "examples": stats["examples"],
}
EVAL.mkdir(exist_ok=True)
(EVAL / "mitre_fix_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(f"\nCorrected dataset -> {out}")
print(f"Report            -> {EVAL / 'mitre_fix_report.json'}")
print("\nNEXT: overwrite dataset_clean.json with the fixed version, then re-split + retrain.")
