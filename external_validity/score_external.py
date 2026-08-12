"""
score_external.py
-----------------
Scores the external-validity outputs. The key metric is MITRE technique
PRECISION: of the technique IDs the model names in its scenario, what fraction
appear in the authoritative advisory list for that incident. This is the fair
out-of-distribution measure — the model produces a focused scenario, and we ask
whether the techniques it chose are real techniques from that real attack.

Also reports: recall (how many advisory techniques the model recovered),
JSON validity, and MITRE-name correctness against the official catalogue.

Run:
    python scripts\\evaluation\\score_external.py
"""

import json
import re
from pathlib import Path
import numpy as np

from config import BASE_DIR as BASE
EVAL = BASE / "evaluation_results"
RAW = BASE / "raw_data"

id2name = {t["id"]: t["name"] for t in
           json.loads((RAW / "mitre_complete.json").read_text(encoding="utf-8"))["techniques"]
           if t.get("id") and t.get("name")}

MODELS = {
    "finetuned": "external_outputs_finetuned.json",
    "llama_raw": "external_outputs_llama_raw.json",
    "gpt_5_5":   "external_outputs_gpt_5_5.json",
}

TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

def _parses(text):
    t = text[text.find("{"): text.rfind("}") + 1]
    try:
        json.loads(t); return True
    except Exception:
        return False


def extract_ids(text):
    return set(TECH_RE.findall(text or ""))


def name_correct_ids(text):
    """IDs whose (id,name) pair in the output matches the official catalogue."""
    obj = None
    t = (text or "").strip()
    if "{" in t:
        try:
            obj = json.loads(t[t.find("{"): t.rfind("}") + 1])
        except Exception:
            obj = None
    pairs = []
    def walk(o):
        if isinstance(o, dict):
            if "mitre_id" in o and "mitre_name" in o:
                pairs.append((o["mitre_id"], str(o["mitre_name"])))
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
    if obj is not None: walk(obj)
    correct = sum(1 for i, n in pairs
                  if i in id2name and n.strip().lower() == id2name[i].strip().lower())
    return correct, len(pairs)


print(f"{'Model':<12}{'Precision':>10}{'Recall':>9}{'JSON':>7}{'NameAcc':>9}  (n scored)")
print("-" * 60)

summary = {}
for key, fname in MODELS.items():
    path = EVAL / fname
    if not path.exists():
        print(f"{key:<12}  (no output file — skipped)")
        continue
    data = json.loads(path.read_text(encoding="utf-8"))
    precisions, recalls, jsons, nameaccs = [], [], [], []
    per_item = []
    for r in data:
        gen = r.get("generated") or ""
        ref_ids = {t["id"] for t in r["reference_techniques"]}
        gen_ids = extract_ids(gen)

        prec = len(gen_ids & ref_ids) / len(gen_ids) if gen_ids else 0.0
        rec = len(gen_ids & ref_ids) / len(ref_ids) if ref_ids else 0.0
        jv = 1.0 if ("{" in gen and "}" in gen and _parses(gen)) else 0.0
        nc, npairs = name_correct_ids(gen)
        nacc = nc / npairs if npairs else None

        precisions.append(prec); recalls.append(rec); jsons.append(jv)
        if nacc is not None: nameaccs.append(nacc)
        per_item.append({"id": r["id"], "sector": r["sector"],
                         "precision": prec, "recall": rec,
                         "gen_techniques": sorted(gen_ids),
                         "matched": sorted(gen_ids & ref_ids)})

    (EVAL / f"external_metrics_{key}.json").write_text(
        json.dumps(per_item, indent=2), encoding="utf-8")

    summary[key] = {
        "precision": float(np.mean(precisions)),
        "recall": float(np.mean(recalls)),
        "json_valid": float(np.mean(jsons)),
        "name_acc": float(np.mean(nameaccs)) if nameaccs else float("nan"),
        "n": len(data),
    }
    s = summary[key]
    print(f"{key:<12}{s['precision']:>10.3f}{s['recall']:>9.3f}"
          f"{s['json_valid']:>7.2f}{s['name_acc']:>9.3f}  ({s['n']})")

(EVAL / "external_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print("\nSaved external_metrics_*.json and external_summary.json")
print("\nPrecision = of techniques the model named, fraction real (in the advisory).")
print("Recall    = of advisory techniques, fraction the model recovered.")

