"""
compute_metrics.py
------------------
Computes per-sample metrics for the three models on the 100-sample test set,
then writes metrics_<model>.json for each.

Metrics:
  BLEU-4, ROUGE-1/2/L, BERTScore-F1  (text similarity to reference)
  json_valid           (1 if output parses as JSON)
  ebios_compliance     (required-field presence + MITRE presence + parseability)
  mitre_name_accuracy  (fraction of mitre_id/mitre_name pairs whose name matches
                        the authoritative MITRE data — the run-3 improvement)
  composite            (weighted blend; see WEIGHTS)

Model files (schema-guided baselines, run-3 fine-tuned):
  outputs_ebios_70b_finetuned.json
  outputs_llama_70b_raw_schema.json
  outputs_gpt_5_5_schema.json

Run:
    python scripts\\evaluation\\compute_metrics.py
"""

import json
import re
from pathlib import Path
import numpy as np
from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
from rouge_score import rouge_scorer
from bert_score import score as bert_score

from config import BASE_DIR as BASE
EVAL = BASE / "evaluation_results"
RAW = BASE / "raw_data"

MODELS = {
    "ebios_70b_finetuned": "outputs_ebios_70b_finetuned.json",
    "llama_70b_raw":       "outputs_llama_70b_raw_schema.json",
    "gpt_5_5":             "outputs_gpt_5_5_schema.json",
}

WEIGHTS = {"bleu4": 0.15, "rougeL": 0.20, "bertscore": 0.30, "ebios": 0.35}

REQUIRED_FIELDS = {
    2: ["risk_origin", "target_objective", "business_asset"],
    3: ["risk_origin", "attack_path", "severity"],
    4: ["knowing", "entering", "finding", "exploiting", "likelihood"],
}

# authoritative MITRE id -> name
mitre = json.loads((RAW / "mitre_complete.json").read_text(encoding="utf-8"))
ID2NAME = {t["id"]: t["name"] for t in mitre.get("techniques", []) if t.get("id") and t.get("name")}

smooth = SmoothingFunction().method4
rscorer = rouge_scorer.RougeScorer(["rouge1", "rouge2", "rougeL"], use_stemmer=True)


def try_parse(text):
    if not text or "{" not in text:
        return None
    try:
        return json.loads(text[text.find("{"): text.rfind("}") + 1])
    except Exception:
        return None


def ebios_compliance(text, workshop):
    low = (text or "").lower()
    fields = REQUIRED_FIELDS.get(workshop, [])
    field_score = sum(f.lower() in low for f in fields) / len(fields) if fields else 0.0
    mitre = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text or ""))
    mitre_score = min(len(mitre) / 3.0, 1.0)
    parse_score = 1.0 if try_parse(text) else 0.0
    return 0.5 * field_score + 0.3 * mitre_score + 0.2 * parse_score


def mitre_name_accuracy(text):
    """Fraction of mitre_id/mitre_name pairs whose name matches authoritative data."""
    obj = try_parse(text)
    pairs = []

    def walk(o):
        if isinstance(o, dict):
            if "mitre_id" in o and "mitre_name" in o:
                pairs.append((o["mitre_id"], str(o["mitre_name"])))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    if obj is not None:
        walk(obj)
    if not pairs:
        return None, 0   # no pairs to judge
    correct = sum(1 for tid, name in pairs
                  if tid in ID2NAME and name.strip().lower() == ID2NAME[tid].strip().lower())
    return correct / len(pairs), len(pairs)


def bleu(ref, hyp):
    return sentence_bleu([ref.split()], hyp.split(), smoothing_function=smooth)


for key, fname in MODELS.items():
    path = EVAL / fname
    if not path.exists():
        print(f"SKIP {key}: {fname} not found")
        continue
    data = json.loads(path.read_text(encoding="utf-8"))
    def safe(x):
        x = (x or "").strip()
        return x if x else "[empty]"      # BERTScore RobertaTokenizer fails on ""
    refs = [safe(d["reference"]) for d in data]
    hyps = [safe(d.get("generated")) for d in data]

    print(f"\n=== {key} — BERTScore on {len(data)} samples (first run downloads a model) ===")
    P, R, F1 = bert_score(hyps, refs, lang="en", verbose=True, batch_size=8)

    rows = []
    for d, f1 in zip(data, F1.tolist()):
        gen = (d.get("generated") or "").strip() or "[empty]"
        r = rscorer.score(d["reference"], gen)
        acc, npairs = mitre_name_accuracy(gen)
        m = {
            "id": d["id"], "sector": d["sector"], "workshop": d["workshop"],
            "bleu4": bleu(d["reference"], gen),
            "rouge1": r["rouge1"].fmeasure,
            "rouge2": r["rouge2"].fmeasure,
            "rougeL": r["rougeL"].fmeasure,
            "bertscore": f1,
            "json_valid": 1.0 if try_parse(gen) else 0.0,
            "ebios": ebios_compliance(gen, d["workshop"]),
            "mitre_name_accuracy": acc,
            "mitre_pairs": npairs,
        }
        m["composite"] = (WEIGHTS["bleu4"] * m["bleu4"]
                          + WEIGHTS["rougeL"] * m["rougeL"]
                          + WEIGHTS["bertscore"] * m["bertscore"]
                          + WEIGHTS["ebios"] * m["ebios"])
        rows.append(m)

    (EVAL / f"metrics_{key}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")

    comp = np.mean([r["composite"] for r in rows])
    jval = np.mean([r["json_valid"] for r in rows])
    accs = [r["mitre_name_accuracy"] for r in rows if r["mitre_name_accuracy"] is not None]
    macc = np.mean(accs) if accs else float("nan")
    print(f"{key}: composite={comp:.4f}  json_valid={jval:.2%}  "
          f"mitre_name_acc={macc:.2%} (n={len(accs)})")

print("\nDone. metrics_*.json written to evaluation_results.")