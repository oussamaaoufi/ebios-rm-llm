"""
aggregate.py
------------
Turns metrics_*.json into the paper's main results table + breakdowns.

Outputs (all in evaluation_results/):
  table3_main_results.csv     mean +/- std per metric per model  -> Table 3
  table6_by_sector.csv        composite by sector                -> Figure 4
  table7_by_workshop.csv      composite by workshop
  table8_mitre_accuracy.csv   MITRE name accuracy per model      -> key finding
  summary.md                  human-readable summary of everything

Run:
    python scripts\\evaluation\\aggregate.py
"""

import json
from pathlib import Path
import pandas as pd
import numpy as np

from config import EVAL_DIR as EVAL

MODELS = {
    "ebios_70b_finetuned": "Fine-tuned Llama-3.3-70B (ours)",
    "llama_70b_raw":       "Raw Llama-3.3-70B",
    "gpt_5_5":             "GPT-5.5",
}
METRICS = ["bleu4", "rouge1", "rouge2", "rougeL", "bertscore",
           "json_valid", "ebios", "composite"]

frames = {}
for key in MODELS:
    p = EVAL / f"metrics_{key}.json"
    if not p.exists():
        print(f"MISSING metrics_{key}.json — run compute_metrics.py")
        continue
    frames[key] = pd.DataFrame(json.loads(p.read_text()))

if not frames:
    raise SystemExit("No metrics files found.")

# ---------------------------------------------------------------- Table 3
means = pd.DataFrame({MODELS[k]: f[METRICS].mean() for k, f in frames.items()}).T
stds = pd.DataFrame({MODELS[k]: f[METRICS].std() for k, f in frames.items()}).T
table3 = means.round(3).astype(str) + " ± " + stds.round(3).astype(str)
table3.to_csv(EVAL / "table3_main_results.csv")
print("=== Table 3: Main Results (mean ± std) ===")
print(table3.to_markdown())

# ---------------------------------------------------------------- MITRE accuracy
mitre_rows = {}
for k, f in frames.items():
    accs = f["mitre_name_accuracy"].dropna()
    mitre_rows[MODELS[k]] = {
        "mean_accuracy": round(accs.mean(), 4) if len(accs) else None,
        "n_samples_with_mitre": int(len(accs)),
        "total_mitre_pairs": int(f["mitre_pairs"].sum()),
    }
mitre_df = pd.DataFrame(mitre_rows).T
mitre_df.to_csv(EVAL / "table8_mitre_accuracy.csv")
print("\n=== Table 8: MITRE Name Accuracy (key finding) ===")
print(mitre_df.to_markdown())

# ---------------------------------------------------------------- by sector
by_sector = pd.concat(
    {MODELS[k]: f.groupby("sector")["composite"].mean() for k, f in frames.items()}, axis=1)
by_sector.round(3).to_csv(EVAL / "table6_by_sector.csv")
print("\n=== Composite by Sector ===")
print(by_sector.round(3).to_markdown())

# ---------------------------------------------------------------- by workshop
by_ws = pd.concat(
    {MODELS[k]: f.groupby("workshop")["composite"].mean() for k, f in frames.items()}, axis=1)
by_ws.round(3).to_csv(EVAL / "table7_by_workshop.csv")
print("\n=== Composite by Workshop ===")
print(by_ws.round(3).to_markdown())

# ---------------------------------------------------------------- summary.md
lines = ["# Evaluation Summary\n", "## Table 3 — Main Results\n",
         table3.to_markdown(), "\n\n## MITRE Name Accuracy\n", mitre_df.to_markdown(),
         "\n\n## Composite by Sector\n", by_sector.round(3).to_markdown(),
         "\n\n## Composite by Workshop\n", by_ws.round(3).to_markdown()]
(EVAL / "summary.md").write_text("\n".join(lines), encoding="utf-8")
print(f"\nAll tables written to {EVAL}")
print("Human-readable summary: summary.md")
