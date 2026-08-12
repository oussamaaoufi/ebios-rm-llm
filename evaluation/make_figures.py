"""
make_figures.py
---------------
Publication figures (300 DPI) from the metrics and W&B training data.

  fig2_loss_curve.png     training + eval loss (from wandb export CSV if present)
  fig3_radar.png          3 models x metrics radar
  fig4_sector_breakdown.png   composite by sector
  fig5_mitre_accuracy.png     MITRE name accuracy bar (the key finding)

Run:
    python scripts\\evaluation\\make_figures.py
"""

import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from config import BASE_DIR as BASE
EVAL = BASE / "evaluation_results"
FIG = BASE / "paper_figures"
FIG.mkdir(exist_ok=True)
plt.rcParams.update({"font.size": 11, "font.family": "serif", "figure.dpi": 300})

MODELS = {
    "ebios_70b_finetuned": "Fine-tuned 70B (ours)",
    "llama_70b_raw":       "Raw Llama-3.3-70B",
    "gpt_5_5":             "GPT-5.5",
}
COLORS = {"ebios_70b_finetuned": "#1f77b4", "llama_70b_raw": "#ff7f0e", "gpt_5_5": "#2ca02c"}


def load(key):
    p = EVAL / f"metrics_{key}.json"
    return pd.DataFrame(json.loads(p.read_text())) if p.exists() else None


frames = {k: load(k) for k in MODELS if load(k) is not None}

# -------------------------------------------------- Fig 2: loss curve
loss_csv = EVAL / "wandb_loss_history.csv"   # export this from W&B (train/loss, eval/loss vs step)
if loss_csv.exists():
    df = pd.read_csv(loss_csv)
    fig, ax = plt.subplots(figsize=(6, 4))
    step_col = next((c for c in df.columns if "step" in c.lower()), df.columns[0])
    for col, lab in [(c, c) for c in df.columns if "loss" in c.lower()]:
        ax.plot(df[step_col], df[col], linewidth=1.3, label=lab)
    ax.set_xlabel("Training step"); ax.set_ylabel("Loss")
    ax.set_title("Fine-tuning loss — Llama-3.3-70B (run 3)")
    ax.legend(); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(FIG / "fig2_loss_curve.png"); plt.close(fig)
    print("fig2_loss_curve.png")
else:
    print("SKIP fig2: export W&B history to evaluation_results/wandb_loss_history.csv")
    print("  (W&B run page -> ... -> Export -> CSV, keep step + train/loss + eval/loss)")

# -------------------------------------------------- Fig 3: radar
METRICS = ["bleu4", "rougeL", "bertscore", "ebios", "composite"]
LABELS = ["BLEU-4", "ROUGE-L", "BERTScore", "EBIOS\ncompliance", "Composite"]
angles = np.linspace(0, 2 * np.pi, len(METRICS), endpoint=False).tolist()
angles += angles[:1]
fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
for key, f in frames.items():
    vals = f[METRICS].mean().tolist(); vals += vals[:1]
    ax.plot(angles, vals, linewidth=2, label=MODELS[key], color=COLORS[key])
    ax.fill(angles, vals, alpha=0.10, color=COLORS[key])
ax.set_xticks(angles[:-1]); ax.set_xticklabels(LABELS)
ax.set_ylim(0, 1); ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1))
fig.tight_layout(); fig.savefig(FIG / "fig3_radar.png"); plt.close(fig)
print("fig3_radar.png")

# -------------------------------------------------- Fig 4: by sector
if (EVAL / "table6_by_sector.csv").exists():
    bs = pd.read_csv(EVAL / "table6_by_sector.csv", index_col=0)
    ax = bs.plot(kind="bar", figsize=(8, 4.5), rot=0, edgecolor="black", linewidth=0.5)
    ax.set_ylabel("Composite score"); ax.set_xlabel("Sector"); ax.set_ylim(0, 1)
    ax.grid(axis="y", alpha=0.3); ax.legend(fontsize=9)
    ax.figure.tight_layout(); ax.figure.savefig(FIG / "fig4_sector_breakdown.png"); plt.close()
    print("fig4_sector_breakdown.png")

# -------------------------------------------------- Fig 5: MITRE accuracy
accs, names, cols = [], [], []
for key, f in frames.items():
    a = f["mitre_name_accuracy"].dropna()
    if len(a):
        accs.append(a.mean() * 100); names.append(MODELS[key]); cols.append(COLORS[key])
if accs:
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(names, accs, color=cols, edgecolor="black", linewidth=0.5)
    for b, v in zip(bars, accs):
        ax.text(b.get_x() + b.get_width()/2, v + 1, f"{v:.0f}%", ha="center", fontweight="bold")
    ax.set_ylabel("MITRE technique-name accuracy (%)"); ax.set_ylim(0, 105)
    ax.set_title("MITRE ATT&CK name accuracy by model")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(FIG / "fig5_mitre_accuracy.png"); plt.close(fig)
    print("fig5_mitre_accuracy.png")

print(f"\nFigures written to {FIG}")
