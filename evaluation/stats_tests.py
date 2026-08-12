"""
stats_tests.py
--------------
Paired statistical tests: is the fine-tuned model significantly better than
each baseline? Produces Table 5.

For each metric and each comparison (finetuned vs raw, finetuned vs gpt):
  Wilcoxon signed-rank test (paired, non-parametric)
  Cohen's d (paired effect size)
  95% bootstrap CI of the mean difference

Bonferroni note included for multiple comparisons.

Run:
    python scripts\\evaluation\\stats_tests.py
"""

import json
from pathlib import Path
import numpy as np
from scipy import stats

from config import EVAL_DIR as EVAL
load = lambda k: {r["id"]: r for r in json.loads((EVAL / f"metrics_{k}.json").read_text())}

ft = load("ebios_70b_finetuned")
have = {"ft": ft}
for k in ("llama_70b_raw", "gpt_5_5"):
    p = EVAL / f"metrics_{k}.json"
    if p.exists():
        have[k] = load(k)

ids = set(ft)
for k, v in have.items():
    ids &= set(v)
ids = sorted(ids)
print(f"Paired samples: {len(ids)}")


def paired(a, b, metric):
    x = np.array([a[i][metric] for i in ids], dtype=float)
    y = np.array([b[i][metric] for i in ids], dtype=float)
    diff = x - y
    # Wilcoxon needs some non-zero differences
    if np.all(diff == 0):
        return {"mean_ft": float(x.mean()), "mean_base": float(y.mean()),
                "mean_diff": 0.0, "wilcoxon_p": 1.0, "cohens_d": 0.0,
                "ci95": [0.0, 0.0], "note": "identical"}
    try:
        w = stats.wilcoxon(x, y)
        pval = float(w.pvalue)
    except Exception:
        pval = float("nan")
    sd = diff.std(ddof=1)
    d = float(diff.mean() / sd) if sd > 0 else 0.0
    try:
        ci = stats.bootstrap((diff,), np.mean, confidence_level=0.95,
                             n_resamples=10000, random_state=42).confidence_interval
        ci_lo, ci_hi = float(ci.low), float(ci.high)
    except Exception:
        ci_lo, ci_hi = float("nan"), float("nan")
    return {"mean_ft": float(x.mean()), "mean_base": float(y.mean()),
            "mean_diff": float(diff.mean()), "wilcoxon_p": pval,
            "cohens_d": d, "ci95": [ci_lo, ci_hi]}


METRICS = ["composite", "ebios", "bertscore", "rougeL", "bleu4",
           "json_valid", "mitre_name_accuracy"]

results = {}
n_tests = 0
for metric in METRICS:
    entry = {}
    if "llama_70b_raw" in have:
        # mitre_name_accuracy has None values -> filter to shared non-null
        if metric == "mitre_name_accuracy":
            shared = [i for i in ids if ft[i].get(metric) is not None
                      and have["llama_70b_raw"][i].get(metric) is not None]
            if shared:
                a = {i: ft[i] for i in shared}; b = {i: have["llama_70b_raw"][i] for i in shared}
                old_ids = ids
                globals()['ids'] = shared
                entry["finetuned_vs_raw"] = paired(a, b, metric)
                globals()['ids'] = old_ids
        else:
            entry["finetuned_vs_raw"] = paired(ft, have["llama_70b_raw"], metric)
        n_tests += 1
    if "gpt_5_5" in have:
        if metric == "mitre_name_accuracy":
            shared = [i for i in ids if ft[i].get(metric) is not None
                      and have["gpt_5_5"][i].get(metric) is not None]
            if shared:
                a = {i: ft[i] for i in shared}; b = {i: have["gpt_5_5"][i] for i in shared}
                old_ids = ids
                globals()['ids'] = shared
                entry["finetuned_vs_gpt"] = paired(a, b, metric)
                globals()['ids'] = old_ids
        else:
            entry["finetuned_vs_gpt"] = paired(ft, have["gpt_5_5"], metric)
        n_tests += 1
    results[metric] = entry

results["_meta"] = {"n_paired": len(ids), "n_tests": n_tests,
                    "bonferroni_alpha_0.05": 0.05 / max(n_tests, 1)}

(EVAL / "statistical_tests.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

# readable print
print("\n=== Table 5: Statistical Tests (fine-tuned vs baselines) ===")
for metric in METRICS:
    if metric not in results or not results[metric]:
        continue
    print(f"\n{metric}:")
    for comp, r in results[metric].items():
        star = ""
        if isinstance(r.get("wilcoxon_p"), float) and r["wilcoxon_p"] < results["_meta"]["bonferroni_alpha_0.05"]:
            star = " *sig (Bonferroni)"
        print(f"  {comp}: ft={r['mean_ft']:.3f} base={r['mean_base']:.3f} "
              f"diff={r['mean_diff']:+.3f} p={r['wilcoxon_p']:.2e} d={r['cohens_d']:.2f}{star}")

print(f"\nBonferroni alpha: {results['_meta']['bonferroni_alpha_0.05']:.4f} "
      f"({n_tests} tests)")
print(f"Saved -> {EVAL / 'statistical_tests.json'}")
