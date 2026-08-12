"""
build_expert_package.py
-----------------------
Builds the blind expert-evaluation package from the run-3 outputs:

  5 scenarios from the fine-tuned model   (source A)
  5 from raw Llama-3.3 (schema)           (source B)
  5 from GPT-5.5 (schema)                 (source C)
  5 human-reference scenarios             (source D)  <- the indistinguishability test

All 20 are anonymised, shuffled, and written to:
  expert_package_blind.json   -> the items evaluators see (item_id, instruction, scenario)
  expert_package_key.json     -> the source of each item  (NEVER send this)

Sampling is stratified so the 5 picks per source span different workshops/sectors.
Seed fixed for reproducibility.

Run:
    python scripts\\evaluation\\build_expert_package.py
"""

import json
import random
from pathlib import Path

from config import EVAL_DIR as EVAL
SEED = 7
random.seed(SEED)

SOURCES = {
    "A_finetuned":     "outputs_ebios_70b_finetuned.json",
    "B_llama_raw":     "outputs_llama_70b_raw_schema.json",
    "C_gpt55":         "outputs_gpt_5_5_schema.json",
}
N_PER_SOURCE = 5


def load(fname):
    p = EVAL / fname
    if not p.exists():
        raise SystemExit(f"Missing {p}. Check the filename.")
    return json.loads(p.read_text(encoding="utf-8"))


def stratified_pick(data, n):
    """Pick n items spanning distinct (sector, workshop) cells where possible."""
    usable = [d for d in data if (d.get("generated") or "").strip()]
    random.shuffle(usable)
    picked, seen = [], set()
    for d in usable:
        cell = (d.get("sector"), d.get("workshop"))
        if cell not in seen:
            picked.append(d); seen.add(cell)
        if len(picked) == n:
            return picked
    # top up if not enough distinct cells
    for d in usable:
        if d not in picked:
            picked.append(d)
        if len(picked) == n:
            break
    return picked[:n]


items, key = [], []

# model sources: use the generated text
for tag, fname in SOURCES.items():
    data = load(fname)
    for d in stratified_pick(data, N_PER_SOURCE):
        items.append({"instruction": d["instruction"],
                      "scenario": d["generated"]})
        key.append({"source": tag, "orig_id": d["id"],
                    "sector": d.get("sector"), "workshop": d.get("workshop")})

# human reference: take from the fine-tuned file's reference field (the ground truth)
ref_data = load(SOURCES["A_finetuned"])
for d in stratified_pick(ref_data, N_PER_SOURCE):
    items.append({"instruction": d["instruction"],
                  "scenario": d["reference"]})
    key.append({"source": "D_human_reference", "orig_id": d["id"],
                "sector": d.get("sector"), "workshop": d.get("workshop")})

# shuffle into final order and assign blind item ids
order = list(range(len(items)))
random.shuffle(order)

blind = [{"item_id": f"S{n+1:02d}", **items[i]} for n, i in enumerate(order)]
answer_key = [{"item_id": f"S{n+1:02d}", **key[i]} for n, i in enumerate(order)]

(EVAL / "expert_package_blind.json").write_text(
    json.dumps(blind, indent=2, ensure_ascii=False), encoding="utf-8")
(EVAL / "expert_package_key.json").write_text(
    json.dumps(answer_key, indent=2), encoding="utf-8")

# report composition (without revealing which item is which)
from collections import Counter
comp = Counter(k["source"] for k in answer_key)
print(f"Built {len(blind)} blind items ({SEED=}):")
for src, n in sorted(comp.items()):
    print(f"  {src:20} {n}")
print(f"\n  expert_package_blind.json  -> goes into each evaluator's sheet")
print(f"  expert_package_key.json    -> KEEP PRIVATE, never send")
print("\nNext: python scripts\\evaluation\\fill_expert_sheets.py")
