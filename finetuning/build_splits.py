"""
build_splits.py
---------------
Creates the held-out splits that run 1 lacked.

Stratified by (sector, workshop) so every split mirrors the full distribution:
    train_clean.json   4801 samples  -> run 2 training
    val_clean.json      100 samples  -> validation loss during training
    test_clean.json     100 samples  -> Phase 5 evaluation, NEVER seen in training

Also emits the legacy *_ready.json variants (pre-tokenised text format) in case
anything downstream still expects them.

Report in the paper as: "4801 / 100 / 100 stratified by sector and workshop, seed 42."

Run:
    cd D:\\phd\\ebios_phd_thesis
    .\\start.ps1
    python scripts\\build_splits.py
"""

import json
import random
from collections import defaultdict, Counter
from pathlib import Path

from config import BASE_DIR as BASE
FINAL = BASE / "final_dataset"
PROC  = BASE / "processed_data"

SEED = 42
N_TEST_PER_CELL = 4     # 5 sectors x 5 workshop-values... see below
N_VAL_PER_CELL  = 4

random.seed(SEED)


# ---------------------------------------------------------------- load
def load(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("samples", data)
    return data


clean_path = PROC / "dataset_clean.json"
ready_path = FINAL / "finetuning_ready.json"

if not clean_path.exists():
    raise SystemExit(f"Missing {clean_path}. Phase 3 output is required.")

clean = load(clean_path)
print(f"dataset_clean.json      : {len(clean)} samples")

ready = None
if ready_path.exists():
    ready = load(ready_path)
    print(f"finetuning_ready.json   : {len(ready)} samples")
    if len(ready) != len(clean):
        print("  WARNING: lengths differ. Index alignment between the two files")
        print("  cannot be assumed. Only the *_clean.json outputs will be trusted.")
        ready = None
else:
    print("finetuning_ready.json   : not found (fine — run 2 does not need it)")


# ---------------------------------------------------------------- stratify
buckets = defaultdict(list)
for i, s in enumerate(clean):
    buckets[(s.get("sector"), s.get("workshop"))].append(i)

print(f"\nStrata: {len(buckets)} (sector x workshop cells)")
for key in sorted(buckets, key=lambda k: (str(k[0]), str(k[1]))):
    print(f"  {str(key):<30} {len(buckets[key])} samples")

# Per-cell quota so the totals land on 100/100 regardless of cell count
n_cells = len(buckets)
test_per_cell = max(1, round(100 / n_cells))
val_per_cell  = max(1, round(100 / n_cells))
print(f"\nTaking {test_per_cell} test + {val_per_cell} val per cell "
      f"({n_cells} cells)")

test_idx, val_idx = [], []
for key, idxs in sorted(buckets.items(), key=lambda kv: str(kv[0])):
    pool = idxs[:]
    random.shuffle(pool)
    if len(pool) < test_per_cell + val_per_cell:
        raise SystemExit(f"Cell {key} has only {len(pool)} samples — too small to split.")
    test_idx += pool[:test_per_cell]
    val_idx  += pool[test_per_cell:test_per_cell + val_per_cell]

# Trim or top up to exactly 100 each, keeping stratification as even as possible
def resize(idx_list, target, exclude):
    idx_list = idx_list[:]
    random.shuffle(idx_list)
    if len(idx_list) > target:
        return idx_list[:target]
    pool = [i for i in range(len(clean)) if i not in exclude and i not in idx_list]
    random.shuffle(pool)
    return idx_list + pool[: target - len(idx_list)]

test_idx = resize(test_idx, 100, set(val_idx))
val_idx  = resize(val_idx, 100, set(test_idx))

held = set(test_idx) | set(val_idx)
assert not (set(test_idx) & set(val_idx)), "test and val overlap"
train_idx = [i for i in range(len(clean)) if i not in held]


# ---------------------------------------------------------------- write
def dump(name, idxs, source):
    out = FINAL / name
    out.write_text(
        json.dumps([source[i] for i in idxs], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"  {name:<22} {len(idxs):>5} samples   ({out.stat().st_size/1_048_576:.1f} MB)")


FINAL.mkdir(parents=True, exist_ok=True)
print("\nWriting splits:")
dump("train_clean.json", train_idx, clean)
dump("val_clean.json",   val_idx,   clean)
dump("test_clean.json",  test_idx,  clean)

if ready is not None:
    dump("train_ready.json", train_idx, ready)
    dump("val_ready.json",   val_idx,   ready)
    dump("test_ready.json",  test_idx,  ready)


# ---------------------------------------------------------------- verify
print("\nVerification:")
print(f"  total          : {len(train_idx) + len(val_idx) + len(test_idx)} "
      f"(expected {len(clean)})")
print(f"  train/val/test : {len(train_idx)} / {len(val_idx)} / {len(test_idx)}")
print(f"  no overlap     : {len(set(train_idx) & held) == 0}")

print("\n  Test set composition:")
for key, n in sorted(Counter((clean[i].get("sector"), clean[i].get("workshop"))
                             for i in test_idx).items(), key=lambda kv: str(kv[0])):
    print(f"    {str(key):<30} {n}")

manifest = {
    "seed": SEED,
    "source": str(clean_path),
    "n_total": len(clean),
    "n_train": len(train_idx),
    "n_val": len(val_idx),
    "n_test": len(test_idx),
    "stratified_by": ["sector", "workshop"],
    "test_ids":  [clean[i].get("id") for i in test_idx],
    "val_ids":   [clean[i].get("id") for i in val_idx],
}
(BASE / "evaluation_results").mkdir(exist_ok=True)
(BASE / "evaluation_results" / "split_manifest.json").write_text(
    json.dumps(manifest, indent=2), encoding="utf-8"
)
print("\n  split_manifest.json written — cite these IDs in supplementary material.")
print("\nNext: python scripts\\run2_finetune_corrected.py")
