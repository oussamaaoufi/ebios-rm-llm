"""
run_finetune_corrected.py
----------------
Phase 4, run 3 — full training on MITRE-corrected data. Fixes every issue found in run 1:

  ISSUE-1  flat loss            -> learning_rate 1e-4, 3 epochs, lora_r 32
  ISSUE-2  train_on_inputs=True -> conversational JSONL so instruction tokens are masked
  ISSUE-3  no held-out data     -> 4801 / 100 / 100 split, validation_file attached
  ISSUE-4  defaults silently    -> every hyperparameter explicit + verified after submit
  ISSUE-5  base retired         -> migrate to the Llama 3.3 70B LoRA-serving base

Prerequisites:
    python scripts\\build_splits.py        (creates train_clean.json / val_clean.json)
    pip install wandb                      (per-step loss; run 1 had none)

Run:
    python scripts\\run2_finetune_corrected.py
"""

import os
import json
import time
from pathlib import Path
from together import Together

# ============================================================== CONFIGURATION
# (everything referenced later is defined here, before first use)

from config import BASE_DIR as BASE
EVAL = BASE / "evaluation_results"
FINAL = BASE / "final_dataset"
EVAL.mkdir(parents=True, exist_ok=True)

# Run 1 used meta-llama/Meta-Llama-3.1-70B-Reference. That base was retired from
# serverless inference, leaving its adapter unqueryable without a dedicated
# endpoint. Run 2 migrates to the Llama 3.3 70B fine-tuning base.
#
# Per docs.together.ai/docs/fine-tuning/supported-models, this base supports:
#   LoRA SFT | context 24576 | max batch 8 | max LoRA rank 64
# (Llama-3.3-70B-Instruct-FP8-Lora is a SERVING base, not a fine-tuning base —
#  passing it to fine_tuning.create returns 404.)
BASE_MODEL = "meta-llama/Llama-3.3-70B-Instruct-Reference"

# Documented limits for BASE_MODEL — the script asserts against these below.
MAX_LORA_RANK = 64
MAX_BATCH_SFT = 8
MAX_CONTEXT_SFT = 24576

# PROBE_MODE: 50 samples, 1 epoch, ~$0.50. Run this FIRST to confirm the
# resulting adapter answers serverlessly. Only set False once check_models.py
# reports [ OK ] for the probe adapter.
PROBE_MODE = False   # RUN 3: full training on corrected data

PROBE_SAMPLES = 50

SYSTEM_PROMPT = (
    "You are an expert cybersecurity risk analyst specialized in EBIOS-RM. "
    "Generate technically accurate, sector-specific risk scenarios following "
    "EBIOS-RM methodology. Always reference MITRE ATT&CK technique IDs."
)

client = Together(api_key=os.environ["TOGETHER_API_KEY"], timeout=1200.0)  # 20 min for slow uploads

print("=" * 68)
print(f"  MODE       : {'PROBE (50 samples, 1 epoch, ~$0.50)' if PROBE_MODE else 'FULL RUN (~$45)'}")
print(f"  BASE MODEL : {BASE_MODEL}")
print("=" * 68)


# ============================================================== 1. CONVERSATIONAL JSONL
def to_conversational(in_json, out_jsonl):
    """
    Writes the 'messages' format, which is what enables instruction masking.
    Reads dataset_clean-style records (instruction + output dict), NOT the
    pre-tokenised text field that triggered the general-format fallback in run 1.
    """
    samples = json.loads(Path(in_json).read_text(encoding="utf-8"))
    if isinstance(samples, dict):
        samples = samples.get("samples", samples)

    n = 0
    with open(out_jsonl, "w", encoding="utf-8") as f:
        for s in samples:
            out = s["output"]
            assistant = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False, indent=2)
            rec = {"messages": [
                {"role": "system",    "content": SYSTEM_PROMPT},
                {"role": "user",      "content": s["instruction"]},
                {"role": "assistant", "content": assistant},
            ]}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    print(f"  {Path(out_jsonl).name}: {n} records")
    return Path(out_jsonl)


print("\nBuilding conversational JSONL ...")
train_jsonl = to_conversational(FINAL / "train_clean.json", FINAL / "train_conv.jsonl")
val_jsonl = to_conversational(FINAL / "val_clean.json", FINAL / "val_conv.jsonl")

if PROBE_MODE:
    probe_path = FINAL / "train_probe.jsonl"
    lines = open(train_jsonl, encoding="utf-8").readlines()[:PROBE_SAMPLES]
    probe_path.write_text("".join(lines), encoding="utf-8")
    train_jsonl = probe_path
    print(f"  PROBE MODE: sliced to {PROBE_SAMPLES} samples -> {probe_path.name}")

# Verify format before spending anything
first = json.loads(open(train_jsonl, encoding="utf-8").readline())
assert "messages" in first, "format check failed: no 'messages' key"
assert len(first["messages"]) == 3, "format check failed: expected 3 turns"
assert [m["role"] for m in first["messages"]] == ["system", "user", "assistant"]
print("  format check passed: messages array, 3 turns, correct roles")


# ============================================================== 2. WEIGHTS & BIASES
# Run 1 produced NO retrievable per-step loss because no W&B project was
# attached. Without this, Figure 2 can only come from screenshots again.
WANDB_KEY = os.environ.get("WANDB_API_KEY", "")
if not WANDB_KEY:
    print("\n  WARNING: WANDB_API_KEY is not set.")
    print("  Per-step loss will NOT be retrievable via the API — exactly the")
    print("  gap that left run 1 with only a dashboard screenshot.")
    if input("  Continue without it? [y/N] ").strip().lower() != "y":
        raise SystemExit("Aborted. Set WANDB_API_KEY and re-run.")


# ============================================================== 3. UPLOAD
# ============================================================== PRE-FLIGHT
# The docs warn that some bases can be fine-tuned but cannot host the result.
# A 404 here means the adapter would have nowhere to be deployed.
print("\nPre-flight: checking deployability of the base ...")
try:
    hw = client.endpoints.list_hardware(model=BASE_MODEL)
    opts = getattr(hw, "data", hw)
    print(f"  OK — {len(list(opts))} hardware configuration(s) available")
except Exception as e:
    print(f"  WARNING: {str(e)[:160]}")
    print("  This base may not be able to host a fine-tuned deployment.")
    if input("  Continue anyway? [y/N] ").strip().lower() != "y":
        raise SystemExit("Aborted.")


def upload(path):
    """
    Upload with retries. Large files on slow links can hit WriteTimeout; retry
    a few times before giving up. Handles both new (path) and old (tuple) SDK
    signatures.
    """
    path = Path(path)
    last = None
    for attempt in range(4):
        try:
            try:
                return client.files.upload(file=str(path), purpose="fine-tune")
            except TypeError:
                with open(path, "rb") as f:
                    return client.files.upload(file=(path.name, f), purpose="fine-tune")
        except Exception as e:
            last = e
            print(f"  upload attempt {attempt+1} failed ({type(e).__name__}); retrying in 15s ...")
            import time; time.sleep(15)
    raise last


print("\nUploading datasets ...")
train_file = upload(train_jsonl)
val_file = upload(val_jsonl)
print(f"  train: {train_file.id}")
print(f"  val:   {val_file.id}")


# ============================================================== 4. SUBMIT
CONFIG = dict(
    model=BASE_MODEL,
    training_file=train_file.id,
    validation_file=val_file.id,
    n_evals=12,                              # validation loss points -> Figure 2
    lora=True,
    lora_r=32,                               # run 1 used 8
    lora_alpha=64,                           # 2 x rank
    lora_dropout=0.05,
    n_epochs=1 if PROBE_MODE else 3,         # run 1 used 1
    learning_rate=1e-4,                      # run 1 used 1e-5
    warmup_ratio=0.05,                       # run 1 used 0
    batch_size=8,
    train_on_inputs=False,                   # THE key fix
    suffix="ebios-rm-phd-run3",
)
assert CONFIG["lora_r"] <= MAX_LORA_RANK, f"lora_r exceeds {MAX_LORA_RANK} for {BASE_MODEL}"
assert CONFIG["batch_size"] <= MAX_BATCH_SFT, f"batch_size exceeds {MAX_BATCH_SFT} for {BASE_MODEL}"

if WANDB_KEY:
    CONFIG["wandb_api_key"] = WANDB_KEY
    CONFIG["wandb_project_name"] = "ebios-rm-phd"

print("\nSubmitting with:")
for k, v in CONFIG.items():
    if k == "wandb_api_key":
        v = "***set***"
    print(f"  {k:>20} : {v}")

ft = client.fine_tuning.create(**CONFIG)
print(f"\nJob created: {ft.id}")


# ============================================================== 5. VERIFY
# Run 1 silently executed on Together defaults. Never trust the submission;
# read the config back from the API and compare field by field.
print("\nVerifying accepted configuration ...")
time.sleep(5)
back = client.fine_tuning.retrieve(ft.id)
b = back.model_dump() if hasattr(back, "model_dump") else dict(back)

tt = b.get("training_type") or {}
tm = b.get("training_method") or {}
actual = {
    "model":           b.get("model"),
    "n_epochs":        b.get("n_epochs"),
    "learning_rate":   b.get("learning_rate"),
    "batch_size":      b.get("batch_size"),
    "warmup_ratio":    b.get("warmup_ratio"),
    "lora_r":          tt.get("lora_r"),
    "lora_alpha":      tt.get("lora_alpha"),
    "lora_dropout":    tt.get("lora_dropout"),
    "train_on_inputs": tm.get("train_on_inputs"),
    "validation_file": b.get("validation_file"),
    "n_evals":         b.get("n_evals"),
    "suffix":          b.get("suffix"),
    "wandb_url":       b.get("wandb_url"),
}
expected = {
    "n_epochs": 1 if PROBE_MODE else 3,
    "learning_rate": 1e-4,
    "batch_size": 8,
    "warmup_ratio": 0.05,
    "lora_r": 32,
    "lora_alpha": 64,
    "lora_dropout": 0.05,
}

ok = True
for k, v in actual.items():
    exp = expected.get(k)
    flag = ""
    if exp is not None and v != exp:
        flag = f"   <-- MISMATCH, expected {exp}"
        ok = False
    print(f"  {k:>18} : {v}{flag}")

if actual["train_on_inputs"] in (True, "true", "auto"):
    print("\n  *** train_on_inputs is not False — the masking fix did NOT apply. ***")
    ok = False
if not actual["validation_file"]:
    print("\n  *** No validation file attached. ***")
    ok = False

if not ok:
    print("\n  CANCEL THIS JOB NOW before it consumes budget:")
    print(f"    python -c \"import os;from together import Together;"
          f"Together(api_key=os.environ['TOGETHER_API_KEY'])"
          f".fine_tuning.cancel('{ft.id}')\"")
else:
    print("\n  Configuration verified — job is running as intended.")


# ============================================================== 6. PERSIST
out_name = "together_job_run3.json"
info = {
    "run_label":         "probe_3.3_lora" if PROBE_MODE else "run2_corrected",
    "job_id":            ft.id,
    "base_model":        BASE_MODEL,
    "probe_mode":        PROBE_MODE,
    "train_file_id":     train_file.id,
    "val_file_id":       val_file.id,
    "config":            {k: ("***" if k == "wandb_api_key" else v) for k, v in CONFIG.items()},
    "verified_config":   actual,
    "config_verified_ok": ok,
    "submitted_at":      time.strftime("%Y-%m-%dT%H:%M:%S"),
    "supersedes":        "ft-b6d3f937-8b03",
}
(EVAL / out_name).write_text(json.dumps(info, indent=2, default=str), encoding="utf-8")
print(f"\nSaved -> {EVAL / out_name}")

if PROBE_MODE:
    print("\nPROBE RUN submitted. Expected cost ~$0.50.")
    print("When it completes:")
    print("  1. Add the resulting adapter name to TARGETS in check_models.py")
    print("  2. Re-run check_models.py")
    print("  3. Only if it reports [ OK ], set PROBE_MODE = False and run this again")
else:
    print("\nFULL RUN submitted. Expected cost ~$45.")

print("\nMonitor: python scripts\\together_monitor.py")