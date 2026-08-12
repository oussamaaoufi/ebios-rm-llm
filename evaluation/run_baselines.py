"""
run_baselines.py
-----------------------
Re-runs the two baselines (raw Llama-3.3, GPT-5.5) WITH a one-shot schema
example in the prompt, so they produce the same JSON structure as the
fine-tuned model. This makes BLEU/ROUGE/JSON-parse a fair comparison.

Design decisions (state these in the paper):
  - The schema example for each workshop is drawn from the TRAIN split, never
    the test split, so no test-set leakage occurs.
  - Same schema example is given to BOTH baselines, identically.
  - The fine-tuned model got NO schema example (zero-shot) -> that difference is
    itself a reported finding (format-adherence advantage of fine-tuning).
  - Decoding: temperature 0.3 for Llama; GPT-5 uses default temp + low reasoning.

Outputs go to NEW files so the zero-shot baselines are preserved:
  outputs_llama_70b_raw_schema.json
  outputs_gpt_5_5_schema.json

Run (safe to run in parallel with run 3 training):
    python scripts\\run_baselines_schema.py
"""

import os
import json
import time
from pathlib import Path
from together import Together

from config import BASE_DIR as BASE
EVAL = BASE / "evaluation_results"
FINAL = BASE / "final_dataset"

SYSTEM_PROMPT = (
    "You are an expert cybersecurity risk analyst specialized in EBIOS-RM. "
    "Generate technically accurate, sector-specific risk scenarios following "
    "EBIOS-RM methodology. Always reference MITRE ATT&CK technique IDs. "
    "Respond with ONLY a single valid JSON object matching the structure of the "
    "provided example. Do not add markdown, commentary, or text outside the JSON."
)

together_client = Together(api_key=os.environ["TOGETHER_API_KEY"])
openai_client = None
if os.environ.get("OPENAI_API_KEY"):
    import openai
    openai_client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])

MODELS = {
    "llama_70b_raw_schema": ("together", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
}
if openai_client:
    MODELS["gpt_5_5_schema"] = ("openai", "gpt-5.5")
else:
    print("OPENAI_API_KEY not set — skipping GPT-5.5 (optional).")

# ---------------------------------------------------------------- schema examples
# One canonical example per workshop, taken from the TRAIN split (no test leakage).
train = json.loads((FINAL / "train_clean.json").read_text(encoding="utf-8"))
schema_example = {}
for s in train:
    ws = s.get("workshop")
    if ws not in schema_example:
        out = s["output"]
        schema_example[ws] = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False, indent=2)
    if len(schema_example) == 3:
        break
print(f"Schema examples ready for workshops: {sorted(schema_example)}")

test = json.loads((FINAL / "test_clean.json").read_text(encoding="utf-8"))
print(f"Test samples: {len(test)}\n")


def build_user_prompt(sample):
    ws = sample["workshop"]
    example = schema_example.get(ws, "")
    return (
        f"Here is an example of the exact JSON structure required for a Workshop {ws} "
        f"response:\n\n{example}\n\n"
        f"Now produce a JSON object with the SAME structure for the following task. "
        f"Return ONLY the JSON object.\n\n{sample['instruction']}"
    )


def query(provider, model_id, prompt, retries=3):
    for attempt in range(retries):
        try:
            if provider == "together":
                r = together_client.chat.completions.create(
                    model=model_id,
                    messages=[{"role": "system", "content": SYSTEM_PROMPT},
                              {"role": "user", "content": prompt}],
                    max_tokens=2000, temperature=0.3,
                )
                return r.choices[0].message.content, None
            else:
                def _call(effort, cap):
                    kw = dict(model=model_id,
                              messages=[{"role": "system", "content": SYSTEM_PROMPT},
                                        {"role": "user", "content": prompt}],
                              max_completion_tokens=cap)
                    if effort:
                        kw["reasoning_effort"] = effort
                    return openai_client.chat.completions.create(**kw)
                rr = _call("low", 8000)
                if not (rr.choices[0].message.content or "").strip():
                    rr = _call("minimal", 12000)
                return rr.choices[0].message.content, None
        except Exception as e:
            msg = str(e)
            if "content" in msg.lower() and "flag" in msg.lower():
                return "", "content_filtered"     # GPT safety refusal — record, move on
            if attempt == retries - 1:
                return "", msg
            time.sleep(8 * (attempt + 1))


for key, (provider, model_id) in MODELS.items():
    out_path = EVAL / f"outputs_{key}.json"
    results = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else []
    done = {r["id"] for r in results}
    print(f"=== {key} ({model_id}) — {len(done)}/{len(test)} done ===")

    for i, s in enumerate(test):
        if s["id"] in done:
            continue
        text, err = query(provider, model_id, build_user_prompt(s))
        results.append({
            "id": s["id"], "sector": s["sector"], "workshop": s["workshop"],
            "type": s.get("type"), "instruction": s["instruction"],
            "reference": json.dumps(s["output"], ensure_ascii=False, indent=2),
            "generated": text, "error": err,
        })
        out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        tag = "ERR:" + (err or "")[:20] if err else f"{len(text)}c"
        print(f"  [{i+1}/{len(test)}] {s['id']} {tag}")
        time.sleep(0.4)
    print(f"  saved -> {out_path}\n")

print("Baselines-with-schema done.")
print("Zero-shot baselines preserved in outputs_llama_70b_raw.json / outputs_gpt_5_5.json")
print("Schema baselines in *_schema.json — use these for the fair BLEU/ROUGE comparison.")
