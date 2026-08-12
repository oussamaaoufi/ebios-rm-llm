"""
run_external_eval.py
--------------------
Runs the external-validity tasks (15 real incidents) through the three models
and saves their generated scenarios. Reuses the same query logic and settings as
the in-distribution evaluation, so the comparison is apples-to-apples.

The fine-tuned model needs a DEDICATED ENDPOINT (deploy from the dashboard,
then set ENDPOINT_MODEL below). Baselines are serverless.

USAGE — two phases so you control endpoint cost:

  # Phase 1: baselines (serverless, cheap, ~$1). No endpoint needed.
  python scripts\\evaluation\\run_external_eval.py baselines

  # Phase 2: fine-tuned model. Deploy the endpoint first, set ENDPOINT_MODEL,
  # run this, then DELETE the endpoint immediately.
  python scripts\\evaluation\\run_external_eval.py finetuned
"""

import os
import sys
import json
import time
from pathlib import Path
from together import Together

from config import BASE_DIR as BASE
EVAL = BASE / "evaluation_results"
FINAL = BASE / "final_dataset"

# ---- set this to your endpoint's model name when running 'finetuned' ----
ENDPOINT_MODEL = "oussamaaoufi43-1a49/finetuned-llm"
# -------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are an expert cybersecurity risk analyst specialized in EBIOS-RM. "
    "Generate technically accurate, sector-specific risk scenarios following "
    "EBIOS-RM methodology. Always reference MITRE ATT&CK technique IDs."
)

together = Together(api_key=os.environ["TOGETHER_API_KEY"])
openai_client = None
if os.environ.get("OPENAI_API_KEY"):
    import openai
    openai_client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])

tasks = json.loads((EVAL / "external_tasks.json").read_text(encoding="utf-8"))
print(f"External tasks: {len(tasks)}")

# schema exemplar for baselines (from TRAIN split, no leakage) — WS4 example
train = json.loads((FINAL / "train_clean.json").read_text(encoding="utf-8"))
ws4_example = next((s["output"] for s in train if s.get("workshop") == 4), None)
ws4_example = ws4_example if isinstance(ws4_example, str) else json.dumps(ws4_example, ensure_ascii=False, indent=2)


def q_together(model, instruction, schema=False):
    user = instruction
    if schema:
        user = (f"Here is an example of the required Workshop 4 JSON structure:\n\n"
                f"{ws4_example}\n\nNow produce a JSON object with the SAME structure "
                f"for the following task. Return ONLY the JSON.\n\n{instruction}")
    for attempt in range(4):
        try:
            r = together.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": SYSTEM_PROMPT},
                          {"role": "user", "content": user}],
                max_tokens=1500, temperature=0.3)
            return r.choices[0].message.content, None
        except Exception as e:
            if "not ready" in str(e).lower() or "503" in str(e):
                print("  endpoint warming, wait 30s..."); time.sleep(30); continue
            if attempt == 3:
                return "", str(e)
            time.sleep(8 * (attempt + 1))


def q_openai(instruction):
    user = (f"Here is an example of the required Workshop 4 JSON structure:\n\n"
            f"{ws4_example}\n\nNow produce a JSON object with the SAME structure for the "
            f"following task. Return ONLY the JSON.\n\n{instruction}")
    try:
        r = openai_client.chat.completions.create(
            model="gpt-5.5",
            messages=[{"role": "system", "content": SYSTEM_PROMPT},
                      {"role": "user", "content": user}],
            max_completion_tokens=8000, reasoning_effort="low")
        return r.choices[0].message.content, None
    except Exception as e:
        return "", str(e)


def run(model_key, fn):
    out_path = EVAL / f"external_outputs_{model_key}.json"
    results = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else []
    done = {r["id"] for r in results}
    for i, t in enumerate(tasks):
        if t["id"] in done:
            continue
        text, err = fn(t["instruction"])
        results.append({
            "id": t["id"], "sector": t["sector"], "workshop": 4,
            "source_incident": t["source_incident"], "advisory": t["advisory"],
            "instruction": t["instruction"],
            "reference_techniques": t["reference_techniques"],
            "generated": text, "error": err,
        })
        out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  [{i+1}/{len(tasks)}] {t['id']} {'ERR' if err else str(len(text))+'c'}")
        time.sleep(0.3)
    print(f"  saved -> {out_path}\n")


mode = sys.argv[1] if len(sys.argv) > 1 else "baselines"

if mode == "baselines":
    print("=== Raw Llama-3.3 (schema) ===")
    run("llama_raw", lambda ins: q_together("meta-llama/Llama-3.3-70B-Instruct-Turbo", ins, schema=True))
    if openai_client:
        print("=== GPT-5.5 (schema) ===")
        run("gpt_5_5", q_openai)
    else:
        print("OPENAI_API_KEY not set — skipping GPT-5.5.")

elif mode == "finetuned":
    print(f"=== Fine-tuned (endpoint: {ENDPOINT_MODEL}) ===")
    run("finetuned", lambda ins: q_together(ENDPOINT_MODEL, ins, schema=False))
    print("\n*** DELETE THE ENDPOINT NOW in the dashboard — it bills per minute ***")

else:
    print("Usage: python run_external_eval.py [baselines|finetuned]")
