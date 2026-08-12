"""
query_finetuned_endpoint.py
--------------------------------
Queries an ALREADY-RUNNING dedicated endpoint (created from the Together
dashboard) on the 100 held-out test samples. Does NOT create or delete the
endpoint — you manage its lifecycle in the dashboard. This avoids the
endpoints-create permission problem entirely.

BEFORE RUNNING:
  1. Create the endpoint in the dashboard, wait until it shows READY.
  2. Set MODEL_STRING below to the model name the dashboard shows in its
     inference example (client.chat.completions.create(model="...")).
     It is usually your fine-tuned model name:
        oussamaaoufi43_1a49/Llama-3.3-70B-Instruct-Reference-ebios-rm-phd-run2-03cfec66

AFTER RUNNING:
  Go back to the dashboard and DELETE/STOP the endpoint immediately.
  It bills at ~$21.96/hr for as long as it is running.

Run:
    python scripts\\query_finetuned_endpoint.py
"""

import os
import json
import time
from pathlib import Path
from together import Together

# ============================== SET THIS ==============================
MODEL_STRING = "oussamaaoufi43-1a49/finetuned-llm"
# =====================================================================

from config import BASE_DIR as BASE
EVAL = BASE / "evaluation_results"
FINAL = BASE / "final_dataset"

client = Together(api_key=os.environ["TOGETHER_API_KEY"])

SYSTEM_PROMPT = (
    "You are an expert cybersecurity risk analyst specialized in EBIOS-RM. "
    "Generate technically accurate, sector-specific risk scenarios following "
    "EBIOS-RM methodology. Always reference MITRE ATT&CK technique IDs. "
    "Respond with ONLY a single valid JSON object matching the structure of the "
    "provided example. Do not add markdown, commentary, or text outside the JSON."
)

test = json.loads((FINAL / "test_clean.json").read_text(encoding="utf-8"))
print(f"Model: {MODEL_STRING}")
print(f"Test samples: {len(test)}")


def query(instruction, retries=4):
    for attempt in range(retries):
        try:
            r = client.chat.completions.create(
                model=MODEL_STRING,
                messages=[{"role": "system", "content": SYSTEM_PROMPT},
                          {"role": "user", "content": instruction}],
                max_tokens=1500, temperature=0.3,
            )
            return r.choices[0].message.content, None
        except Exception as e:
            msg = str(e)
            # If the endpoint is still spinning up, wait and retry.
            if "not ready" in msg.lower() or "starting" in msg.lower() or "503" in msg:
                print(f"    endpoint not ready yet, waiting 30s ...")
                time.sleep(30)
                continue
            if attempt == retries - 1:
                return "", msg
            time.sleep(8 * (attempt + 1))
    return "", "exhausted retries"


# quick connectivity check before the loop
print("\nTesting endpoint reachability ...")
probe, err = query("Reply with the single word: ready.")
if err:
    print(f"  Endpoint not reachable: {err}")
    print("  Confirm it shows READY in the dashboard and MODEL_STRING is correct.")
    raise SystemExit
print(f"  Endpoint responding ({len(probe)} chars). Starting run.\n")

out_path = EVAL / "outputs_ebios_70b_finetuned.json"
results = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else []
done = {r["id"] for r in results}

t_start = time.time()
for i, s in enumerate(test):
    if s["id"] in done:
        continue
    t0 = time.time()
    text, err = query(s["instruction"])
    results.append({
        "id": s["id"], "sector": s["sector"], "workshop": s["workshop"],
        "type": s.get("type"), "instruction": s["instruction"],
        "reference": json.dumps(s["output"], ensure_ascii=False, indent=2),
        "generated": text, "latency_s": round(time.time() - t0, 2), "error": err,
    })
    out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  [{i+1}/{len(test)}] {s['id']} {'ERR' if err else str(len(text))+'c'} {results[-1]['latency_s']}s")

mins = (time.time() - t_start) / 60
n_err = sum(1 for r in results if r.get("error"))
print(f"\nDone in {mins:.1f} min. {len(results)} outputs, {n_err} errors.")
print(f"Saved -> {out_path}")
print("\n*** NOW GO DELETE THE ENDPOINT IN THE DASHBOARD — it bills ~$21.96/hr ***")
