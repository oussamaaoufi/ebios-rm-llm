"""
build_external_tasks.py
-----------------------
Turns the 15 verified real incidents (external_incidents_normalized.json) into
EBIOS-RM Workshop 4 operational-scenario TASKS, phrased exactly like the training
instructions, so the fine-tuned model and baselines can be run on genuinely
out-of-distribution, real-world cases.

For each incident it produces:
  - instruction : the WS4 prompt (same style as training)
  - reference_techniques : the authoritative advisory technique IDs (ground truth)
  - metadata : id, sector, advisory, url

The reference here is the set of REAL techniques from the CISA advisory. Scoring
uses precision: of the techniques the model names, how many are in this set —
the same logic as the in-distribution mitre_name_accuracy metric.

Run:
    python scripts\\evaluation\\build_external_tasks.py
"""

import json
from pathlib import Path

from config import BASE_DIR as BASE
EVAL = BASE / "evaluation_results"
SRC = EVAL / "external_incidents.json"   # place the normalized file here

SECTOR_ASSET = {
    "healthcare": "patient care systems and electronic health records",
    "finance": "core banking and payment processing systems",
    "energy": "operational technology and grid control systems",
    "government": "citizen data and administrative networks",
    "technology": "cloud services and software delivery infrastructure",
}


def make_instruction(inc):
    sector = inc["sector"]
    name = inc["name"]
    asset = SECTOR_ASSET.get(sector, "critical business systems")
    sid = f"SS-EXT-{inc['id'].split('-')[-1]}"
    oid = f"OS-EXT-{inc['id'].split('-')[-1]}"
    return (
        f"You are an EBIOS-RM expert conducting Workshop 4 (Operational Scenarios) "
        f"for a {sector.upper()} organization.\n\n"
        f"PARENT STRATEGIC SCENARIO:\n"
        f"ID:              {sid}\n"
        f"Title:           Threat actor — {name} campaign against {sector} sector\n"
        f"Risk Origin:     Real-world threat actor ({name})\n"
        f"Target:          Compromise of {asset}\n"
        f"Selected Path:   Real-world attack chain as observed in the {name} campaign\n"
        f"Path Steps:\n"
        f"  1. Reconnaissance and preparation against the {sector} target\n"
        f"  2. Initial access to the environment\n"
        f"  3. Discovery, lateral movement, and privilege escalation\n"
        f"  4. Execution of the threat actor's objective on {asset}\n\n"
        f"TASK: Generate a complete operational scenario with ID {oid} following the "
        f"EBIOS-RM attack sequence model (Knowing -> Entering -> Finding -> Exploiting). "
        f"Include specific MITRE ATT&CK technique IDs, realistic tools, and a likelihood "
        f"assessment using the EBIOS-RM V0-V4 scale."
    )


def main():
    d = json.loads(SRC.read_text(encoding="utf-8"))
    tasks = []
    for inc in d["incidents"]:
        tasks.append({
            "id": inc["id"],
            "sector": inc["sector"],
            "workshop": 4,
            "type": "external_validity",
            "source_incident": inc["name"],
            "advisory": inc["advisory"],
            "url": inc["url"],
            "instruction": make_instruction(inc),
            "reference_techniques": inc["reference_techniques"],  # authoritative ground truth
        })

    out = EVAL / "external_tasks.json"
    out.write_text(json.dumps(tasks, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {len(tasks)} external tasks -> {out}")
    print("Sample instruction:\n")
    print(tasks[0]["instruction"][:500])


if __name__ == "__main__":
    main()
