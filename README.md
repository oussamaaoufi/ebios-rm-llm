# EBIOS-RM-LLM

Fine-tuning an open large language model to generate **EBIOS Risk Manager (EBIOS-RM)** cybersecurity risk scenarios grounded in **MITRE ATT&CK**.

This repository accompanies the paper *"EBIOS-RM-LLM: A Fine-Tuned Large Language Model for Automated Cybersecurity Risk Scenario Generation within the EBIOS Risk Manager Framework"* and contains the full pipeline: dataset generation, the MITRE label correction, fine-tuning, and the in-distribution and external-validity evaluations.

---

## What this is

We build a domain-specific dataset of **5,001 labelled EBIOS-RM scenarios** (Workshops 2–4, five sectors) using a **deterministic, template-based generator** (no language model is involved in dataset construction), correct a systematic MITRE-label error affecting 98.4% of the technique names, and fine-tune **Llama-3.3-70B** with LoRA. We evaluate against the unadapted base model and a frontier commercial model, both in-distribution and on **15 real-world incidents** drawn from official CISA advisories.

**Key results (in-distribution, 100 held-out scenarios):**
- Composite score: fine-tuned **0.888** vs raw Llama 0.816 vs GPT-5.5 0.701
- MITRE technique-name accuracy: **100%** vs 53% vs 95.3%
- Controlled ablation (label correction): **5.0% → 100%** MITRE accuracy, same model and test set

**Honest external finding (15 real incidents):** the fine-tuned model keeps 100% naming accuracy but selects fitting techniques less often than the general model (precision 0.10 vs 0.37), having learned sector-level templates rather than incident-specific reasoning — an instance of the synthetic-data / model-collapse phenomenon.

---

## Repository structure

```
ebios-rm-llm/
├── README.md
├── LICENSE
├── requirements.txt
├── CITATION.cff
├── config.py                     # central paths & settings (edit BASE_DIR here)
│
├── data_collection/
│   ├── collect_mitre.py          # MITRE ATT&CK (Enterprise + ICS) from the CTI repo
│   ├── collect_cve.py            # sector CVEs from the NIST NVD API 2.0
│   └── build_incidents.py        # the 10 documented training incidents
│
├── data_generation/
│   ├── sector_profiles.py        # the five hand-authored sector profiles
│   ├── dataset_generator.py      # the deterministic template generator (seed=42)
│   ├── quality_control.py        # field/length/MITRE-tag quality checks
│   ├── finetuning_formatter.py   # serialise to conversational training format
│   └── fix_mitre_names.py        # the MITRE label correction (see the ablation)
│
├── finetuning/
│   ├── build_splits.py           # stratified 4801 / 100 / 100 split
│   ├── run_finetune_uncorrected.py   # run 2 — trained on uncorrected labels (ablation "before")
│   └── run_finetune_corrected.py     # run 3 — final model (ablation "after")
│
├── evaluation/
│   ├── query_finetuned_endpoint.py   # fine-tuned model inference (dedicated endpoint)
│   ├── run_baselines.py          # raw Llama + GPT-5.5 with a schema exemplar
│   ├── compute_metrics.py        # BLEU, ROUGE, BERTScore, EBIOS-compliance, MITRE accuracy
│   ├── aggregate.py              # builds the result tables
│   ├── stats_tests.py            # Wilcoxon, rank-biserial, bootstrap 95% CIs
│   └── make_figures.py           # the figures
│
├── external_validity/
│   ├── external_incidents.json   # the 15 verified incidents + advisory technique lists
│   ├── build_external_tasks.py   # turns incidents into Workshop-4 tasks
│   ├── run_external_eval.py      # runs the three models on the 15 incidents
│   └── score_external.py         # technique-precision metric vs advisory ground truth
│
├── docs/expert_evaluation/       # instruments for the (separate) blind human study
│   ├── build_expert_package.py
│   └── make_expert_docs.py
│
└── utils/
    └── logger.py
```

---

## Requirements

```bash
pip install -r requirements.txt
```

Python 3.11 is recommended. Fine-tuning and inference use the [Together](https://www.together.ai/) API; the GPT-5.5 baseline uses the OpenAI API. Set your keys as environment variables (never commit them):

```bash
export TOGETHER_API_KEY=...
export OPENAI_API_KEY=...
export NVD_API_KEY=...        # optional, raises the NVD rate limit
```

Steps that need network/API access are marked below; the rest run offline.

---

## Reproducing the results

All paths are resolved from `config.py` — set `BASE_DIR` there once.

**1. Collect the threat data** *(needs network)*
```bash
python data_collection/collect_mitre.py      # MITRE ATT&CK
python data_collection/collect_cve.py        # NVD CVEs (slow without an API key)
python data_collection/build_incidents.py    # training incidents
```

**2. Generate and correct the dataset** *(offline, deterministic)*
```bash
python data_generation/dataset_generator.py  # writes the 5,001 scenarios
python data_generation/quality_control.py    # verifies 100% pass
python data_generation/fix_mitre_names.py     # corrects the MITRE labels
python data_generation/finetuning_formatter.py
python finetuning/build_splits.py            # 4801 / 100 / 100
```

**3. Fine-tune** *(needs the Together API; incurs cost)*
```bash
python finetuning/run_finetune_corrected.py  # the final model (run 3)
# For the ablation "before" condition:
python finetuning/run_finetune_uncorrected.py
```

**4. Evaluate in-distribution** *(needs API access)*
```bash
python evaluation/query_finetuned_endpoint.py   # deploy the endpoint first; delete after
python evaluation/run_baselines.py
python evaluation/compute_metrics.py
python evaluation/aggregate.py
python evaluation/stats_tests.py
python evaluation/make_figures.py
```

**5. External validity** *(needs API access)*
```bash
python external_validity/build_external_tasks.py
python external_validity/run_external_eval.py
python external_validity/score_external.py
```

> **Cost & endpoint note.** The fine-tuned model requires a dedicated Together endpoint billed by the minute. Deploy it, run the inference step, and **delete it immediately**. Baseline queries are serverless and inexpensive.

---

## Data and model availability

- The generated dataset is derived entirely from public sources (MITRE ATT&CK, NIST NVD) via the deterministic generator here, and can be regenerated exactly with `seed = 42`.
- The external-validity ground truth is transcribed from public CISA advisories; the advisory identifiers are listed in `external_validity/external_incidents.json`.
- Fine-tuned model weights are hosted on the Together platform and are not redistributed here; the training configuration is fully specified in `finetuning/`.

## What is intentionally **not** included

- API keys or any `.env` file.
- The expert-evaluation answer key (kept private to preserve blind scoring).
- Fine-tuned model weights (see above).

---

## Citation

If you use this work, please cite the paper (see `CITATION.cff`):

```
O. Aoufi and A. Rahmani, "EBIOS-RM-LLM: A Fine-Tuned Large Language Model for
Automated Cybersecurity Risk Scenario Generation within the EBIOS Risk Manager
Framework," 2026.
```

## License

Released under the MIT License (see `LICENSE`). MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Advisory content referenced in the external-validity set is the property of CISA and the cited agencies.
