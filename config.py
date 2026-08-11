"""
Central configuration for the EBIOS-RM-LLM pipeline.
Set BASE_DIR to wherever you cloned this repository, then all scripts resolve
their input/output paths from here. This replaces the hard-coded absolute
paths used during development.
"""
import os
from pathlib import Path

# --- EDIT THIS: the root of your local copy of the repository/project ---
BASE_DIR = Path(os.environ.get("EBIOS_HOME", Path(__file__).resolve().parent))

# Derived directories (created on demand by the scripts)
RAW_DIR        = BASE_DIR / "raw_data"
PROCESSED_DIR  = BASE_DIR / "processed_data"
FINAL_DIR      = BASE_DIR / "final_dataset"
EVAL_DIR       = BASE_DIR / "evaluation_results"
FIG_DIR        = BASE_DIR / "figures"

# API keys are read from the environment — never hard-code them
TOGETHER_API_KEY = os.environ.get("TOGETHER_API_KEY", "")
OPENAI_API_KEY   = os.environ.get("OPENAI_API_KEY", "")
NVD_API_KEY      = os.environ.get("NVD_API_KEY", "")

# Reproducibility
RANDOM_SEED = 42
SECTORS = ["healthcare", "finance", "energy", "government", "technology"]
