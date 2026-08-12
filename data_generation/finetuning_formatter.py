# Part of the EBIOS-RM-LLM pipeline.

import sys
import json
from pathlib import Path
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.utils.paths  import FINAL_DIR, save_json, load_json
from scripts.utils.logger import get_logger, print_success

logger = get_logger('formatter', 'formatter.log')

SYSTEM_PROMPT = (
    'You are an expert cybersecurity risk analyst specialized in '
    'EBIOS Risk Manager (EBIOS-RM). Generate technically accurate, '
    'sector-specific risk scenarios strictly following EBIOS-RM '
    'methodology. Always reference MITRE ATT&CK technique IDs. '
    'All outputs must be structured JSON following EBIOS-RM requirements.'
)


def prepare_finetuning(clean_path: Path) -> Path:

    data    = load_json(clean_path)
    samples = data.get('samples', [])

    formatted = []
    for s in tqdm(samples, desc='  Formatting', ncols=70):
        text = (
            '<|begin_of_text|>'
            '<|start_header_id|>system<|end_header_id|>\n'
            f'{SYSTEM_PROMPT}<|eot_id|>\n'
            '<|start_header_id|>user<|end_header_id|>\n'
            f'{s["instruction"]}<|eot_id|>\n'
            '<|start_header_id|>assistant<|end_header_id|>\n'
            f'{json.dumps(s["output"], indent=2, ensure_ascii=False)}<|eot_id|>'
        )
        formatted.append({
            'text':     text,
            'type':     s['type'],
            'sector':   s['sector'],
            'workshop': s['workshop']
        })

    out_path = FINAL_DIR / 'finetuning_ready.json'
    FINAL_DIR.mkdir(parents=True, exist_ok=True)
    save_json(formatted, out_path)

    size_mb = out_path.stat().st_size / 1024 / 1024
    print_success(f'Fine-tuning file: {out_path}')
    print_success(f'Samples:          {len(formatted)}')
    print_success(f'File size:         {size_mb:.1f} MB')

    return out_path