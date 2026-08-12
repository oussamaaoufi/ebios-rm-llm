# Part of the EBIOS-RM-LLM pipeline.

import sys
import json
from pathlib import Path
from collections import Counter
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.utils.paths  import PROCESSED_DIR, save_json, load_json
from scripts.utils.logger import get_logger, print_success, print_warning

logger = get_logger('quality_control', 'quality_control.log')


class QualityController:

    # Minimum word counts per workshop type
    MIN_INSTRUCTION_WORDS = {
        'ro_to_identification': 60,
        'strategic_scenario':   80,
        'operational_scenario': 80
    }

    # Required output fields per type
    REQUIRED_OUTPUT_FIELDS = {
        'ro_to_identification': ['ro_to_pair'],
        'strategic_scenario':   ['scenario_id', 'risk_origin', 'attack_paths', 'severity'],
        'operational_scenario': ['scenario_id', 'attack_sequence', 'likelihood']
    }

    # Required attack sequence phases
    REQUIRED_PHASES = ['knowing', 'entering', 'finding', 'exploiting']

    def check_sample(self, sample: dict) -> list:
        """Check one sample — returns list of issues (empty = passed)"""

        issues = []
        s_type = sample.get('type', '')

        # Basic fields
        for field in ['id', 'workshop', 'sector', 'type', 'instruction', 'output']:
            if not sample.get(field):
                issues.append(f'missing_{field}')

        if issues:
            return issues

        # Instruction length
        words    = len(sample['instruction'].split())
        min_words = self.MIN_INSTRUCTION_WORDS.get(s_type, 50)
        if words < min_words:
            issues.append(f'instruction_too_short_{words}_words')

        # Output fields
        output   = sample.get('output', {})
        required = self.REQUIRED_OUTPUT_FIELDS.get(s_type, [])
        for field in required:
            if not output.get(field):
                issues.append(f'output_missing_{field}')

        # Operational scenario: check all 4 phases
        if s_type == 'operational_scenario':
            seq = output.get('attack_sequence', {})
            for phase in self.REQUIRED_PHASES:
                if phase not in seq:
                    issues.append(f'missing_phase_{phase}')
                elif not seq[phase].get('mitre_id'):
                    issues.append(f'missing_mitre_id_in_{phase}')

        # Strategic scenario: check attack paths
        if s_type == 'strategic_scenario':
            paths = output.get('attack_paths', [])
            if len(paths) < 1:
                issues.append('no_attack_paths')
            else:
                for p in paths:
                    if not p.get('steps'):
                        issues.append('attack_path_missing_steps')

        return issues

    def run(self, input_path: Path, output_path: Path) -> dict:
        """Run quality control on full dataset"""

        data    = load_json(input_path)
        samples = data.get('samples', data) \
                  if isinstance(data, dict) else data

        logger.info(f'QC on {len(samples)} samples...')

        clean    = []
        removed  = []
        issue_counts = Counter()

        for sample in tqdm(samples, desc='  QC', ncols=70):
            issues = self.check_sample(sample)
            if not issues:
                clean.append(sample)
            else:
                removed.append({'id': sample.get('id'), 'issues': issues})
                for issue in issues:
                    issue_counts[issue] += 1

        pass_rate = len(clean) / len(samples) * 100

        # Save clean dataset
        clean_data = {
            'version':    '1.0_clean',
            'created_at': __import__('datetime').datetime.now().isoformat(),
            'total':      len(clean),
            'removed':    len(removed),
            'pass_rate':  f'{pass_rate:.1f}%',
            'samples':    clean
        }
        save_json(clean_data, output_path)

        result = {
            'total_input':   len(samples),
            'total_clean':   len(clean),
            'total_removed': len(removed),
            'pass_rate':     pass_rate,
            'top_issues':    issue_counts.most_common(10)
        }

        # Print report
        print_success(f'Passed:   {len(clean)} ({pass_rate:.1f}%)')
        print_warning(f'Removed:  {len(removed)}')
        if issue_counts:
            print('\n  Top issues:')
            for issue, count in issue_counts.most_common(5):
                print(f'    {issue}: {count}')

        return result