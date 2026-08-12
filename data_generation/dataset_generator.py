# Part of the EBIOS-RM-LLM pipeline.

import sys
import json
import random
from pathlib import Path
from datetime import datetime
from typing import List, Dict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.utils.paths   import RAW_DIR, load_json
from scripts.utils.logger  import get_logger
from scripts.generators.sector_profiles import get_all_sector_profiles

logger = get_logger('dataset_generator', 'generation.log')


class EBIOSDatasetGenerator:
    """
    Generates 5000+ EBIOS-RM training samples from:
    - MITRE ATT&CK techniques (976)
    - CVE database (474 entries)
    - Real incidents (10 documented cases)
    - Sector profiles (5 sectors)
    """

    def __init__(self):
        logger.info('Loading raw data sources...')

        # Load MITRE data
        self.mitre = load_json(RAW_DIR / 'mitre_complete.json')

        # Load CVE data
        cve_raw  = load_json(RAW_DIR / 'cve_by_sector.json')
        self.cves = {
            k: v for k, v in cve_raw.items()
            if not k.startswith('_')
        }

        # Load incidents
        inc_raw        = load_json(RAW_DIR / 'real_incidents.json')
        self.incidents = inc_raw.get('incidents', inc_raw) \
                         if isinstance(inc_raw, dict) else inc_raw

        # Load sector profiles
        self.profiles = get_all_sector_profiles()
        self.sectors  = list(self.profiles.keys())

        random.seed(42)

        logger.info(f'Ready: {len(self.mitre["techniques"])} techniques, '
                    f'{sum(len(v) for v in self.cves.values())} CVEs, '
                    f'{len(self.incidents)} incidents')

    # ──────────────────────────────────────────────────────────────
    # HELPER METHODS
    # ──────────────────────────────────────────────────────────────

    def _get_sector_incidents(self, sector: str) -> List[Dict]:
        """Get incidents for a sector, fallback to all incidents"""
        matches = [i for i in self.incidents if i.get('sector') == sector]
        return matches if matches else self.incidents

    def _get_sector_cves(self, sector: str, n: int = 3) -> List[Dict]:
        """Get random CVEs for a sector"""
        cves = self.cves.get(sector, [])
        if not cves:
            # Fallback: use CVEs from any sector
            all_cves = [c for v in self.cves.values() for c in v]
            cves     = all_cves
        return random.sample(cves, min(n, len(cves))) if cves else []

    def _get_relevant_techniques(self, tactics: List[str],
                                  n: int = 4) -> List[Dict]:
        """Get MITRE techniques relevant to given tactics"""
        relevant = [
            t for t in self.mitre['techniques']
            if any(tac in t.get('tactics', []) for tac in tactics)
            and t.get('id', '').startswith('T')
        ]
        if not relevant:
            relevant = self.mitre['techniques'][:50]
        return random.sample(relevant, min(n, len(relevant)))

    def _get_apt_group(self, sector: str) -> Dict:
        """Get a realistic threat actor for the sector"""
        profile    = self.profiles[sector]
        ro_profile = random.choice(profile['ro_profiles'])
        return ro_profile

    def _make_id(self, prefix: str, sector: str) -> str:
        return f'{prefix}_{sector[:3].upper()}_{random.randint(1000, 9999)}'

    # ──────────────────────────────────────────────────────────────
    # WORKSHOP 2: RO/TO IDENTIFICATION SAMPLES
    # ──────────────────────────────────────────────────────────────

    def make_ws2_sample(self, sector: str) -> Dict:
        """Generate one Workshop 2 RO/TO identification sample"""

        profile = self.profiles[sector]
        ro      = self._get_apt_group(sector)
        asset   = random.choice(profile['business_assets'])
        feared  = random.choice(profile['feared_events'])
        mission = random.choice(profile['missions'])

        to_options = [
            'Espionage — theft of sensitive information for strategic advantage',
            'Financial fraud — direct monetary theft or extortion',
            'Infrastructure disruption — disabling critical operations',
            'Sabotage — causing physical or operational damage',
            'Reputational damage — public data leak or disinformation',
            'Ransomware — encryption for financial extortion'
        ]
        target_obj = random.choice(to_options)

        # Pertinence scoring
        if ro['resources'] in ['Nation-state', 'High']:
            pertinence  = 'High'
            priority    = 'Primary'
            motivation_score  = '++'
            resource_score    = '+++'
        else:
            pertinence  = 'Medium'
            priority    = 'Secondary'
            motivation_score  = '++'
            resource_score    = '++'

        instruction = (
            f'You are an EBIOS-RM certified analyst performing Workshop 2 '
            f'(Risk Origins) for a {sector.upper()} organization.\n\n'
            f'ORGANIZATION CONTEXT:\n'
            f'Mission: {mission}\n\n'
            f'BUSINESS ASSETS:\n'
            + '\n'.join(f'- {a}' for a in profile['business_assets'][:4])
            + f'\n\nFEARED EVENTS:\n'
            + '\n'.join(f'- {e["event"]} (severity {e["severity"]}/5)'
                        for e in profile['feared_events'][:3])
            + f'\n\nRISK ORIGIN TO ASSESS:\n'
            f'Category: {ro["category"]}\n'
            f'Known name: {ro["name"]}\n'
            f'Motivation: {ro["motivation"]}\n'
            f'Resources: {ro["resources"]}\n\n'
            f'TASK: Assess this RO/TO pair targeting "{asset}" '
            f'following EBIOS-RM Workshop 2 methodology. '
            f'Include motivation scoring, resource scoring, '
            f'pertinence assessment, and selection decision.'
        )

        output = {
            'workshop':  2,
            'ro_to_pair': {
                'risk_origin': {
                    'category':   ro['category'],
                    'name':       ro['name'],
                    'motivation': ro['motivation'],
                    'motivation_score':  motivation_score,
                    'resources':  ro['resources'],
                    'resource_score':    resource_score,
                    'activity_sectors': [sector],
                    'preferred_methods': [
                        'Spear-phishing campaigns',
                        'Supply chain compromise',
                        'Zero-day exploitation'
                    ]
                },
                'target_objective': target_obj,
                'targeted_asset':   asset,
                'pertinence_assessment': {
                    'score':         pertinence,
                    'justification': (
                        f'{ro["category"]} ({ro["name"]}) demonstrates '
                        f'{ro["motivation"].lower()} with {ro["resources"].lower()} '
                        f'resources, making {asset} in the {sector} sector '
                        f'a realistic and credible target.'
                    )
                },
                'priority':  priority,
                'selected':  pertinence in ['High', 'Medium'],
                'feared_event_linked': feared['event']
            }
        }

        return {
            'id':          self._make_id('WS2', sector),
            'workshop':     2,
            'sector':       sector,
            'type':        'ro_to_identification',
            'instruction':  instruction,
            'output':       output
        }

    # ──────────────────────────────────────────────────────────────
    # WORKSHOP 3: STRATEGIC SCENARIO SAMPLES
    # ──────────────────────────────────────────────────────────────

    def make_ws3_sample(self, sector: str,
                         incident: Dict = None) -> Dict:
        """Generate one Workshop 3 strategic scenario sample"""

        profile     = self.profiles[sector]
        ro          = self._get_apt_group(sector)
        stakeholder = random.choice(profile['stakeholders'])
        asset       = random.choice(profile['business_assets'])
        feared      = random.choice(profile['feared_events'])
        cves        = self._get_sector_cves(sector, n=2)
        techniques  = self._get_relevant_techniques(
            ['initial-access', 'persistence', 'impact'], n=3
        )

        if incident is None:
            incident = random.choice(self._get_sector_incidents(sector))

        scenario_id = f'SS-{sector[:3].upper()}-{random.randint(100, 999)}'

        instruction = (
            f'You are an EBIOS-RM expert conducting Workshop 3 '
            f'(Strategic Scenarios) for a {sector.upper()} organization.\n\n'
            f'ORGANIZATION SCOPE:\n'
            f'Missions:\n'
            + '\n'.join(f'- {m}' for m in profile['missions'][:3])
            + f'\n\nBusiness Assets:\n'
            + '\n'.join(f'- {a}' for a in profile['business_assets'][:4])
            + f'\n\nSupporting Assets:\n'
            + '\n'.join(f'- {a}' for a in profile['supporting_assets'][:4])
            + f'\n\nFEARED EVENTS:\n'
            + '\n'.join(f'- {e["event"]} (severity {e["severity"]}/5)'
                        for e in profile['feared_events'][:3])
            + f'\n\nCRITICAL STAKEHOLDERS:\n'
            + '\n'.join(
                f'- {s["name"]} ({s["type"]}, criticality: {s["criticality"]})'
                for s in profile['stakeholders'][:4]
            )
            + f'\n\nSELECTED RO/TO PAIR:\n'
            f'Risk Origin: {ro["category"]} — {ro["name"]}\n'
            f'Motivation:  {ro["motivation"]}\n'
            f'Resources:   {ro["resources"]}\n'
            f'Target:      {feared["event"]}\n\n'
            f'TASK: Generate a complete EBIOS-RM Workshop 3 strategic scenario '
            f'with ID {scenario_id}. Include two attack paths: one direct '
            f'and one through a critical stakeholder. Assess severity using '
            f'the EBIOS-RM risk matrix (Insignificant to Severe x Rare to Highly Likely).'
        )

        output = {
            'workshop':      3,
            'scenario_id':   scenario_id,
            'scenario_title': (
                f'{ro["category"]} — {feared["event"][:55]}'
            ),
            'risk_origin': {
                'category':   ro['category'],
                'name':       ro['name'],
                'motivation': ro['motivation'],
                'resources':  ro['resources']
            },
            'target_objective':  feared['event'],
            'targeted_assets':  [asset],
            'attack_paths': [
                {
                    'path_id':     'AP-01',
                    'route':       'Direct attack on internet-facing infrastructure',
                    'description': (
                        f'Direct exploitation of {sector} organization '
                        f'internet-facing services'
                    ),
                    'steps': [
                        f'External OSINT reconnaissance of {sector} digital footprint',
                        f'Exploit internet-facing vulnerability to gain initial access',
                        f'Lateral movement to internal systems hosting {asset}',
                        f'Execute target objective: {feared["event"]}'
                    ],
                    'mitre_techniques': [t['id'] for t in techniques[:2]]
                },
                {
                    'path_id':     'AP-02',
                    'route':       f'Supply chain via {stakeholder["name"]}',
                    'description': (
                        f'Attack through trusted {stakeholder["name"]} '
                        f'({stakeholder["criticality"]} criticality)'
                    ),
                    'steps': [
                        f'Compromise {stakeholder["name"]} as privileged supply chain entry',
                        f'Leverage trusted relationship to pivot into {sector} organization',
                        f'Use legitimate credentials to reach {asset}',
                        f'Execute: {feared["event"]}'
                    ],
                    'mitre_techniques': [t['id'] for t in techniques[2:]]
                }
            ],
            'ecosystem_analysis': {
                'critical_stakeholder': stakeholder['name'],
                'stakeholder_type':     stakeholder['type'],
                'criticality':          stakeholder['criticality'],
                'threat_vector': (
                    f'{stakeholder["name"]} holds privileged digital access '
                    f'enabling bypass of perimeter controls'
                )
            },
            'severity':              feared['severity'],
            'severity_justification': (
                f'Severity {feared["severity"]}/5 — Direct impact on core '
                f'mission. Affects critical asset: {asset}. '
                f'Based on real incident: {incident.get("incident_id", "N/A")}.'
            ),
            'likelihood':            'Likely',
            'risk_level':            'High' if feared['severity'] >= 4 else 'Medium',
            'mitre_references':      [t['id'] for t in techniques],
            'cve_references':        [c['id'] for c in cves],
            'real_world_reference':  incident.get('incident_id', ''),
            'real_world_source':     incident.get('source', '')
        }

        return {
            'id':         self._make_id('WS3', sector),
            'workshop':    3,
            'sector':      sector,
            'type':       'strategic_scenario',
            'instruction': instruction,
            'output':      output
        }

    # ──────────────────────────────────────────────────────────────
    # WORKSHOP 4: OPERATIONAL SCENARIO SAMPLES
    # ──────────────────────────────────────────────────────────────

    def make_ws4_sample(self, strategic: Dict,
                         incident: Dict = None) -> Dict:
        """Generate one Workshop 4 operational scenario sample"""

        sector   = strategic['sector']
        s_out    = strategic['output']
        profile  = self.profiles[sector]
        path     = random.choice(s_out['attack_paths'])
        cves     = self._get_sector_cves(sector, n=2)

        if incident is None:
            incident = random.choice(self._get_sector_incidents(sector))

        chain    = incident.get('attack_chain', {})
        scenario_id = f'OS-{sector[:3].upper()}-{random.randint(100, 999)}'

        # Techniques for each phase
        knowing_tech   = self._get_relevant_techniques(['reconnaissance'], n=2)
        entering_tech  = self._get_relevant_techniques(['initial-access'], n=2)
        finding_tech   = self._get_relevant_techniques(['discovery', 'lateral-movement'], n=2)
        exploiting_tech= self._get_relevant_techniques(['impact', 'exfiltration'], n=2)

        instruction = (
            f'You are an EBIOS-RM expert conducting Workshop 4 '
            f'(Operational Scenarios) for a {sector.upper()} organization.\n\n'
            f'PARENT STRATEGIC SCENARIO:\n'
            f'ID:              {s_out["scenario_id"]}\n'
            f'Title:           {s_out["scenario_title"]}\n'
            f'Risk Origin:     {s_out["risk_origin"]["category"]} '
            f'({s_out["risk_origin"]["name"]})\n'
            f'Target:          {s_out["target_objective"]}\n'
            f'Selected Path:   {path["route"]}\n'
            f'Path Steps:\n'
            + '\n'.join(f'  {i+1}. {step}'
                        for i, step in enumerate(path['steps']))
            + f'\n\nTASK: Generate a complete operational scenario '
            f'with ID {scenario_id} following the EBIOS-RM attack '
            f'sequence model (Knowing → Entering → Finding → Exploiting). '
            f'Include specific MITRE ATT&CK technique IDs, realistic tools, '
            f'and likelihood assessment using the EBIOS-RM V0-V4 scale.'
        )

        output = {
            'workshop':     4,
            'scenario_id':  scenario_id,
            'scenario_title': f'Operational: {path["description"]}',
            'parent_strategic_id': s_out['scenario_id'],
            'attack_sequence': {
                'knowing': {
                    'phase':       'External reconnaissance',
                    'objective':   'Gather intelligence to plan the attack',
                    'technique':   chain.get('knowing', {}).get('technique',
                                   'OSINT and passive reconnaissance'),
                    'mitre_id':    chain.get('knowing', {}).get('mitre_id',
                                   knowing_tech[0]['id'] if knowing_tech else 'T1591'),
                    'mitre_name':  knowing_tech[0]['name'] if knowing_tech else 'Gather Victim Org Information',
                    'description': chain.get('knowing', {}).get('description',
                                   f'Passive OSINT reconnaissance of {sector} organization'),
                    'elementary_actions': [
                        f'Passive OSINT via LinkedIn, Shodan, WHOIS, job postings',
                        f'Map {sector} organization digital footprint and tech stack',
                        f'Identify key personnel with privileged system access',
                        f'Enumerate internet-facing services and versions'
                    ],
                    'tools': ['Shodan', 'Maltego', 'LinkedIn OSINT', 'WHOIS']
                },
                'entering': {
                    'phase':       'Initial access',
                    'objective':   'Gain first foothold in the target environment',
                    'technique':   chain.get('entering', {}).get('technique',
                                   'Targeted spear-phishing campaign'),
                    'mitre_id':    chain.get('entering', {}).get('mitre_id',
                                   entering_tech[0]['id'] if entering_tech else 'T1566'),
                    'mitre_name':  entering_tech[0]['name'] if entering_tech else 'Phishing',
                    'description': chain.get('entering', {}).get('description',
                                   'Initial access via targeted attack vector'),
                    'tool_used':   chain.get('entering', {}).get('tool_used',
                                   'Custom malware loader'),
                    'elementary_actions': [
                        f'Craft sector-specific spear-phishing email with lure',
                        f'Deliver initial access payload via email attachment or link',
                        f'Execute payload establishing encrypted C2 channel',
                        f'Confirm access and deploy persistence mechanism'
                    ],
                    'tools': [
                        chain.get('entering', {}).get('tool_used', 'Custom loader'),
                        'Cobalt Strike', 'Metasploit'
                    ],
                    'cve_exploited': cves[0]['id'] if cves else 'CVE-N/A'
                },
                'finding': {
                    'phase':       'Internal reconnaissance and lateral movement',
                    'objective':   'Locate target assets and elevate privileges',
                    'technique':   chain.get('finding', {}).get('technique',
                                   'Active Directory enumeration and lateral movement'),
                    'mitre_id':    chain.get('finding', {}).get('mitre_id',
                                   finding_tech[0]['id'] if finding_tech else 'T1018'),
                    'mitre_name':  finding_tech[0]['name'] if finding_tech else 'Remote System Discovery',
                    'description': chain.get('finding', {}).get('description',
                                   'Internal network mapping and target location'),
                    'tool_used':   chain.get('finding', {}).get('tool_used',
                                   'BloodHound, Nmap, Mimikatz'),
                    'elementary_actions': [
                        f'Enumerate Active Directory structure and privileged accounts',
                        f'Map internal network topology and identify {s_out["targeted_assets"][0]}',
                        f'Dump credentials and perform pass-the-hash attacks',
                        f'Move laterally to systems with access to target assets'
                    ],
                    'tools': ['BloodHound', 'Mimikatz', 'Nmap', 'CrackMapExec']
                },
                'exploiting': {
                    'phase':       'Objective execution',
                    'objective':   f'Execute: {s_out["target_objective"]}',
                    'technique':   chain.get('exploiting', {}).get('technique',
                                   'Data exfiltration and impact execution'),
                    'mitre_id':    chain.get('exploiting', {}).get('mitre_id',
                                   exploiting_tech[0]['id'] if exploiting_tech else 'T1486'),
                    'mitre_name':  exploiting_tech[0]['name'] if exploiting_tech else 'Data Encrypted for Impact',
                    'description': chain.get('exploiting', {}).get('description',
                                   'Final objective achieved'),
                    'impact':      chain.get('exploiting', {}).get('impact',
                                   f'Significant operational impact on {sector} organization'),
                    'elementary_actions': [
                        f'Execute primary objective: {s_out["target_objective"]}',
                        f'Exfiltrate or encrypt target data for maximum impact',
                        f'Deploy persistence for long-term access if needed',
                        f'Cover tracks: clear logs, remove tools, destroy evidence'
                    ],
                    'tools': ['Custom ransomware', 'Rclone', 'MEGASync']
                }
            },
            'likelihood': {
                'scale':         'V3 - Very Likely',
                'value':          3,
                'method_used':   'Standard method',
                'justification': (
                    f'{s_out["risk_origin"]["category"]} has demonstrated '
                    f'capability ({s_out["risk_origin"]["resources"]}) and '
                    f'strong motivation ({s_out["risk_origin"]["motivation"]}). '
                    f'Attack path is realistic based on {incident.get("incident_id", "documented incidents")}.'
                )
            },
            'countermeasures': [
                'Enforce MFA on all privileged and remote access accounts',
                'Deploy EDR solution with behavioral detection capabilities',
                'Implement network segmentation and micro-segmentation',
                'Conduct regular purple team exercises on this scenario',
                'Enable comprehensive audit logging and SIEM correlation'
            ],
            'cve_references':      [c['id'] for c in cves],
            'real_world_reference': incident.get('incident_id', ''),
            'lessons_learned':      incident.get('lessons_learned', '')
        }

        return {
            'id':         self._make_id('WS4', sector),
            'workshop':    4,
            'sector':      sector,
            'type':       'operational_scenario',
            'instruction': instruction,
            'output':      output
        }

    # ──────────────────────────────────────────────────────────────
    # MAIN GENERATION METHOD
    # ──────────────────────────────────────────────────────────────

    def generate(self, target: int = 5001) -> List[Dict]:
        """
        Generate the complete training dataset.
        Distribution: 20% WS2, 40% WS3, 40% WS4
        """

        from tqdm import tqdm

        dataset          = []
        per_ws2          = int(target * 0.20)   # ~1000
        per_ws3          = int(target * 0.40)   # ~2000
        per_ws4          = target - per_ws2 - per_ws3  # ~2001
        strategic_cache  = []

        logger.info(f'Generating {target} samples: '
                    f'{per_ws2} WS2 + {per_ws3} WS3 + {per_ws4} WS4')

        # ── Workshop 2 ────────────────────────────────────────────
        print(f'\n  [1/3] Workshop 2: {per_ws2} RO/TO samples...')
        for i in tqdm(range(per_ws2), desc='  WS2', ncols=70):
            sector = self.sectors[i % len(self.sectors)]
            dataset.append(self.make_ws2_sample(sector))

        # ── Workshop 3 ────────────────────────────────────────────
        print(f'\n  [2/3] Workshop 3: {per_ws3} strategic samples...')
        for i in tqdm(range(per_ws3), desc='  WS3', ncols=70):
            sector   = self.sectors[i % len(self.sectors)]
            incident = self.incidents[i % len(self.incidents)]
            sample   = self.make_ws3_sample(sector, incident)
            dataset.append(sample)
            strategic_cache.append(sample)

        # ── Workshop 4 ────────────────────────────────────────────
        print(f'\n  [3/3] Workshop 4: {per_ws4} operational samples...')
        for i in tqdm(range(per_ws4), desc='  WS4', ncols=70):
            strategic = strategic_cache[i % len(strategic_cache)]
            incident  = self.incidents[i % len(self.incidents)]
            dataset.append(self.make_ws4_sample(strategic, incident))

        # Shuffle to mix workshops and sectors
        random.shuffle(dataset)

        logger.info(f'Generation complete: {len(dataset)} samples')
        return dataset