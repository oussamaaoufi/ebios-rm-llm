# Path: scripts\collectors\collect_mitre.py

import sys
import json
import requests
from pathlib import Path
from tqdm import tqdm

# ── MODIFICATION: DYNAMIC PATH RESOLUTION FOR D: DRIVE ─────────────────────
# Replaced the old Path.home() reference to guarantee scripts are imported correctly.
PROJECT_ROOT = Path(r'.')
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# ───────────────────────────────────────────────────────────────────────────

from scripts.utils.paths  import RAW_DIR, PipelineState, save_json, load_json
from scripts.utils.logger import get_logger, print_section, print_success, print_warning, print_error

logger = get_logger('mitre_collector', 'mitre_collection.log')


def collect_mitre_attack() -> dict:
    """
    Collect complete MITRE ATT&CK dataset.
    Source: Official MITRE GitHub repository.
    No API key needed.
    """
    
    print_section('STEP 1: COLLECTING MITRE ATT&CK DATA')
    
    output_file = RAW_DIR / 'mitre_complete.json'
    
    # Skip if already collected
    if output_file.exists():
        logger.info('MITRE data already exists — loading from disk')
        data = load_json(output_file)
        print_success(f'Loaded existing data: {len(data["techniques"])} techniques')
        return data
    
    # Official MITRE ATT&CK GitHub URLs
    urls = {
        'enterprise': (
            'https://raw.githubusercontent.com/mitre/cti/master'
            '/enterprise-attack/enterprise-attack.json'
        ),
        'ics': (
            'https://raw.githubusercontent.com/mitre/cti/master'
            '/ics-attack/ics-attack.json'
        )
    }
    
    result = {
        'techniques':  [],
        'groups':      [],
        'software':    [],
        'campaigns':   [],
        'collected_at': ''
    }
    
    for domain, url in urls.items():
        logger.info(f'Downloading {domain} domain...')
        print(f'\n  Downloading {domain} ATT&CK data...')
        
        try:
            # Windows needs longer timeout for large files
            response = requests.get(url, timeout=120)
            response.raise_for_status()
            
            # Parse JSON
            data = response.json()
            objects = data.get('objects', [])
            
            logger.info(f'  {domain}: {len(objects)} objects to process')
            
            for obj in tqdm(objects, desc=f'  Processing {domain}'):
                obj_type = obj.get('type', '')
                
                # Get MITRE ID from external references
                refs   = obj.get('external_references', [])
                obj_id = next(
                    (r['external_id'] for r in refs
                     if r.get('source_name') == 'mitre-attack'),
                    'Unknown'
                )
                
                # ── Techniques (attack patterns) ─────────────────
                if obj_type == 'attack-pattern':
                    technique = {
                        'domain':    domain,
                        'id':        obj_id,
                        'name':      obj.get('name', ''),
                        'description': (
                            obj.get('description', '')[:600]
                            .replace('\n', ' ')
                            .strip()
                        ),
                        'tactics': [
                            p['phase_name']
                            for p in obj.get('kill_chain_phases', [])
                        ],
                        'platforms':    obj.get('x_mitre_platforms', []),
                        'detection':    obj.get('x_mitre_detection', '')[:300],
                        'is_subtechnique': obj.get('x_mitre_is_subtechnique', False),
                        'permissions':  obj.get('x_mitre_permissions_required', []),
                        'defenses_bypassed': obj.get('x_mitre_defense_bypassed', []),
                        'url': next(
                            (r.get('url', '') for r in refs
                             if r.get('source_name') == 'mitre-attack'),
                            ''
                        )
                    }
                    result['techniques'].append(technique)
                
                # ── Threat Groups ─────────────────────────────────
                elif obj_type == 'intrusion-set':
                    group = {
                        'id':          obj_id,
                        'name':        obj.get('name', ''),
                        'aliases':     obj.get('aliases', []),
                        'description': obj.get('description', '')[:500],
                        'motivation':  obj.get('primary_motivation', ''),
                        'resources':   obj.get('resource_level', ''),
                        'goals':       obj.get('goals', [])
                    }
                    result['groups'].append(group)
                
                # ── Malware and Tools ─────────────────────────────
                elif obj_type in ['malware', 'tool']:
                    software = {
                        'type':        obj_type,
                        'id':          obj_id,
                        'name':        obj.get('name', ''),
                        'description': obj.get('description', '')[:400],
                        'platforms':   obj.get('x_mitre_platforms', []),
                        'aliases':     obj.get('x_mitre_aliases', [])
                    }
                    result['software'].append(software)
                
                # ── Campaigns ─────────────────────────────────────
                elif obj_type == 'campaign':
                    campaign = {
                        'name':        obj.get('name', ''),
                        'description': obj.get('description', '')[:400],
                        'first_seen':  obj.get('first_seen', ''),
                        'last_seen':   obj.get('last_seen', '')
                    }
                    result['campaigns'].append(campaign)
        
        except requests.exceptions.Timeout:
            print_error(f'Timeout downloading {domain} — check your internet')
            logger.error(f'Timeout: {domain}')
            continue
        
        except requests.exceptions.ConnectionError:
            print_error(f'Connection failed for {domain}')
            print_warning('Check internet connection and try again')
            continue
        
        except Exception as e:
            print_error(f'Error collecting {domain}: {e}')
            logger.error(f'{domain}: {e}')
            continue
        
        print_success(f'{domain}: {len([t for t in result["techniques"] if t["domain"]==domain])} techniques')
    
    # Add collection timestamp
    from datetime import datetime
    result['collected_at'] = datetime.now().isoformat()
    
    # Save to disk
    save_json(result, output_file)
    
    # Print summary
    print_section('MITRE COLLECTION SUMMARY')
    print_success(f'Techniques:  {len(result["techniques"])}')
    print_success(f'Groups:      {len(result["groups"])}')
    print_success(f'Software:    {len(result["software"])}')
    print_success(f'Campaigns:   {len(result["campaigns"])}')
    print_success(f'Saved to:    {output_file}')
    
    return result


if __name__ == '__main__':
    data = collect_mitre_attack()
    
    print('\nSample technique:')
    if data['techniques']:
        t = data['techniques'][0]
        print(f'  ID:        {t["id"]}')
        print(f'  Name:      {t["name"]}')
        print(f'  Tactics:   {t["tactics"]}')
        print(f'  Platforms:{t["platforms"]}')