# Replace your entire scripts\collectors\collect_cve.py with this

import sys
import json
import time
import requests
import os
from pathlib import Path
from tqdm import tqdm
from datetime import datetime

sys.path.insert(0, str(Path('D:/') / 'phd' / 'ebios_phd_thesis'))

from scripts.utils.paths  import RAW_DIR, save_json, load_json
from scripts.utils.logger import (
    get_logger, print_section, print_success,
    print_warning, print_error, print_info
)

logger = get_logger('cve_collector', 'cve_collection.log')


# ── NVD API Configuration ─────────────────────────────────────────
NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def build_request(keyword: str,
                  results_per_page: int = 20,
                  start_index: int = 0,
                  api_key: str = '') -> dict:
    """
    Build correct NVD API 2.0 request.
    Removes the broken cvssV3Severity parameter.
    """
    
    params = {
        'keywordSearch':  keyword,
        'resultsPerPage': results_per_page,
        'startIndex':     start_index
    }
    
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    
    return params, headers


def make_nvd_request(keyword: str,
                     api_key: str = '',
                     sleep_time: float = 7.0,
                     max_retries: int = 3) -> list:
    """
    Make a single NVD API request with retry logic.
    Returns list of CVE entries or empty list on failure.
    """
    
    params, headers = build_request(
        keyword         = keyword,
        results_per_page = 20
    )
    
    for attempt in range(max_retries):
        try:
            response = requests.get(
                NVD_BASE_URL,
                params  = params,
                headers = headers,
                timeout = 30
            )
            
            # Success
            if response.status_code == 200:
                data  = response.json()
                vulns = data.get('vulnerabilities', [])
                logger.debug(f'"{keyword}": {len(vulns)} results')
                return vulns
            
            # Rate limited
            elif response.status_code == 429:
                wait = 35 * (attempt + 1)
                print_warning(f'Rate limited — waiting {wait}s (attempt {attempt+1})')
                logger.warning(f'Rate limited on "{keyword}" — waiting {wait}s')
                time.sleep(wait)
                continue
            
            # Bad request — log the actual error message
            elif response.status_code == 400:
                error_msg = response.text[:200]
                logger.error(f'Bad request for "{keyword}": {error_msg}')
                print_error(f'Bad request: {error_msg}')
                return []
            
            # Not found
            elif response.status_code == 404:
                logger.warning(f'404 for "{keyword}" — keyword may be too specific')
                return []
            
            # Server error — retry
            elif response.status_code >= 500:
                print_warning(f'Server error {response.status_code} — retrying')
                time.sleep(10 * (attempt + 1))
                continue
            
            else:
                logger.warning(f'Unexpected status {response.status_code} for "{keyword}"')
                return []
        
        except requests.exceptions.Timeout:
            print_warning(f'Timeout for "{keyword}" (attempt {attempt+1}/{max_retries})')
            time.sleep(10)
            continue
        
        except requests.exceptions.ConnectionError as e:
            print_error(f'Connection error: {e}')
            time.sleep(20)
            continue
        
        except Exception as e:
            logger.error(f'Unexpected error for "{keyword}": {e}')
            return []
    
    logger.error(f'All {max_retries} attempts failed for "{keyword}"')
    return []


def parse_cve_entry(vuln: dict, sector: str, keyword: str) -> dict:
    """
    Parse a single CVE entry from NVD API response.
    Handles all edge cases safely.
    """
    
    cve = vuln.get('cve', {})
    
    # Get English description
    description = next(
        (d['value'] for d in cve.get('descriptions', [])
         if d.get('lang') == 'en'),
        ''
    )
    
    # Get CVSS metrics (try v3.1 first, then v3.0, then v2)
    metrics      = cve.get('metrics', {})
    cvss_data    = {}
    cvss_version = 'none'
    
    if metrics.get('cvssMetricV31'):
        cvss_data    = metrics['cvssMetricV31'][0].get('cvssData', {})
        cvss_version = '3.1'
    elif metrics.get('cvssMetricV30'):
        cvss_data    = metrics['cvssMetricV30'][0].get('cvssData', {})
        cvss_version = '3.0'
    elif metrics.get('cvssMetricV2'):
        cvss_data    = metrics['cvssMetricV2'][0].get('cvssData', {})
        cvss_version = '2.0'
    
    # Get severity — compute from score if not present
    severity  = cvss_data.get('baseSeverity', '')
    cvss_score = float(cvss_data.get('baseScore', 0))
    
    if not severity and cvss_score > 0:
        if cvss_score >= 9.0:
            severity = 'CRITICAL'
        elif cvss_score >= 7.0:
            severity = 'HIGH'
        elif cvss_score >= 4.0:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
    
    # Get CWE identifiers
    cwe_list = []
    for weakness in cve.get('weaknesses', []):
        for desc in weakness.get('description', []):
            if desc.get('value', '').startswith('CWE-'):
                cwe_list.append(desc['value'])
    
    return {
        'id':                   cve.get('id', ''),
        'description':          description[:500],
        'severity':             severity or 'UNKNOWN',
        'cvss_score':           cvss_score,
        'cvss_version':         cvss_version,
        'attack_vector':        cvss_data.get('attackVector', ''),
        'attack_complexity':    cvss_data.get('attackComplexity', ''),
        'privileges_required':  cvss_data.get('privilegesRequired', ''),
        'user_interaction':     cvss_data.get('userInteraction', ''),
        'cwe':                  cwe_list[:3],
        'published':            cve.get('published', ''),
        'last_modified':        cve.get('lastModified', ''),
        'sector':               sector,
        'keyword':              keyword
    }


def filter_relevant_cves(cves: list,
                         min_score: float = 6.0) -> list:
    """
    Filter CVEs to keep only relevant ones.
    Removes low-severity and incomplete entries.
    """
    
    filtered = []
    for cve in cves:
        # Must have an ID
        if not cve.get('id'):
            continue
        # Must have a description
        if len(cve.get('description', '')) < 20:
            continue
        # Score filter (keep medium, high, critical)
        score = cve.get('cvss_score', 0)
        if score < min_score and cve.get('severity') not in ['HIGH', 'CRITICAL']:
            continue
        filtered.append(cve)
    
    return filtered


def collect_cve_data() -> dict:
    """
    Collect CVEs from NVD organized by sector.
    Fixed version — works with current NVD API 2.0.
    """
    
    print_section('STEP 2: COLLECTING CVE DATA FROM NVD API 2.0')
    
    output_file  = RAW_DIR / 'cve_by_sector.json'
    partial_file = RAW_DIR / 'cve_partial.json'
    
    # Return existing data if complete
    if output_file.exists():
        logger.info('CVE data already complete — loading from disk')
        data  = load_json(output_file)
        total = sum(
            len(v) for k, v in data.items()
            if not k.startswith('_')
        )
        print_success(f'Loaded {total} existing CVEs')
        return data
    
    # Load partial data for resume capability
    completed = {}
    if partial_file.exists():
        completed = load_json(partial_file)
        done_sectors = [k for k in completed if not k.startswith('_')]
        if done_sectors:
            print_warning(f'Resuming — already done: {done_sectors}')
    
    # API key setup
    NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
    if NVD_API_KEY:
        sleep_time = 0.7
        print_success('NVD API key detected — fast mode (~8 min)')
    else:
        sleep_time = 7.0
        print_warning('No API key — slow mode (~30 min)')
        print_info('Get free key: https://nvd.nist.gov/developers/request-an-api-key')
        print_info('Set it: $env:NVD_API_KEY = "your-key-here"')
    
    # ── Sector keyword mapping ─────────────────────────────────────
    # Keywords carefully chosen to work with NVD API 2.0
    # Shorter, broader terms work better than long specific phrases
    sector_keywords = {
        'healthcare': [
            'medical',
            'hospital',
            'patient',
            'clinical',
            'pharmacy',
            'radiology',
            'telemedicine',
            'EMR'
        ],
        'finance': [
            'banking',
            'payment',
            'financial',
            'trading',
            'cryptocurrency',
            'ATM',
            'invoice',
            'accounting'
        ],
        'energy': [
            'SCADA',
            'industrial',
            'power',
            'Modbus',
            'firmware',
            'PLC',
            'pipeline',
            'substation'
        ],
        'government': [
            'authentication',
            'identity',
            'directory',
            'privilege',
            'access control',
            'encryption',
            'certificate',
            'VPN'
        ],
        'technology': [
            'container',
            'Kubernetes',
            'cloud',
            'API',
            'repository',
            'pipeline',
            'microservice',
            'DevOps'
        ]
    }
    
    all_cves = {}
    
    for sector, keywords in sector_keywords.items():
        
        # Skip completed sectors
        if sector in completed:
            print_warning(f'Skipping {sector} — already collected')
            all_cves[sector] = completed[sector]
            continue
        
        print(f'\n  [{list(sector_keywords.keys()).index(sector)+1}/5] {sector.upper()}...')
        logger.info(f'Starting: {sector}')
        
        sector_cves = []
        seen_ids    = set()
        
        for keyword in tqdm(keywords, desc=f'  {sector}', ncols=70):
            
            # Make API request
            vulns = make_nvd_request(
                keyword    = keyword,
                api_key    = NVD_API_KEY,
                sleep_time = sleep_time
            )
            
            # Parse each CVE
            for vuln in vulns:
                cve_id = vuln.get('cve', {}).get('id', '')
                
                # Skip duplicates
                if not cve_id or cve_id in seen_ids:
                    continue
                seen_ids.add(cve_id)
                
                entry = parse_cve_entry(vuln, sector, keyword)
                sector_cves.append(entry)
            
            # Respect rate limit
            time.sleep(sleep_time)
        
        # Filter to relevant CVEs only
        filtered = filter_relevant_cves(sector_cves, min_score=6.0)
        
        all_cves[sector] = filtered
        logger.info(f'{sector}: {len(filtered)} CVEs (from {len(sector_cves)} raw)')
        print_success(f'{sector}: {len(filtered)} CVEs collected')
        
        # Save partial progress
        completed[sector] = filtered
        save_json(completed, partial_file)
    
    # Add metadata
    total_cves = sum(len(v) for v in all_cves.values())
    all_cves['_metadata'] = {
        'collected_at':  datetime.now().isoformat(),
        'api_key_used':  bool(NVD_API_KEY),
        'total_cves':    total_cves,
        'nvd_api_version': '2.0'
    }
    
    # Save complete dataset
    save_json(all_cves, output_file)
    
    # Clean up partial file
    if partial_file.exists():
        partial_file.unlink()
    
    # Summary
    print_section('CVE COLLECTION COMPLETE')
    for sector, cves in all_cves.items():
        if not sector.startswith('_'):
            print_success(f'{sector:<15}: {len(cves)} CVEs')
    print_success(f'TOTAL          : {total_cves} CVEs')
    print_success(f'Saved to       : {output_file}')
    
    return all_cves


if __name__ == '__main__':
    
    # Delete partial file to start fresh
    partial = RAW_DIR / 'cve_partial.json'
    if partial.exists():
        partial.unlink()
        print_info('Cleared partial data — starting fresh')
    
    data = collect_cve_data()
    
    # Show sample from each sector
    print('\nSample CVEs per sector:')
    for sector, cves in data.items():
        if not sector.startswith('_') and cves:
            sample = cves[0]
            print(f'\n  {sector.upper()}:')
            print(f'    ID:       {sample["id"]}')
            print(f'    Score:    {sample["cvss_score"]} ({sample["severity"]})')
            print(f'    Vector:   {sample["attack_vector"]}')
            print(f'    Keyword:  {sample["keyword"]}')