import sys
import json
from pathlib import Path
from datetime import datetime
from collections import Counter

sys.path.insert(0, str(Path('D:/') / 'phd' / 'ebios_phd_thesis'))

from scripts.utils.paths  import RAW_DIR, save_json
from scripts.utils.logger import get_logger, print_section, print_success

logger = get_logger('incidents_builder', 'incidents.log')


def build_real_incidents() -> list:
    """
    Build database of real documented cyber incidents.
    
    Sources
    - CISA Advisories (cisa.gov)
    - ENISA Threat Landscape Reports
    - FBI/CISA Joint Advisories
    - CERT-UA Reports
    - SWIFT Security Reports
    - Public breach disclosures
    
    Each incident is structured for EBIOS-RM Workshop 3/4 training.
    """
    
    print_section('STEP 3: BUILDING REAL INCIDENTS DATABASE')
    
    output_file = RAW_DIR / 'real_incidents.json'
    
    incidents = [
        
        # ══════════════════════════════════════════
        # HEALTHCARE SECTOR
        # ══════════════════════════════════════════
        {
            'incident_id': 'INC-HC-001',
            'sector': 'healthcare',
            'year': 2021,
            'name': 'Conti Ransomware vs Hospital Network',
            'source': 'CISA Advisory AA21-131A',
            'reference_url': 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a',
            'threat_actor': {
                'category': 'Organized cybercriminal group',
                'name': 'Conti',
                'motivation': 'Financial gain through ransomware extortion',
                'resources': 'High - well-funded criminal organization'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'LinkedIn staff reconnaissance',
                    'mitre_id': 'T1591',
                    'description': 'Identified IT admins and VPN users via LinkedIn profiles'
                },
                'entering': {
                    'technique': 'COVID-19 themed spear-phishing',
                    'mitre_id': 'T1566.001',
                    'description': 'Malicious email with COVID document delivering TrickBot',
                    'tool_used': 'TrickBot loader'
                },
                'finding': {
                    'technique': 'Active Directory enumeration',
                    'mitre_id': 'T1018',
                    'description': 'BloodHound to map AD and locate backup servers',
                    'tool_used': 'BloodHound, AdFind'
                },
                'exploiting': {
                    'technique': 'Ransomware deployment and data exfiltration',
                    'mitre_id': 'T1486',
                    'description': '100GB patient data exfiltrated before encryption',
                    'impact': 'Hospital diverted emergency patients, $10M ransom demanded'
                }
            },
            'business_assets': ['Patient EHR', 'Medical imaging', 'Billing systems'],
            'feared_event': 'Ransomware making critical medical systems unavailable',
            'severity': 5,
            'lessons_learned': 'No MFA on VPN was the single critical failure point'
        },
        {
            'incident_id': 'INC-HC-002',
            'sector': 'healthcare',
            'year': 2023,
            'name': 'MOVEit Transfer Supply Chain Attack',
            'source': 'CISA Advisory AA23-158A',
            'reference_url': 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a',
            'threat_actor': {
                'category': 'Cybercriminal group',
                'name': 'Cl0p',
                'motivation': 'Mass data extortion at scale',
                'resources': 'High - sophisticated ransomware group'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'Zero-day vulnerability research on MOVEit Transfer',
                    'mitre_id': 'T1592',
                    'description': 'Discovered SQL injection 0-day CVE-2023-34362'
                },
                'entering': {
                    'technique': 'SQL injection on MOVEit Transfer web application',
                    'mitre_id': 'T1190',
                    'description': 'Unauthenticated SQL injection deploying LEMURLOOT webshell',
                    'tool_used': 'LEMURLOOT webshell'
                },
                'finding': {
                    'technique': 'Automated file system enumeration',
                    'mitre_id': 'T1083',
                    'description': 'Automated enumeration of all patient files in transfer system'
                },
                'exploiting': {
                    'technique': 'Automated mass data exfiltration',
                    'mitre_id': 'T1567',
                    'description': 'Patient PII exfiltrated from hundreds of healthcare providers',
                    'impact': '60+ million patients affected across 900+ organizations'
                }
            },
            'business_assets': ['Patient PII', 'Insurance claims data', 'Medical records'],
            'feared_event': 'Mass breach of patient confidentiality data affecting millions',
            'severity': 5,
            'lessons_learned': 'Third-party file transfer tools require aggressive patch management'
        },
        
        # ══════════════════════════════════════════
        # FINANCE SECTOR
        # ══════════════════════════════════════════
        {
            'incident_id': 'INC-FN-001',
            'sector': 'finance',
            'year': 2016,
            'name': 'Bangladesh Bank SWIFT Heist',
            'source': 'SWIFT Customer Security Programme Report',
            'reference_url': 'https://www.swift.com/our-solutions/compliance-and-shared-services/banking-industry-security',
            'threat_actor': {
                'category': 'State-sponsored group',
                'name': 'Lazarus Group APT38',
                'motivation': 'State-directed cryptocurrency and financial theft',
                'resources': 'Nation-state level resources'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'SWIFT operator staff targeting',
                    'mitre_id': 'T1598',
                    'description': 'Targeted employees with direct SWIFT terminal access'
                },
                'entering': {
                    'technique': 'Fake job application PDF with backdoor',
                    'mitre_id': 'T1566.001',
                    'description': 'Malicious PDF deploying EVTDIAG custom backdoor',
                    'tool_used': 'EVTDIAG, MSOUTC malware'
                },
                'finding': {
                    'technique': 'SWIFT credential extraction from memory',
                    'mitre_id': 'T1003',
                    'description': 'SWIFT Alliance Access credentials dumped from memory',
                    'tool_used': 'Custom credential dumper'
                },
                'exploiting': {
                    'technique': 'Fraudulent SWIFT payment instructions',
                    'mitre_id': 'T1657',
                    'description': 'Submitted 35 fraudulent SWIFT instructions for $951M total',
                    'impact': '$81M successfully transferred, $870M blocked by luck'
                }
            },
            'business_assets': ['SWIFT terminals', 'Correspondent banking accounts', 'Transaction audit logs'],
            'feared_event': 'Fraudulent international transfers causing massive financial loss',
            'severity': 5,
            'lessons_learned': 'SWIFT terminals were not network-isolated from general IT'
        },
        {
            'incident_id': 'INC-FN-002',
            'sector': 'finance',
            'year': 2022,
            'name': 'Ronin Network Crypto Bridge Hack',
            'source': 'Chainalysis Crypto Crime Report 2023',
            'reference_url': 'https://www.chainalysis.com/blog/2022-biggest-year-ever-for-crypto-hacking',
            'threat_actor': {
                'category': 'State-sponsored group',
                'name': 'Lazarus Group',
                'motivation': 'Cryptocurrency theft to fund state sanctions evasion',
                'resources': 'Nation-state level resources'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'LinkedIn fake job offer targeting senior engineer',
                    'mitre_id': 'T1591',
                    'description': 'Senior validator engineer targeted with fraudulent LinkedIn offer'
                },
                'entering': {
                    'technique': 'Malicious PDF delivered via fake interview process',
                    'mitre_id': 'T1204.002',
                    'description': 'Engineer executed malicious document delivering TraderTraitor',
                    'tool_used': 'TraderTraitor spyware'
                },
                'finding': {
                    'technique': 'Validator private key location and extraction',
                    'mitre_id': 'T1552',
                    'description': 'Located and extracted 5 of 9 required Ronin validator keys'
                },
                'exploiting': {
                    'technique': 'Unauthorized blockchain transaction signing',
                    'mitre_id': 'T1657',
                    'description': 'Used 5 compromised keys to authorize fraudulent withdrawals',
                    'impact': '$625M stolen — largest DeFi hack at that time'
                }
            },
            'business_assets': ['Validator private keys', 'Bridge smart contracts', 'Liquidity pools'],
            'feared_event': 'Cryptographic key theft enabling unauthorized mass fund transfers',
            'severity': 5,
            'lessons_learned': 'Single point of failure in validator key management architecture'
        },
        
        # ══════════════════════════════════════════
        # ENERGY SECTOR
        # ══════════════════════════════════════════
        {
            'incident_id': 'INC-EN-001',
            'sector': 'energy',
            'year': 2021,
            'name': 'Colonial Pipeline DarkSide Ransomware',
            'source': 'FBI/CISA Joint Advisory AA21-131A',
            'reference_url': 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a',
            'threat_actor': {
                'category': 'Organized cybercriminal group',
                'name': 'DarkSide',
                'motivation': 'Financial gain through ransomware-as-a-service model',
                'resources': 'High - professional RaaS operation'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'Dark web purchase of leaked VPN credentials',
                    'mitre_id': 'T1589.001',
                    'description': 'Purchased compromised VPN credentials from underground forum'
                },
                'entering': {
                    'technique': 'VPN authentication with stolen credentials, no MFA',
                    'mitre_id': 'T1078',
                    'description': 'Authenticated to legacy VPN account with no MFA protection',
                    'tool_used': 'Legitimate VPN client with stolen credentials'
                },
                'finding': {
                    'technique': 'IT network discovery and IT/OT boundary identification',
                    'mitre_id': 'T1046',
                    'description': 'Identified billing systems and discovered IT/OT convergence'
                },
                'exploiting': {
                    'technique': 'DarkSide ransomware deployment on IT network',
                    'mitre_id': 'T1486',
                    'description': 'Deployed ransomware targeting billing and business operations',
                    'impact': '6-day complete pipeline shutdown, US East Coast fuel shortage'
                }
            },
            'business_assets': ['Billing and dispatch systems', 'Operational data', 'IT infrastructure'],
            'feared_event': 'Disruption of critical national fuel pipeline infrastructure',
            'severity': 5,
            'lessons_learned': 'A single legacy VPN account without MFA enabled the entire attack'
        },
        {
            'incident_id': 'INC-EN-002',
            'sector': 'energy',
            'year': 2022,
            'name': 'Ukraine Power Grid INDUSTROYER2 Attack',
            'source': 'CERT-UA Alert CERT-UA-4435 and ESET Research',
            'reference_url': 'https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded',
            'threat_actor': {
                'category': 'State-sponsored group',
                'name': 'Sandworm Team (GRU Unit 74455)',
                'motivation': 'Wartime critical infrastructure sabotage',
                'resources': 'Nation-state unlimited resources'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'Long-term silent ICS network reconnaissance',
                    'mitre_id': 'T0842',
                    'description': 'Months of silent reconnaissance of SCADA and substation systems'
                },
                'entering': {
                    'technique': 'Spear-phishing for initial IT network entry',
                    'mitre_id': 'T1566',
                    'description': 'IT network compromised as pivot point to reach OT systems'
                },
                'finding': {
                    'technique': 'IEC-104 protocol discovery across substation network',
                    'mitre_id': 'T0840',
                    'description': 'Mapped SCADA architecture and identified all substation RTUs'
                },
                'exploiting': {
                    'technique': 'INDUSTROYER2 malware sending malicious IEC-104 commands',
                    'mitre_id': 'T0831',
                    'description': 'Malicious commands sent directly to substation controllers',
                    'impact': '2 million citizens lost power, CaddyWiper deployed to cover tracks'
                }
            },
            'business_assets': ['SCADA control systems', 'Substation RTU controllers', 'Grid management'],
            'feared_event': 'Physical sabotage of power grid infrastructure causing mass outage',
            'severity': 5,
            'lessons_learned': 'IT/OT network segregation was insufficient against determined nation-state'
        },
        
        # ══════════════════════════════════════════
        # GOVERNMENT SECTOR
        # ══════════════════════════════════════════
        {
            'incident_id': 'INC-GV-001',
            'sector': 'government',
            'year': 2020,
            'name': 'SolarWinds Orion SUNBURST Supply Chain',
            'source': 'CISA Emergency Directive 21-01',
            'reference_url': 'https://www.cisa.gov/emergency-directive-21-01',
            'threat_actor': {
                'category': 'State-sponsored group',
                'name': 'APT29 Cozy Bear (SVR Russian Intelligence)',
                'motivation': 'Large-scale strategic espionage against US government',
                'resources': 'Nation-state SVR intelligence service resources'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'SolarWinds software build pipeline infiltration',
                    'mitre_id': 'T1195.002',
                    'description': 'Infiltrated Orion development pipeline months before execution'
                },
                'entering': {
                    'technique': 'SUNBURST backdoor in trojanized Orion software update',
                    'mitre_id': 'T1195.002',
                    'description': 'Malicious DLL distributed to 18,000+ organizations via update',
                    'tool_used': 'SUNBURST backdoor, TEARDROP loader, Cobalt Strike'
                },
                'finding': {
                    'technique': 'Golden SAML token forgery for cloud access',
                    'mitre_id': 'T1606.002',
                    'description': 'Forged SAML authentication tokens for Microsoft 365 and Azure AD'
                },
                'exploiting': {
                    'technique': 'Long-term persistent silent espionage operation',
                    'mitre_id': 'T1567',
                    'description': 'Classified communications exfiltrated silently for 9+ months',
                    'impact': '18,000 organizations compromised including Treasury, State Dept, DoD'
                }
            },
            'business_assets': ['Government email systems', 'Classified policy documents', 'Inter-agency communications'],
            'feared_event': 'Long-term espionage operation compromising national security intelligence',
            'severity': 5,
            'lessons_learned': 'Software supply chain trust model was fundamentally broken at scale'
        },
        {
            'incident_id': 'INC-GV-002',
            'sector': 'government',
            'year': 2023,
            'name': 'Microsoft Cloud Email Breach (Storm-0558)',
            'source': 'CISA Advisory AA23-193A',
            'reference_url': 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-193a',
            'threat_actor': {
                'category': 'State-sponsored group',
                'name': 'Storm-0558 (Chinese Intelligence)',
                'motivation': 'Espionage targeting US government officials',
                'resources': 'Nation-state level resources'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'Microsoft account consumer key theft',
                    'mitre_id': 'T1552',
                    'description': 'Acquired Microsoft consumer signing key from crashed process dump'
                },
                'entering': {
                    'technique': 'Forged authentication tokens using stolen signing key',
                    'mitre_id': 'T1606.002',
                    'description': 'Forged tokens allowed access to any Microsoft cloud email account'
                },
                'finding': {
                    'technique': 'Targeted mailbox enumeration of government officials',
                    'mitre_id': 'T1114.002',
                    'description': 'Identified and accessed specific high-value government mailboxes'
                },
                'exploiting': {
                    'technique': 'Silent email collection from government accounts',
                    'mitre_id': 'T1114',
                    'description': 'Silently read emails of State Dept and Commerce Dept officials',
                    'impact': '25 organizations affected, senior US government officials compromised'
                }
            },
            'business_assets': ['Government cloud email', 'Diplomat communications', 'Policy negotiations'],
            'feared_event': 'Compromise of government diplomatic communications and negotiations',
            'severity': 5,
            'lessons_learned': 'Cloud provider key management requires additional customer controls'
        },
        
        # ══════════════════════════════════════════
        # TECHNOLOGY SECTOR
        # ══════════════════════════════════════════
        {
            'incident_id': 'INC-TC-001',
            'sector': 'technology',
            'year': 2021,
            'name': 'Codecov CICD Supply Chain Attack',
            'source': 'Codecov Security Disclosure April 2021',
            'reference_url': 'https://about.codecov.io/security-update',
            'threat_actor': {
                'category': 'State-sponsored group (suspected)',
                'name': 'Unknown APT',
                'motivation': 'Mass source code and credential theft at scale',
                'resources': 'High capability threat actor'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'Codecov Docker image analysis for writable components',
                    'mitre_id': 'T1552.007',
                    'description': 'Analyzed Docker image, found writable Bash uploader script'
                },
                'entering': {
                    'technique': 'Modification of CICD Bash uploader to exfiltrate secrets',
                    'mitre_id': 'T1195.001',
                    'description': 'Added single line to exfiltrate all CI environment variables',
                    'tool_used': 'Modified Codecov Bash Uploader v4.0.1'
                },
                'finding': {
                    'technique': 'Automated harvest of CI environment credentials at scale',
                    'mitre_id': 'T1552.001',
                    'description': 'Collected API tokens, passwords, keys from thousands of CI pipelines'
                },
                'exploiting': {
                    'technique': 'Private repository access with harvested tokens',
                    'mitre_id': 'T1213',
                    'description': 'Used harvested credentials to access private source repositories',
                    'impact': '29,000 customers affected: Twilio, HashiCorp, Rapid7, Confluent'
                }
            },
            'business_assets': ['CICD pipelines', 'Source code repositories', 'API credentials', 'Customer secrets'],
            'feared_event': 'CICD supply chain compromise exposing all customer secrets and source code',
            'severity': 5,
            'lessons_learned': 'CI environment secrets were not isolated from third-party integrations'
        },
        {
            'incident_id': 'INC-TC-002',
            'sector': 'technology',
            'year': 2023,
            'name': '3CX Desktop App Supply Chain Attack',
            'source': 'Crowdstrike and Mandiant Research 2023',
            'reference_url': 'https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp',
            'threat_actor': {
                'category': 'State-sponsored group',
                'name': 'Lazarus Group (North Korea)',
                'motivation': 'Financial theft and espionage via VoIP software users',
                'resources': 'Nation-state level resources'
            },
            'attack_chain': {
                'knowing': {
                    'technique': 'Prior supply chain compromise of Trading Technologies X_TRADER',
                    'mitre_id': 'T1195.002',
                    'description': 'First supply chain attack used as vector for second attack'
                },
                'entering': {
                    'technique': '3CX build environment compromise via employee workstation',
                    'mitre_id': 'T1195.002',
                    'description': 'Employee installed compromised X_TRADER, enabling 3CX build compromise',
                    'tool_used': 'ICONIC Stealer, TAXHAUL downloader'
                },
                'finding': {
                    'technique': 'Build system credential access and signing key theft',
                    'mitre_id': 'T1552',
                    'description': 'Accessed build infrastructure and code signing certificates'
                },
                'exploiting': {
                    'technique': 'Signed malicious 3CX update distributed to 600,000+ businesses',
                    'mitre_id': 'T1195.002',
                    'description': 'Trojanized VoIP application targeting finance and cryptocurrency firms',
                    'impact': 'First documented supply chain attack using another supply chain attack'
                }
            },
            'business_assets': ['Software build infrastructure', 'Code signing keys', 'Customer deployment pipeline'],
            'feared_event': 'Build system compromise distributing malware to all customers via signed update',
            'severity': 5,
            'lessons_learned': 'Supply chain attacks can chain together — X_TRADER led to 3CX compromise'
        }
    ]
    
    # Save to disk
    output_data = {
        'version': '1.0',
        'created_at': datetime.now().isoformat(),
        'total': len(incidents),
        'sectors': list(set(i['sector'] for i in incidents)),
        'incidents': incidents
    }
    
    save_json(output_data, output_file)
    
    # Print summary
    print_section('INCIDENTS DATABASE SUMMARY')
    by_sector = Counter(i['sector'] for i in incidents)
    for sector, count in sorted(by_sector.items()):
        print_success(f'{sector:15} {count} incidents')
    print_success(f'TOTAL           {len(incidents)} incidents')
    print_success(f'Saved to        {output_file}')
    
    logger.info(f'Built {len(incidents)} real incident records')
    
    return incidents


if __name__ == '__main__':
    incidents = build_real_incidents()