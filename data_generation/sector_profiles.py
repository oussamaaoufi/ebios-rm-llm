# Part of the EBIOS-RM-LLM pipeline.

def get_all_sector_profiles() -> dict:
    """
    Complete EBIOS-RM organizational profiles
    for all 5 sectors used in dataset generation.
    """
    return {

        # ══════════════════════════════════════════
        'healthcare': {
            'missions': [
                'Provide emergency and specialized medical care to patients',
                'Manage and protect patient health records confidentially',
                'Conduct clinical research and pharmaceutical development',
                'Coordinate with national and regional health authorities',
                'Operate medical devices and connected healthcare systems'
            ],
            'business_assets': [
                'Patient electronic health records (EHR/EMR)',
                'Medical imaging data (DICOM/PACS)',
                'Clinical research and trial data',
                'Pharmaceutical formulas and R&D results',
                'Patient billing and insurance records',
                'Medical device firmware and configurations'
            ],
            'supporting_assets': [
                'Hospital Information System (HIS)',
                'PACS imaging servers',
                'Medical IoT devices and patient monitors',
                'Active Directory and identity management',
                'VPN and remote access infrastructure',
                'Electronic prescription systems',
                'Laboratory Information System (LIS)'
            ],
            'feared_events': [
                {'event': 'Ransomware making critical medical systems unavailable during operations', 'severity': 5},
                {'event': 'Exfiltration of patient PII and medical history at scale',                'severity': 4},
                {'event': 'Manipulation of medical device firmware causing patient harm',            'severity': 5},
                {'event': 'Unavailability of EHR during critical surgical procedures',              'severity': 5},
                {'event': 'Theft of clinical research data and pharmaceutical formulas',             'severity': 4},
                {'event': 'Unauthorized access to radiology and imaging systems',                   'severity': 3}
            ],
            'stakeholders': [
                {'name': 'Medical equipment vendors',       'type': 'external', 'criticality': 'high'},
                {'name': 'Cloud EHR software provider',     'type': 'external', 'criticality': 'high'},
                {'name': 'IT maintenance contractors',       'type': 'external', 'criticality': 'high'},
                {'name': 'Health insurance companies',       'type': 'external', 'criticality': 'medium'},
                {'name': 'Research partner universities',    'type': 'external', 'criticality': 'medium'},
                {'name': 'National health authority',        'type': 'external', 'criticality': 'medium'},
                {'name': 'Internal IT security team',        'type': 'internal', 'criticality': 'high'},
                {'name': 'Medical staff with system access', 'type': 'internal', 'criticality': 'medium'}
            ],
            'ro_profiles': [
                {'category': 'Organized cybercriminal group', 'name': 'Conti',      'motivation': 'Ransomware extortion',        'resources': 'High'},
                {'category': 'Organized cybercriminal group', 'name': 'Cl0p',       'motivation': 'Mass data theft extortion',   'resources': 'High'},
                {'category': 'State-sponsored group',         'name': 'APT41',      'motivation': 'Pharmaceutical espionage',    'resources': 'Nation-state'},
                {'category': 'Competitor organization',       'name': 'Unknown',    'motivation': 'Research data theft',         'resources': 'Medium'},
                {'category': 'Malicious insider',             'name': 'Employee',   'motivation': 'Financial gain or revenge',   'resources': 'Internal access'}
            ]
        },

        # ══════════════════════════════════════════
        'finance': {
            'missions': [
                'Process financial transactions securely and reliably',
                'Manage and protect customer assets and investments',
                'Ensure regulatory compliance (PCI-DSS, Basel III, DORA)',
                'Provide 24/7 digital banking and payment services',
                'Detect and prevent financial fraud in real time'
            ],
            'business_assets': [
                'Customer financial accounts and transaction history',
                'SWIFT interbank messaging infrastructure',
                'Trading algorithms and quantitative models',
                'Transaction processing and clearing systems',
                'Anti-fraud and AML detection databases',
                'Cryptographic keys and HSM configurations'
            ],
            'supporting_assets': [
                'Core banking system',
                'SWIFT Alliance Access terminals',
                'Trading and execution platforms',
                'Mobile banking application backend',
                'Hardware Security Modules (HSM)',
                'Authentication and PKI infrastructure',
                'Real-time fraud detection engine'
            ],
            'feared_events': [
                {'event': 'Fraudulent SWIFT transfers causing massive financial loss',     'severity': 5},
                {'event': 'Mass customer data breach and large-scale identity theft',      'severity': 4},
                {'event': 'Market manipulation via trading algorithm compromise',          'severity': 5},
                {'event': 'Ransomware disrupting core banking operations',                 'severity': 4},
                {'event': 'Cryptographic key compromise enabling transaction forgery',     'severity': 5},
                {'event': 'Insider trading enabled by stolen algorithm access',            'severity': 4}
            ],
            'stakeholders': [
                {'name': 'SWIFT network operator',          'type': 'external', 'criticality': 'high'},
                {'name': 'Core banking software vendor',    'type': 'external', 'criticality': 'high'},
                {'name': 'Payment processor partners',      'type': 'external', 'criticality': 'high'},
                {'name': 'Cloud infrastructure provider',   'type': 'external', 'criticality': 'high'},
                {'name': 'Central bank regulator',          'type': 'external', 'criticality': 'medium'},
                {'name': 'Internal trading desk',           'type': 'internal', 'criticality': 'high'},
                {'name': 'IT operations team',              'type': 'internal', 'criticality': 'high'}
            ],
            'ro_profiles': [
                {'category': 'State-sponsored group',         'name': 'Lazarus APT38', 'motivation': 'State financial theft',           'resources': 'Nation-state'},
                {'category': 'Organized cybercriminal group', 'name': 'Carbanak',      'motivation': 'Banking system fraud',            'resources': 'High'},
                {'category': 'Organized cybercriminal group', 'name': 'FIN7',          'motivation': 'Payment card data theft',         'resources': 'High'},
                {'category': 'Competitor organization',       'name': 'Unknown',        'motivation': 'Trading algorithm theft',         'resources': 'High'},
                {'category': 'Malicious insider',             'name': 'Trader',         'motivation': 'Insider trading financial gain',  'resources': 'Internal access'}
            ]
        },

        # ══════════════════════════════════════════
        'energy': {
            'missions': [
                'Ensure continuous and stable energy production and distribution',
                'Maintain and monitor critical industrial infrastructure (OT/ICS)',
                'Operate SCADA systems safely and in compliance with NERC CIP',
                'Protect physical infrastructure from cyber-physical attacks',
                'Coordinate with national grid operators and energy regulators'
            ],
            'business_assets': [
                'SCADA system configurations and HMI programs',
                'Industrial control system (ICS/PLC) logic',
                'Operational technology (OT) network architecture',
                'Critical infrastructure access credentials',
                'Energy distribution routing algorithms',
                'Customer energy consumption data'
            ],
            'supporting_assets': [
                'SCADA/HMI workstations and servers',
                'PLC and RTU controllers in substations',
                'Engineering workstations',
                'Historian servers',
                'IT/OT DMZ infrastructure',
                'Remote maintenance access systems',
                'Network segmentation infrastructure'
            ],
            'feared_events': [
                {'event': 'Disruption of energy distribution causing mass civilian outage',  'severity': 5},
                {'event': 'Physical damage to industrial equipment via malicious ICS commands','severity': 5},
                {'event': 'Ransomware encrypting operational technology systems',             'severity': 5},
                {'event': 'Unauthorized modification of SCADA control parameters',           'severity': 5},
                {'event': 'Exfiltration of critical infrastructure configurations',          'severity': 4},
                {'event': 'Long-term persistent access to OT network undetected',           'severity': 4}
            ],
            'stakeholders': [
                {'name': 'SCADA and ICS vendors',           'type': 'external', 'criticality': 'high'},
                {'name': 'Remote maintenance providers',    'type': 'external', 'criticality': 'high'},
                {'name': 'Grid operators and TSOs',         'type': 'external', 'criticality': 'high'},
                {'name': 'Government energy regulator',     'type': 'external', 'criticality': 'medium'},
                {'name': 'IT/OT integration contractors',  'type': 'external', 'criticality': 'high'},
                {'name': 'Internal OT engineering team',   'type': 'internal', 'criticality': 'high'}
            ],
            'ro_profiles': [
                {'category': 'State-sponsored group', 'name': 'Sandworm',    'motivation': 'Infrastructure sabotage',     'resources': 'Nation-state'},
                {'category': 'State-sponsored group', 'name': 'TEMP.Veles',  'motivation': 'ICS/SCADA sabotage',          'resources': 'Nation-state'},
                {'category': 'State-sponsored group', 'name': 'APT33',       'motivation': 'Energy sector espionage',     'resources': 'Nation-state'},
                {'category': 'Terrorist group',       'name': 'Unknown',     'motivation': 'Cause societal disruption',   'resources': 'Medium'},
                {'category': 'Hacktivist group',      'name': 'Unknown',     'motivation': 'Environmental protest',       'resources': 'Low'}
            ]
        },

        # ══════════════════════════════════════════
        'government': {
            'missions': [
                'Deliver secure public services to citizens',
                'Protect classified and sensitive government information',
                'Maintain secure inter-agency communications and data sharing',
                'Safeguard national security and defense intelligence',
                'Operate electoral and democratic process infrastructure'
            ],
            'business_assets': [
                'Classified policy and national security documents',
                'Citizen personal and biometric identity data',
                'Secure government communications and diplomatic cables',
                'Law enforcement and intelligence databases',
                'Electoral system data and voting records',
                'Critical national infrastructure access controls'
            ],
            'supporting_assets': [
                'Classified network infrastructure (air-gapped)',
                'Government email and collaboration platforms',
                'Citizen-facing public service portals',
                'Biometric identity and border control systems',
                'Secure file transfer infrastructure',
                'PKI and government certificate authority',
                'Active Directory for government agencies'
            ],
            'feared_events': [
                {'event': 'Long-term espionage exfiltrating classified national security data', 'severity': 5},
                {'event': 'Electoral system manipulation threatening democratic process',        'severity': 5},
                {'event': 'Compromise of law enforcement and intelligence databases',           'severity': 5},
                {'event': 'Disruption of citizen-facing critical public services',             'severity': 4},
                {'event': 'Disinformation campaign via compromised government channels',       'severity': 4},
                {'event': 'Identity data breach affecting millions of citizens',               'severity': 4}
            ],
            'stakeholders': [
                {'name': 'IT service contractors',           'type': 'external', 'criticality': 'high'},
                {'name': 'Cloud service providers',          'type': 'external', 'criticality': 'high'},
                {'name': 'Inter-agency technology partners', 'type': 'external', 'criticality': 'medium'},
                {'name': 'Foreign embassy IT liaisons',      'type': 'external', 'criticality': 'medium'},
                {'name': 'National cybersecurity agency',    'type': 'external', 'criticality': 'high'},
                {'name': 'Internal IT security team',        'type': 'internal', 'criticality': 'high'},
                {'name': 'Privileged government officials',  'type': 'internal', 'criticality': 'high'}
            ],
            'ro_profiles': [
                {'category': 'State-sponsored group', 'name': 'APT29 Cozy Bear', 'motivation': 'Strategic espionage',           'resources': 'Nation-state'},
                {'category': 'State-sponsored group', 'name': 'APT28 Fancy Bear', 'motivation': 'Election interference',        'resources': 'Nation-state'},
                {'category': 'State-sponsored group', 'name': 'Storm-0558',       'motivation': 'Government email espionage',   'resources': 'Nation-state'},
                {'category': 'Hacktivist group',      'name': 'Anonymous',        'motivation': 'Political protest',            'resources': 'Low'},
                {'category': 'Malicious insider',     'name': 'Official',         'motivation': 'Ideology or financial gain',   'resources': 'Internal access'}
            ]
        },

        # ══════════════════════════════════════════
        'technology': {
            'missions': [
                'Develop and maintain secure software products at scale',
                'Provide reliable cloud infrastructure to enterprise customers',
                'Protect intellectual property and proprietary source code',
                'Ensure 99.99% uptime service availability for customers',
                'Operate and secure CI/CD development pipelines'
            ],
            'business_assets': [
                'Proprietary source code and core algorithms',
                'Customer data processed and stored via APIs',
                'Cloud infrastructure configuration and secrets',
                'Code signing certificates and private keys',
                'CI/CD pipeline configurations and build artifacts',
                'Customer authentication credentials and tokens'
            ],
            'supporting_assets': [
                'Source code repositories (GitHub/GitLab)',
                'CI/CD pipeline infrastructure (Jenkins, GitHub Actions)',
                'Cloud environments (AWS, Azure, GCP)',
                'Container registries and artifact stores',
                'Secrets management systems (Vault, AWS Secrets)',
                'Developer workstations and laptops',
                'Package management infrastructure (npm, PyPI)'
            ],
            'feared_events': [
                {'event': 'Source code exfiltration exposing proprietary algorithms',       'severity': 5},
                {'event': 'Supply chain attack via compromised CI/CD pipeline',             'severity': 5},
                {'event': 'Customer data breach via exploited API vulnerability',           'severity': 4},
                {'event': 'Code signing key compromise enabling malicious package signing', 'severity': 5},
                {'event': 'Ransomware on development infrastructure halting all operations','severity': 4},
                {'event': 'Malicious package injection into dependency registry',           'severity': 5}
            ],
            'stakeholders': [
                {'name': 'Cloud infrastructure providers',   'type': 'external', 'criticality': 'high'},
                {'name': 'Third-party library maintainers',  'type': 'external', 'criticality': 'high'},
                {'name': 'Enterprise customers with API',    'type': 'external', 'criticality': 'high'},
                {'name': 'Open source contributors',         'type': 'external', 'criticality': 'medium'},
                {'name': 'Package registry operators',       'type': 'external', 'criticality': 'high'},
                {'name': 'DevOps and platform team',         'type': 'internal', 'criticality': 'high'},
                {'name': 'Senior software engineers',        'type': 'internal', 'criticality': 'high'}
            ],
            'ro_profiles': [
                {'category': 'State-sponsored group',         'name': 'Lazarus Group', 'motivation': 'Software supply chain attack', 'resources': 'Nation-state'},
                {'category': 'State-sponsored group',         'name': 'APT41',         'motivation': 'Source code theft',           'resources': 'Nation-state'},
                {'category': 'Organized cybercriminal group', 'name': 'Unknown',       'motivation': 'Ransomware deployment',       'resources': 'High'},
                {'category': 'Competitor organization',       'name': 'Unknown',       'motivation': 'IP and algorithm theft',      'resources': 'High'},
                {'category': 'Malicious insider',             'name': 'Developer',     'motivation': 'Sabotage or financial gain',  'resources': 'Internal access'}
            ]
        }
    }