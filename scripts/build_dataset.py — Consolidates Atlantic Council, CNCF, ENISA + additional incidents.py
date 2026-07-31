#!/usr/bin/env python3
"""
Consolidated Software Supply Chain Attacks Dataset (2020 - July 2026)
Aggregates data from:
1. Atlantic Council Breaking Trust dataset (via IQT Labs CSV mirror)
2. ENISA Threat Landscape for Supply Chain Attacks (2021) + annual reports
3. CNCF TAG Security Catalog of Supply Chain Compromises
4. Additional well-documented incidents (2022-2026) from public reporting
"""

import csv
import re
from datetime import datetime

# ============================================================
# PART 1: Parse IQT Labs CSV (Atlantic Council Breaking Trust)
# Filter for incidents with report_date >= 2020-01-01
# ============================================================

def parse_iqt_csv(filepath):
    """Parse the IQT Labs CSV and return rows with report_date >= 2020."""
    incidents = []
    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            report_date = row.get('report_date', '').strip()
            # Parse the date (format: M/D/YYYY or MM/DD/YYYY)
            try:
                dt = datetime.strptime(report_date, '%m/%d/%Y')
                if dt.year >= 2020:
                    incidents.append(row)
            except (ValueError, TypeError):
                # Try alternate formats
                if report_date and '2020' in report_date or '2021' in report_date or '2022' in report_date:
                    incidents.append(row)
    return incidents

def normalize_iqt_row(row):
    """Normalize an IQT Labs CSV row to our schema."""
    # Parse dates
    compromise_date = row.get('initial_compromise_date', '').strip()
    report_date = row.get('report_date', '').strip()
    
    # Use compromise date if available, otherwise report date
    incident_date = compromise_date if compromise_date and compromise_date.lower() != 'unknown' else report_date
    
    # Normalize date to YYYY-MM-DD
    try:
        dt = datetime.strptime(incident_date, '%m/%d/%Y')
        incident_date = dt.strftime('%Y-%m-%d')
    except (ValueError, TypeError):
        try:
            dt = datetime.strptime(report_date, '%m/%d/%Y')
            incident_date = dt.strftime('%Y-%m-%d')
        except (ValueError, TypeError):
            pass
    
    technology = row.get('technology', '').strip()
    description = row.get('description', '').strip()
    
    # Determine attack vector from flags
    vectors = []
    if row.get('build_system_compromise') == '1':
        vectors.append('Build system compromise')
    if row.get('source_code_compromise') == '1':
        vectors.append('Source code compromise')
    if row.get('firmware_implant') == '1':
        vectors.append('Firmware implant')
    if row.get('certificate_attack') == '1':
        vectors.append('Certificate attack')
    if row.get('delivery_system_compromise') == '1':
        vectors.append('Delivery system compromise')
    if row.get('account_takeover') == '1':
        vectors.append('Account takeover')
    if row.get('dependency_compromise') == '1':
        vectors.append('Dependency compromise')
    if row.get('malicious_package') == '1':
        vectors.append('Malicious package')
    if row.get('typosquatting') == '1':
        vectors.append('Typosquatting')
    
    # Use minor category as fallback
    minor_cat = row.get('attack_minor_category', '').strip()
    if not vectors and minor_cat:
        vectors.append(minor_cat)
    
    attack_vector = '; '.join(vectors) if vectors else minor_cat
    
    # Determine target industry from technology
    tech_lower = technology.lower()
    if any(x in tech_lower for x in ['android', 'google play', 'chrome', 'app store', 'mobile']):
        target_industry = 'Mobile/Consumer Software'
    elif any(x in tech_lower for x in ['npm', 'pypi', 'ruby', 'packagist', 'docker', 'wordpress']):
        target_industry = 'Open Source/Package Registry'
    elif any(x in tech_lower for x in ['solarwinds', 'kaseya', 'codecov', 'travis']):
        target_industry = 'IT/DevOps Software'
    elif any(x in tech_lower for x in ['certificate', 'diginotar']):
        target_industry = 'Certificate Authority'
    elif any(x in tech_lower for x in ['php', 'linux', 'kernel', 'gentoo', 'fedora', 'webmin']):
        target_industry = 'Open Source/Infrastructure'
    else:
        target_industry = 'Technology/Software'
    
    # Determine actor type from description
    desc_lower = description.lower()
    actor_type = 'Unknown'
    apt_flag = 'Other/Unknown'
    
    apt_indicators = ['apt', 'lazarus', 'sandworm', 'apt29', 'apt41', 'winnti', 'thallium',
                      'north korea', 'russia', 'china', 'iran', 'state-sponsored', 'apt group',
                      'mustang panda', 'ta428', 'ta413']
    criminal_indicators = ['ransomware', 'revil', 'cryptominer', 'crypto mining', 'cl0p',
                           'ransom', 'extortion']
    
    for indicator in apt_indicators:
        if indicator in desc_lower:
            actor_type = 'APT / State-linked'
            apt_flag = 'APT'
            break
    
    if actor_type == 'Unknown':
        for indicator in criminal_indicators:
            if indicator in desc_lower:
                actor_type = 'Cybercriminal / Financially motivated'
                apt_flag = 'Opportunistic'
                break
    
    if actor_type == 'Unknown':
        actor_type = 'Unknown / Not attributed'
        apt_flag = 'Other/Unknown'
    
    # Number of attacks
    num_attacks = row.get('number_of_attacks', '1').strip()
    
    return {
        'Incident Date': incident_date,
        'Incident Name': f"{technology} ({report_date})" if technology else f"Unknown ({report_date})",
        'Target Industry': target_industry,
        'Attack Vector': attack_vector,
        'Attributed Actor Type': actor_type,
        'Impacted Entities': f"{technology}; {num_attacks} packages/instances affected" if num_attacks and num_attacks != '1' else technology,
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': apt_flag,
        'Source': 'Atlantic Council Breaking Trust',
        'Source URL': row.get('reference', '').strip().split('\n')[0],
        'Notes': f"IQT/Breaking Trust dataset. {row.get('comments', '').strip()}" if row.get('comments', '').strip() else 'IQT/Breaking Trust dataset'
    }


# ============================================================
# PART 2: CNCF TAG Security Catalog incidents (2020-2024)
# Manually coded from downloaded markdown files
# ============================================================

cncf_incidents = [
    # 2020
    {
        'Incident Date': '2020-10-21',
        'Incident Name': 'NPM malicious packages (plutov-slack-client, nodetest199, etc.)',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Malicious package',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'NPM; 4 malicious packages; 1,000+ downloads',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain',
        'Notes': 'Malicious NPM packages with reverse-shell and data mining functionality'
    },
    {
        'Incident Date': '2020-03-09',
        'Incident Name': 'Octopus Scanner Malware (GitHub repositories)',
        'Target Industry': 'Open Source/Developer Tools',
        'Attack Vector': 'Dev tooling compromise; Malicious package',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'GitHub; 26 open source projects affected; unknown number of developers',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain',
        'Notes': 'Malware designed to enumerate and backdoor NetBeans projects via build process'
    },
    {
        'Incident Date': '2020-12-13',
        'Incident Name': 'SolarWinds Orion (SUNBURST)',
        'Target Industry': 'IT Management/Government',
        'Attack Vector': 'Build system compromise; Code injection',
        'Attributed Actor Type': 'APT29 (Cozy Bear)',
        'Impacted Entities': 'SolarWinds; 18,000+ customers; US government agencies; Fortune 500 companies',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html',
        'Notes': 'SUNSPOT malware infected build system; injected SUNBURST backdoor into Orion updates'
    },
    {
        'Incident Date': '2020-11-03',
        'Incident Name': 'SonarQube misconfiguration source code theft',
        'Target Industry': 'Government/Technology',
        'Attack Vector': 'Credential compromise; Misconfigured service',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'US government agencies; private businesses; source code stolen',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.zdnet.com/article/fbi-hackers-stole-source-code-from-us-government-agencies-and-private-companies/',
        'Notes': 'FBI alert about threat actors abusing misconfigured SonarQube instances'
    },
    {
        'Incident Date': '2020-10-01',
        'Incident Name': 'The Great Suspender Chrome extension',
        'Target Industry': 'Browser Extensions/Consumer Software',
        'Attack Vector': 'Malicious maintainer; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': '2 million+ Chrome extension users',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://github.com/greatsuspender/thegreatsuspender/issues/1263',
        'Notes': 'Extension sold to unknown entity who injected tracking/malicious code'
    },
    {
        'Incident Date': '2020-01-01',
        'Incident Name': 'Trojanized Free Download Manager (Linux)',
        'Target Industry': 'Consumer Software',
        'Attack Vector': 'Publishing infrastructure compromise; Malicious package',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Linux users worldwide; victims in Brazil, China, Saudi Arabia, Russia',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://securelist.com/backdoored-free-download-manager-linux-malware/110465/',
        'Notes': 'Trojanized FDM from counterfeit Debian repository; active 2020-2022'
    },
    # 2021
    {
        'Incident Date': '2021-11-04',
        'Incident Name': 'NPM coa and rc packages hijacked',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Account takeover; Malicious maintainer',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'NPM; coa (8M+ weekly downloads); rc (14M+ weekly downloads); Qakbot trojan distributed',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://blog.sonatype.com/npm-hijackers-at-it-again-popular-coa-and-rc-open-source-libraries-taken-over-to-spread-malware',
        'Notes': 'Developer accounts hijacked to publish malicious versions with Qakbot trojan'
    },
    {
        'Incident Date': '2021-04-15',
        'Incident Name': 'Codecov Bash Uploader compromise',
        'Target Industry': 'DevOps/Developer Tools',
        'Attack Vector': 'Credential compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Codecov; multiple customers including Monday.com, Rapid7; credentials/tokens/keys exposed',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://about.codecov.io/security-update/',
        'Notes': 'Docker image creation error allowed credential theft; bash uploader modified since Jan 2021'
    },
    {
        'Incident Date': '2021-04-18',
        'Incident Name': 'Homebrew CI vulnerability (review-cask-pr)',
        'Target Industry': 'Open Source/Package Management',
        'Attack Vector': 'Dev tooling compromise; CI/CD compromise',
        'Attributed Actor Type': 'Security researcher (white hat)',
        'Impacted Entities': 'Homebrew; homebrew-cask repositories',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://brew.sh/2021/04/21/security-incident-disclosure/',
        'Notes': 'Vulnerability in GitHub Action allowed arbitrary code injection into casks'
    },
    {
        'Incident Date': '2021-10-15',
        'Incident Name': 'NPM klow/klown/okhsa malicious packages',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Malicious package; Typosquatting',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'NPM; cryptominer distributed via malicious packages',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://blog.sonatype.com/newly-found-npm-malware-mines-cryptocurrency-on-windows-linux-macos-devices',
        'Notes': 'Related to ua-parser-js attack; packages distributed cryptominer'
    },
    {
        'Incident Date': '2021-12-10',
        'Incident Name': 'Log4j (Log4Shell) vulnerability',
        'Target Industry': 'Open Source/Infrastructure',
        'Attack Vector': 'Code injection (RCE vulnerability)',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Apache Log4j; widespread global impact across virtually all Java applications',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://security.googleblog.com/2021/12/understanding-impact-of-apache-log4j.html',
        'Notes': 'CVE-2021-44228; critical RCE vulnerability in ubiquitous logging library'
    },
    {
        'Incident Date': '2021-03-28',
        'Incident Name': 'PHP Git server compromise',
        'Target Industry': 'Open Source/Infrastructure',
        'Attack Vector': 'Source code compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'PHP; git.php.net; two malicious commits with backdoor',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://news-web.php.net/php.internals/113838',
        'Notes': 'Self-hosted Git server compromised; backdoor in PHP source code'
    },
    {
        'Incident Date': '2021-02-01',
        'Incident Name': 'Dependency confusion attacks (repojacking)',
        'Target Industry': 'Technology/Software',
        'Attack Vector': 'Dependency confusion; Malicious package',
        'Attributed Actor Type': 'Security researcher (white hat)',
        'Impacted Entities': 'Apple, Microsoft, PayPal, Shopify, Netflix, Yelp, Uber; 35+ companies',
        'Financial Cost': '$130,000+ in bug bounties',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610',
        'Notes': 'Alex Birsan research; public packages with same names as internal packages'
    },
    {
        'Incident Date': '2021-09-23',
        'Incident Name': 'Travis CI secrets leak',
        'Target Industry': 'DevOps/CI-CD',
        'Attack Vector': 'Dev tooling compromise; Secrets exposure',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Travis CI; all public repositories with forks Sep 3-10, 2021; environment variables leaked',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://travis-ci.community/t/security-bulletin/12081',
        'Notes': 'Bug exposed secrets of public open source projects'
    },
    {
        'Incident Date': '2021-10-22',
        'Incident Name': 'NPM ua-parser-js hijacked',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Account takeover; Malicious maintainer',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'NPM; ua-parser-js (7M+ weekly downloads); 3 malicious versions with cryptominer',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://github.com/faisalman/ua-parser-js/issues/536',
        'Notes': 'Developer account hijacked; malicious versions with cryptominer and password stealer'
    },
    {
        'Incident Date': '2021-02-01',
        'Incident Name': 'VS Code GitHub repository compromise',
        'Target Industry': 'Developer Tools',
        'Attack Vector': 'Dev tooling compromise; CI/CD compromise',
        'Attributed Actor Type': 'Security researcher (white hat)',
        'Impacted Entities': 'Microsoft VS Code; GitHub repository',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.bleepingcomputer.com/news/security/heres-how-a-researcher-broke-into-microsoft-vs-codes-github/',
        'Notes': 'Researcher obtained push access via vulnerability in issue management'
    },
    # 2022
    {
        'Incident Date': '2022-09-27',
        'Incident Name': 'Comm100 Live Chat trojanized installer',
        'Target Industry': 'Customer Engagement Software',
        'Attack Vector': 'Publishing infrastructure compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Comm100; 15,000+ customers across 51 countries; industrial, healthcare, technology, manufacturing sectors',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.securityweek.com/supply-chain-attack-targets-customer-engagement-firm-comm100',
        'Notes': 'Trojanized Electron app with JavaScript backdoor; valid Comm100 certificate'
    },
    {
        'Incident Date': '2022-01-01',
        'Incident Name': 'Auth0 source code repository stolen',
        'Target Industry': 'Identity/Access Management',
        'Attack Vector': 'Source code compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Auth0 (Okta); source code from 2020 and earlier',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://auth0.com/blog/auth0-code-repository-archives-from-2020-and-earlier/',
        'Notes': 'Third-party individual informed Okta of possession of source code'
    },
    {
        'Incident Date': '2022-05-01',
        'Incident Name': 'PyPI ctx and PHP PHPass account takeover',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Account takeover; Dev tooling compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'PyPI ctx package (tens of thousands of installs); PHPass (~2.5M downloads)',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://sockpuppets.medium.com/how-i-hacked-ctx-and-phpass-modules-656638c6ec5e',
        'Notes': 'Expired GitHub accounts and email domains allowed account takeover'
    },
    {
        'Incident Date': '2022-01-01',
        'Incident Name': 'Docker Hub malicious containers (1,650+)',
        'Target Industry': 'Container/Cloud Infrastructure',
        'Attack Vector': 'Malicious package; Publishing infrastructure compromise',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'Docker Hub; 1,652 malicious container images identified; cryptominers, secrets, proxy tools',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.bleepingcomputer.com/news/security/docker-hub-repositories-hide-over-1-650-malicious-containers/',
        'Notes': 'Sysdig researchers scanned 250,000+ images; found 1,652 malicious'
    },
    {
        'Incident Date': '2022-11-01',
        'Incident Name': 'Dropbox GitHub account breach (130 repos)',
        'Target Industry': 'Cloud Storage/Technology',
        'Attack Vector': 'Phishing; Attack chaining',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Dropbox; 130 GitHub repositories; code, names, email addresses of employees/customers',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.bleepingcomputer.com/news/security/dropbox-discloses-breach-after-hacker-stole-130-github-repositories/',
        'Notes': 'Phishing impersonating CircleCI; stole GitHub credentials and OTP'
    },
    {
        'Incident Date': '2022-12-07',
        'Incident Name': 'Fantasy wiper (Agrius) supply chain attack',
        'Target Industry': 'Software/Diamond Industry',
        'Attack Vector': 'Publishing infrastructure compromise; Update mechanism compromise',
        'Attributed Actor Type': 'APT (Agrius)',
        'Impacted Entities': 'Israeli ISV; organizations in Israel, South Africa, Hong Kong; diamond industry',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.welivesecurity.com/2022/12/07/fantasy-new-agrius-wiper-supply-chain-attack/',
        'Notes': 'Agrius APT abused software update mechanism to deploy wiper malware'
    },
    {
        'Incident Date': '2022-01-01',
        'Incident Name': 'GCP Golang Buildpacks old compiler injection',
        'Target Industry': 'Cloud Infrastructure/Developer Tools',
        'Attack Vector': 'Dev tooling compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Google Cloud Platform Buildpacks; Go developers using GCP',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://zt.dev/posts/gcp-buildpacks-old-compiler/',
        'Notes': 'Build pipelines pulled older compilers with known vulnerabilities'
    },
    {
        'Incident Date': '2022-01-01',
        'Incident Name': 'Intel Alder Lake BIOS leak',
        'Target Industry': 'Hardware/Semiconductor',
        'Attack Vector': 'Source code compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Intel; 6GB BIOS/UEFI source code leaked on 4chan and GitHub',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.tomshardware.com/news/intel-confirms-6gb-alder-lake-bios-source-code-leak-new-details-emerge',
        'Notes': 'Leaked by third party; contained private signing key for Intel Boot Guard'
    },
    {
        'Incident Date': '2022-01-09',
        'Incident Name': 'NPM colors and faker sabotaged by maintainer',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Malicious maintainer; Code injection',
        'Attributed Actor Type': 'Insider (malicious maintainer)',
        'Impacted Entities': 'NPM; colors.js and faker.js; aws-cdk, Jest, Node.js Open CLI Framework; many downstream projects',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://snyk.io/blog/open-source-npm-packages-colors-faker/',
        'Notes': 'Maintainer intentionally introduced infinite loops causing DoS'
    },
    {
        'Incident Date': '2022-03-01',
        'Incident Name': 'NPM node-ipc sabotaged (peacenotwar)',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Malicious maintainer; Code injection',
        'Attributed Actor Type': 'Insider (malicious maintainer)',
        'Impacted Entities': 'NPM; node-ipc; @vue/cli; 4M+ combined downloads of related packages',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/',
        'Notes': 'Maintainer added protest-ware rewriting files based on IP geographical origin'
    },
    {
        'Incident Date': '2022-01-01',
        'Incident Name': 'Okta source code theft (GitHub)',
        'Target Industry': 'Identity/Access Management',
        'Attack Vector': 'Source code compromise; Dev tooling compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Okta; private GitHub repositories; proprietary source code',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.bleepingcomputer.com/news/security/oktas-source-code-stolen-after-github-repositories-hacked/',
        'Notes': 'GitHub notified Okta of suspicious activity; no customer data involved'
    },
    {
        'Incident Date': '2022-01-01',
        'Incident Name': 'PEAR PHP package manager compromise',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Dev tooling compromise; Credential compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'PEAR/PHP; 285M package downloads; pear.php.net server',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://blog.sonarsource.com/php-supply-chain-attack-on-pear',
        'Notes': 'Password reset flaw and unpatched CVE allowed server compromise'
    },
    {
        'Incident Date': '2022-06-24',
        'Incident Name': 'PyPI malicious packages (pygrata, loglib, etc.)',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Typosquatting; Malicious package',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'PyPI; loglib-modules, pyg-modules, pygrata, pygrata-utils, hkg-sol-utils; AWS credentials stolen',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://thehackernews.com/2022/06/multiple-backdoored-python-libraries.html',
        'Notes': 'Typosquatted packages harvesting AWS credentials and environment variables'
    },
    {
        'Incident Date': '2022-01-01',
        'Incident Name': 'RubyGems package overwrite flaw (CVE-2022-29176)',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Dev tooling compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'RubyGems.org; all packages with specific naming conventions at risk',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.bleepingcomputer.com/news/security/check-your-gems-rubygems-fixes-unauthorized-package-takeover-bug/',
        'Notes': 'Security bug allowed anyone to remove and republish legitimate packages'
    },
    {
        'Incident Date': '2022-01-18',
        'Incident Name': 'WordPress AccessPress themes/plugins backdoor',
        'Target Industry': 'Web/CMS',
        'Attack Vector': 'Source code compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'AccessPress; 93 themes and plugins; 360,000+ active websites',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://jetpack.com/2022/01/18/backdoor-found-in-themes-and-plugins-from-accesspress-themes/',
        'Notes': 'Coordinated supply chain attack; webshell injected into themes and plugins'
    },
    # 2023
    {
        'Incident Date': '2023-01-01',
        'Incident Name': 'Fake Dependabot commits',
        'Target Industry': 'Developer Tools/Open Source',
        'Attack Vector': 'Source code compromise; Credential compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'GitHub users primarily in Indonesia; hundreds of commits; repository secrets stolen',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://checkmarx.com/blog/surprise-when-dependabot-contributes-malicious-code/',
        'Notes': 'Attacker impersonated Dependabot to push malicious commits'
    },
    {
        'Incident Date': '2023-01-01',
        'Incident Name': 'NPM mathjs-min credential stealer',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Malicious package; Typosquatting',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'NPM; mathjs-min; 667K weekly downloads; 1800 dependents; Discord tokens stolen',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://blog.phylum.io/phylum-discovers-npm-package-mathjs-min-contains-discord-token-grabber',
        'Notes': 'Malicious copy of mathjs with Discord token grabber embedded'
    },
    {
        'Incident Date': '2023-05-01',
        'Incident Name': 'Packagist maintainer account takeover',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Account takeover; Dev tooling compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Packagist.org; 4 maintainer accounts; 14 packages',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://blog.packagist.com/packagist-org-maintainer-account-takeover/',
        'Notes': 'Inactive accounts with leaked passwords compromised; no malicious code distributed'
    },
    {
        'Incident Date': '2023-07-01',
        'Incident Name': 'Retool development platform MFA bypass',
        'Target Industry': 'Developer Tools/DevOps',
        'Attack Vector': 'Spear phishing; Attack chaining; Credential compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Retool; customer accounts; Fortress Trust; $15M crypto theft',
        'Financial Cost': '$15,000,000',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://retool.com/blog/mfa-isnt-mfa',
        'Notes': 'Spear phishing and voice deepfaking compromised employee Google account for MFA'
    },
    {
        'Incident Date': '2023-01-01',
        'Incident Name': 'ManageEngine CVE-2022-47966 exploitation',
        'Target Industry': 'IT Management Software',
        'Attack Vector': 'Dependency compromise; Vulnerable third-party dependency',
        'Attributed Actor Type': 'APT (North Korean)',
        'Impacted Entities': 'Zoho ManageEngine; European internet infrastructure provider; aeronautical sector',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.securityweek.com/north-korean-apt-hacks-internet-infrastructure-provider-via-manageengine-flaw/',
        'Notes': 'APT exploited vulnerable Apache Santuario/xmlsec dependency in ManageEngine'
    },
    # 2024
    {
        'Incident Date': '2024-01-01',
        'Incident Name': 'GitGot: npm packages using GitHub for exfiltration',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Malicious package; Trust and signing compromise',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'NPM; warbeast2000 (~400 downloads); kodiak2k (~950 downloads); SSH keys stolen',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.reversinglabs.com/blog/gitgot-cybercriminals-using-github-to-store-stolen-data',
        'Notes': 'npm packages designed to steal SSH keys using GitHub as exfiltration storage'
    },
    {
        'Incident Date': '2024-01-01',
        'Incident Name': 'LaiXi/3proxy signed malware (digital certificate abuse)',
        'Target Industry': 'Mobile Software',
        'Attack Vector': 'Trust and signing compromise; Certificate attack',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Microsoft Windows Hardware Compatibility certificate; Hainan YouHu Technology Co. Ltd; Android screen-sharing app users',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://news.sophos.com/en-us/2024/04/09/smoke-and-screen-mirrors-a-strange-signed-backdoor/',
        'Notes': 'Malware signed with legitimate Microsoft WHCP certificate'
    },
    {
        'Incident Date': '2024-06-25',
        'Incident Name': 'Polyfill.io infrastructure takeover',
        'Target Industry': 'Web Infrastructure/CDN',
        'Attack Vector': 'Publishing infrastructure compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'polyfill.io; 100,000+ websites; ~4% of the web; BootCSS, BootCDN, Staticfile',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://sansec.io/research/polyfill-supply-chain-attack',
        'Notes': 'Chinese company acquired domains; malware served from CDN; Cloudflare and Fastly offered replacements'
    },
    {
        'Incident Date': '2024-12-02',
        'Incident Name': 'Solana Web3.js malicious code injection',
        'Target Industry': 'Cryptocurrency/Blockchain',
        'Attack Vector': 'Account takeover; Code injection; Malicious package',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'NPM @solana/web3.js; 400K weekly downloads; 51M total downloads; crypto bots and dapps',
        'Financial Cost': '~$130,000',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://www.reversinglabs.com/blog/malware-found-in-solana-npm-library-with-50m-downloads',
        'Notes': 'Malicious versions 1.95.6/1.95.7 exfiltrated private keys; active for ~6 hours'
    },
    {
        'Incident Date': '2024-01-01',
        'Incident Name': 'Kimsuky signed malware targeting Korean institution (Endoor)',
        'Target Industry': 'Government/Public Sector',
        'Attack Vector': 'Trust and signing compromise; Code injection',
        'Attributed Actor Type': 'APT (Kimsuky)',
        'Impacted Entities': 'Korean public institution; users of trojanized installer',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://asec.ahnlab.com/en/63396/',
        'Notes': 'Kimsuky APT distributed malware disguised as official installer with valid Korean certificate'
    },
    {
        'Incident Date': '2024-03-29',
        'Incident Name': 'XZ Utils backdoor (CVE-2024-3094)',
        'Target Industry': 'Open Source/Linux Infrastructure',
        'Attack Vector': 'Malicious maintainer; Build system compromise; Attack chaining',
        'Attributed Actor Type': 'Unknown / Not attributed (suspected state-sponsored)',
        'Impacted Entities': 'XZ Utils; Fedora, Debian, Kali Linux, openSUSE, Arch Linux, Homebrew, pkgsrc; SSH servers',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'CNCF TAG Security Catalog',
        'Source URL': 'https://securitylabs.datadoghq.com/articles/xz-backdoor-cve-2024-3094/',
        'Notes': 'Multi-year social engineering to attain maintainer status; backdoor in liblzma targeting sshd; CVSS 10'
    },
]

# ============================================================
# PART 3: ENISA Threat Landscape for Supply Chain Attacks (2021)
# 24 incidents from January 2020 to early July 2021
# ============================================================

enisa_incidents = [
    {
        'Incident Date': '2021-07-01',
        'Incident Name': 'Kaseya VSA ransomware (REvil)',
        'Target Industry': 'IT Management/MSP',
        'Attack Vector': 'Vulnerability exploitation (CVE-2021-30116); Code injection; Ransomware',
        'Attributed Actor Type': 'Cybercriminal (REvil Group)',
        'Impacted Entities': 'Kaseya; MSP customers; hundreds of US companies; thousands of targets',
        'Financial Cost': 'REvil demanded $70M for universal decryptor',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Zero-day in Kaseya VSA; ransomware deployed to customer systems via VSA'
    },
    {
        'Incident Date': '2021-03-01',
        'Incident Name': 'Verkada security camera compromise',
        'Target Industry': 'Physical Security/Surveillance',
        'Attack Vector': 'Credential compromise',
        'Attributed Actor Type': 'Hacktivist',
        'Impacted Entities': 'Verkada; 5,000+ customers; 150,000+ cameras at schools, jails, hospitals, Tesla factories',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Privileged credentials found on internet; production server compromised'
    },
    {
        'Incident Date': '2021-04-15',
        'Incident Name': 'Codecov Bash Uploader (ENISA)',
        'Target Industry': 'Enterprise Software/DevOps',
        'Attack Vector': 'Credential compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Codecov; Monday.com; Rapid7; multiple Codecov customers',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Docker image error allowed credential theft; bash uploader modified'
    },
    {
        'Incident Date': '2020-11-01',
        'Incident Name': 'Wizvera VeraPort malware delivery',
        'Target Industry': 'Identity Verification/Certificate Authority',
        'Attack Vector': 'Publishing infrastructure compromise; Code injection',
        'Attributed Actor Type': 'APT (Lazarus Group)',
        'Impacted Entities': 'Wizvera; South Korean users; citizens and businesses',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Legitimate website compromised; VeraPort config replaced to deliver malware; digitally signed'
    },
    {
        'Incident Date': '2020-06-01',
        'Incident Name': 'Able Desktop chat software compromise',
        'Target Industry': 'Government/Business Software',
        'Attack Vector': 'Delivery system compromise; Update mechanism compromise; Code injection',
        'Attributed Actor Type': 'APT (TA428)',
        'Impacted Entities': 'Able; customers with infected devices',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Backend compromised; malware added to Able Desktop update'
    },
    {
        'Incident Date': '2020-06-01',
        'Incident Name': 'Aisino intelligent tax software suite',
        'Target Industry': 'Tax/Government Software',
        'Attack Vector': 'Unknown (software compromised)',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Aisino Credit Information Company; businesses in China',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Tax software suite found to include malware; method of compromise unknown'
    },
    {
        'Incident Date': '2021-02-01',
        'Incident Name': 'BigNox NoxPlayer emulator compromise',
        'Target Industry': 'Gaming/Software',
        'Attack Vector': 'Update mechanism compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'BigNox; specific targets in Asia',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Infrastructure compromised; update mechanism abused to deliver malware'
    },
    {
        'Incident Date': '2020-12-01',
        'Incident Name': 'Vietnam VGCA certification authority compromise',
        'Target Industry': 'Certificate Authority/Government',
        'Attack Vector': 'Publishing infrastructure compromise; Code injection',
        'Attributed Actor Type': 'APT (TA413, TA428)',
        'Impacted Entities': 'VGCA; users in Vietnam; citizens and businesses',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'VGCA website compromised; legitimate binaries replaced with trojanized applications'
    },
    {
        'Incident Date': '2020-05-01',
        'Incident Name': 'Apache NetBeans projects with malware',
        'Target Industry': 'Development Platform/Open Source',
        'Attack Vector': 'Malicious package; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'NetBeans project users; GitHub users; RAT malware infections',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'NetBeans projects on GitHub contained malware; self-propagating'
    },
    {
        'Incident Date': '2021-01-01',
        'Incident Name': 'Private stock investment messenger (Thallium)',
        'Target Industry': 'Financial Software',
        'Attack Vector': 'Code injection; Malicious package',
        'Attributed Actor Type': 'APT (Thallium)',
        'Impacted Entities': 'Stock investors; infected users',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Thallium APT trojanized installers to spy on infected users'
    },
    {
        'Incident Date': '2021-04-01',
        'Incident Name': 'ClickStudios Passwordstate compromise',
        'Target Industry': 'Password Management/Security Software',
        'Attack Vector': 'Update mechanism compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'ClickStudios; Passwordstate customers',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Upgrade director web mechanism compromised to deliver malware'
    },
    {
        'Incident Date': '2021-03-01',
        'Incident Name': 'Apple Xcode malicious project',
        'Target Industry': 'Developer Tools',
        'Attack Vector': 'Code injection; Dev tooling compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Xcode developers; backdoor infections',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Malicious Xcode project with backdoor; exploited Xcode weakness'
    },
    {
        'Incident Date': '2021-06-01',
        'Incident Name': 'Myanmar presidential website trojanized',
        'Target Industry': 'Government',
        'Attack Vector': 'Publishing infrastructure compromise; Code injection',
        'Attributed Actor Type': 'APT (Mustang Panda suspected)',
        'Impacted Entities': 'Myanmar presidential website; potential victims',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Resources on presidential website trojanized to deliver malware'
    },
    {
        'Incident Date': '2020-12-13',
        'Incident Name': 'SolarWinds Orion (ENISA)',
        'Target Industry': 'Cloud/IT Management',
        'Attack Vector': 'Build system compromise; Code injection',
        'Attributed Actor Type': 'APT29',
        'Impacted Entities': 'SolarWinds; governmental organizations; large corporations; multiple global victims',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Malware injected into Orion build process; downloaded by customers'
    },
    {
        'Incident Date': '2021-02-01',
        'Incident Name': 'Ukraine SEI EB portal compromise',
        'Target Industry': 'Government/Public Administration',
        'Attack Vector': 'Code injection; Malicious documents',
        'Attributed Actor Type': 'Various APT groups',
        'Impacted Entities': 'Ukraine government; public authorities; executive bodies',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Malicious documents uploaded to government document exchange portal'
    },
    {
        'Incident Date': '2021-01-01',
        'Incident Name': 'Mimecast certificate compromise (via SolarWinds)',
        'Target Industry': 'Cloud Cybersecurity/Email Security',
        'Attack Vector': 'Credential compromise; Certificate attack',
        'Attributed Actor Type': 'APT29',
        'Impacted Entities': 'Mimecast; customers using Microsoft 365; customer data',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Compromised via SolarWinds; Mimecast certificate accessed to intercept Microsoft 365 connections'
    },
    {
        'Incident Date': '2020-12-01',
        'Incident Name': 'Accellion FTA zero-day exploitation',
        'Target Industry': 'File Transfer/Enterprise Software',
        'Attack Vector': 'Vulnerability exploitation; Code injection',
        'Attributed Actor Type': 'Cybercriminal (UNC2546)',
        'Impacted Entities': 'Accellion; many customer companies; data exfiltrated and extortion attempted',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Multiple zero-day vulnerabilities exploited; webshell deployed; data exfiltration'
    },
    {
        'Incident Date': '2021-03-01',
        'Incident Name': 'SITA passenger service system breach',
        'Target Industry': 'Aviation/Air Transport IT',
        'Attack Vector': 'Server compromise; Data exfiltration',
        'Attributed Actor Type': 'APT41 (for Air India attack); SITA compromise not attributed',
        'Impacted Entities': 'SITA; Air India; Singapore Airlines; Malaysia Airlines; passenger data',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'SITA servers compromised; passenger data accessed from multiple airlines'
    },
    {
        'Incident Date': '2020-07-01',
        'Incident Name': 'Ledger hardware wallet data breach',
        'Target Industry': 'Cryptocurrency/Hardware',
        'Attack Vector': 'Credential compromise; Data exfiltration',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Ledger; users; customers whose data was leaked; phishing/extortion victims',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'E-commerce database credentials stolen; data published online; phishing and extortion'
    },
    {
        'Incident Date': '2021-05-01',
        'Incident Name': 'Fujitsu ProjectWEB compromise',
        'Target Industry': 'Collaboration/Government Software',
        'Attack Vector': 'Vulnerability exploitation; Data exfiltration',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Japanese government agencies; Japanese Air Traffic Control',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Weaknesses in ProjectWEB exploited; government and air traffic control data stolen'
    },
    {
        'Incident Date': '2020-01-01',
        'Incident Name': 'Unimax mobile devices pre-installed malware',
        'Target Industry': 'Telecommunications/Mobile Devices',
        'Attack Vector': 'Firmware implant',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Customers via US Government Lifeline Assistance Program; UMX phone users',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Pre-installed unremovable malware on low-cost mobile devices'
    },
    {
        'Incident Date': '2021-06-01',
        'Incident Name': 'Microsoft WHCP driver signing abuse',
        'Target Industry': 'Software/Gaming',
        'Attack Vector': 'Certificate attack; Trust and signing compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Users systems; gaming sector in China',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Code signing processes abused to distribute rootkit malware'
    },
    {
        'Incident Date': '2021-02-01',
        'Incident Name': 'MonPass certificate authority compromise',
        'Target Industry': 'Certificate Authority',
        'Attack Vector': 'Publishing infrastructure compromise; Code injection',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'MonPass; at least one customer infected; visitors to MonPass website',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Website compromised; binary installer backdoored with Cobalt Strike'
    },
    {
        'Incident Date': '2021-07-01',
        'Incident Name': 'Synnex IT distribution breach',
        'Target Industry': 'Technology Distribution',
        'Attack Vector': 'Credential compromise; Cloud access',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Synnex; Microsoft cloud customer applications; US Republican National Committee (RNC)',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'ENISA Threat Landscape for Supply Chain Attacks',
        'Source URL': 'https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks',
        'Notes': 'Possibly connected to Kaseya MSP attacks; RNC accessed through Microsoft cloud'
    },
]

# ============================================================
# PART 4: Additional well-documented incidents (2022-2026)
# Not in the three primary sources but widely reported
# ============================================================

additional_incidents = [
    {
        'Incident Date': '2022-12-25',
        'Incident Name': 'PyTorch nightly dependency confusion (torchtriton)',
        'Target Industry': 'AI/ML/Open Source',
        'Attack Vector': 'Dependency confusion; Malicious package',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'PyTorch; PyPI; users of PyTorch nightly builds; system data stolen',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'Public reporting',
        'Source URL': 'https://news.sophos.com/en-us/2023/01/01/pytorch-machine-learning-toolkit-pwned-from-christmas-to-new-year/',
        'Notes': 'Malicious torchtriton package on PyPI with same name as internal PyTorch package; data-stealing malware'
    },
    {
        'Incident Date': '2023-03-29',
        'Incident Name': '3CX DesktopApp trojanized (Operation SmoothOperator)',
        'Target Industry': 'Enterprise Communications/VoIP',
        'Attack Vector': 'Build system compromise; Code injection; Double supply chain attack',
        'Attributed Actor Type': 'APT (Lazarus Group / UNC4736, DPRK)',
        'Impacted Entities': '3CX; 600,000+ customers; 12M daily users; financial services, critical infrastructure, technology sectors',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'APT',
        'Source': 'Public reporting (CISA, Mandiant, SentinelOne)',
        'Source URL': 'https://threatpedia.wiki/campaigns/lazarus-3cx-supply-chain-compromise-2023/',
        'Notes': 'Double supply chain: 3CX build env compromised via trojanized X_TRADER; ICONIC Stealer and POOLRAT deployed'
    },
    {
        'Incident Date': '2023-05-31',
        'Incident Name': 'MOVEit Transfer (CVE-2023-34362) mass exploitation',
        'Target Industry': 'Managed File Transfer/Enterprise Software',
        'Attack Vector': 'Vulnerability exploitation (SQL injection); Data exfiltration',
        'Attributed Actor Type': 'Cybercriminal (Cl0p ransomware group)',
        'Impacted Entities': 'Progress Software; 2,700+ organizations; 95M+ records; federal agencies, universities, healthcare, financial services',
        'Financial Cost': '~$2,700,000,000 (IBM Security estimate)',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'Public reporting (CISA, IBM Security)',
        'Source URL': 'https://databreachcost.com/case/moveit-2023',
        'Notes': 'SQL injection zero-day; LEMURLOOT webshell; pure data extortion campaign; largest supply-chain breach by economic impact'
    },
    {
        'Incident Date': '2023-10-19',
        'Incident Name': 'Okta support system breach',
        'Target Industry': 'Identity/Access Management',
        'Attack Vector': 'Credential compromise; Session token theft',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Okta; 134 customers (<1%); 1Password, BeyondTrust, Cloudflare; all Okta certified users',
        'Financial Cost': 'Okta shares fell 11%',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'Public reporting',
        'Source URL': 'https://www.manageengine.com/blog/it-security/understanding-the-okta-supply-chain-attack-of-2023-a-comprehensive-analysis.html',
        'Notes': 'Employee personal Google account compromised on work laptop; HAR files with session tokens stolen'
    },
    {
        'Incident Date': '2025-03-14',
        'Incident Name': 'tj-actions/changed-files GitHub Action compromise',
        'Target Industry': 'CI/CD/Developer Tools',
        'Attack Vector': 'CI/CD compromise; Credential compromise; Tag retagging',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'GitHub Actions; 23,000+ repositories; CI runner credentials exposed in build logs',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'Public reporting (CVE-2025-30066)',
        'Source URL': 'https://www.bleepingcomputer.com/news/security/popular-github-action-tj-actions-changed-files-is-compromised/',
        'Notes': 'Compromised bot account PAT; 350+ version tags retagged to malicious commit; credentials dumped to public logs'
    },
    {
        'Incident Date': '2025-09-08',
        'Incident Name': 'NPM chalk/debug + 17 packages compromise (Great NPM Heist)',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Phishing; Account takeover; Code injection; Malicious package',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'NPM; chalk, debug, 17+ packages; 2B+ combined weekly downloads; crypto wallet hijacking',
        'Financial Cost': 'Minimal (2-hour live window); rapid community detection',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'Public reporting',
        'Source URL': 'https://intel.threadlinqs.com/threat/TL-2026-1714',
        'Notes': 'Phishing from fake npmjs.help domain; 2FA intercepted; crypto transaction hijacking in browser context'
    },
    {
        'Incident Date': '2025-11-21',
        'Incident Name': 'Shai-Hulud 2.0 npm worm',
        'Target Industry': 'Open Source/Package Registry',
        'Attack Vector': 'Self-propagating worm; Account takeover; Preinstall execution',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': '25,000+ GitHub repositories; hundreds of maintainers; 100M+ combined monthly downloads; Zapier, ENS Domains, PostHog, Postman',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'Public reporting',
        'Source URL': 'https://securityboulevard.com/2026/07/the-7-biggest-supply-chain-attacks-of-2026/',
        'Notes': 'Self-propagating npm worm; preinstall execution; fake Bun runtime disguise; blockchain-based C2'
    },
    {
        'Incident Date': '2025-12-24',
        'Incident Name': 'Trust Wallet Chrome extension hack',
        'Target Industry': 'Cryptocurrency/Browser Extensions',
        'Attack Vector': 'Account takeover; Code injection; Credential compromise',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'Trust Wallet; ~2,500 wallets; Chrome Web Store users',
        'Financial Cost': '$8,500,000',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'Public reporting',
        'Source URL': 'https://securityboulevard.com/2026/07/the-7-biggest-supply-chain-attacks-of-2026/',
        'Notes': 'Credentials stolen via Shai-Hulud; trojanized extension v2.68 published; wallet seed phrases captured'
    },
    {
        'Incident Date': '2026-03-09',
        'Incident Name': 'AppsFlyer SDK crypto wallet swap',
        'Target Industry': 'Mobile/Web Analytics',
        'Attack Vector': 'CDN compromise; Code injection',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'AppsFlyer; 100,000+ web and mobile applications; 48-hour compromise window',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'Public reporting',
        'Source URL': 'https://securityboulevard.com/2026/07/the-7-biggest-supply-chain-attacks-of-2026/',
        'Notes': 'AppsFlyer Web SDK modified on CDN to intercept and swap crypto wallet addresses; legitimate analytics continued'
    },
    {
        'Incident Date': '2026-03-01',
        'Incident Name': 'Trivy/CanisterWorm npm self-propagating attack',
        'Target Industry': 'Security Tools/Open Source',
        'Attack Vector': 'Self-propagating worm; Account takeover; Malicious package',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'Trivy vulnerability scanner; 47 npm packages; thousands of downloads',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'Public reporting',
        'Source URL': 'https://securityboulevard.com/2026/07/the-7-biggest-supply-chain-attacks-of-2026/',
        'Notes': 'Self-propagating; ICP canister blockchain-based C2; first documented use of blockchain for malware C2'
    },
    {
        'Incident Date': '2026-07-11',
        'Incident Name': 'Jscrambler npm package compromise',
        'Target Industry': 'Security Software/Open Source',
        'Attack Vector': 'Account takeover; Malicious package; Code injection',
        'Attributed Actor Type': 'Cybercriminal / Financially motivated',
        'Impacted Entities': 'Jscrambler; npm users; cloud credentials, CI tokens, browser sessions, crypto wallets targeted',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'Public reporting',
        'Source URL': 'https://securityboulevard.com/2026/07/the-7-biggest-supply-chain-attacks-of-2026/',
        'Notes': 'Hijacked publishing credential; preinstall hook dropped cross-platform infostealer'
    },
    {
        'Incident Date': '2025-08-01',
        'Incident Name': 'Salesloft/Drift OAuth token compromise',
        'Target Industry': 'Sales/Marketing Software',
        'Attack Vector': 'OAuth token compromise; Credential compromise',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Salesloft; Drift; 700+ organizations; CRM, cloud, collaboration, email systems',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'Public reporting',
        'Source URL': 'https://cyberint.com/blog/research/recent-supply-chain-attacks-examined/',
        'Notes': 'OAuth refresh tokens compromised; no direct credentials or malware required'
    },
]

# ============================================================
# PART 4b: Physical/operational supply chain attacks
# Broader supply-chain category: cyberattacks on physical/logistics
# supply chain nodes (manufacturing, food, logistics) that cascade
# to downstream operations. Distinct from software-only supply
# chain compromises but relevant for comparative analysis.
# ============================================================

physical_supply_chain_incidents = [
    {
        'Incident Date': '2021-05-30',
        'Incident Name': 'JBS Foods ransomware (REvil)',
        'Target Industry': 'Food/Meat Processing',
        'Attack Vector': 'Ransomware; Credential/access compromise (initial vector undisclosed)',
        'Attributed Actor Type': 'Cybercriminal (REvil ransomware group)',
        'Impacted Entities': 'JBS S.A./JBS USA; JBS Canada; JBS Australia; ~20% of U.S. beef and pork processing capacity',
        'Financial Cost': '$11,000,000 ransom paid; ~$100,000,000 total business impact (JBS estimate)',
        'APT vs Opportunistic': 'Opportunistic',
        'Source': 'Public reporting',
        'Source URL': 'https://www.cyberbreaches.org/en/incidents/jbs-foods-2021',
        'Notes': 'Physical/operational supply chain attack (not software supply chain). REvil dwelled ~3 months before detonating ransomware simultaneously across three countries; White House engaged Russian government; FBI attributed to REvil.'
    },
    {
        'Incident Date': '2022-02-26',
        'Incident Name': 'Kojima Industries ransomware halts Toyota production',
        'Target Industry': 'Automotive Manufacturing',
        'Attack Vector': 'Ransomware; Tier-1 supplier compromise (initial vector/actor undisclosed)',
        'Attributed Actor Type': 'Unknown / Not attributed (no confirmed attribution)',
        'Impacted Entities': 'Kojima Industries (Toyota Tier-1 supplier); Toyota (all 14 Japanese plants); Hino Motors; Daihatsu; ~13,000 vehicles/day lost production',
        'Financial Cost': 'Not available',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'Public reporting',
        'Source URL': 'https://www.cyberbreaches.org/en/incidents/toyota-kojima-2022',
        'Notes': 'Physical/operational supply chain attack (not software supply chain). Ransomware on a single Tier-1 parts supplier disrupted Toyota just-in-time manufacturing; no attribution ever confirmed, though timing (post Japan-Russia sanctions) fueled speculation of state-aligned origin.'
    },
    {
        'Incident Date': '2026-07-13',
        'Incident Name': 'Nichirei cold-chain logistics cyberattack',
        'Target Industry': 'Food/Cold-Chain Logistics',
        'Attack Vector': 'Suspected ransomware/unauthorized server access (vector undisclosed); IT/OT convergence exploited',
        'Attributed Actor Type': 'Unknown / Not attributed',
        'Impacted Entities': 'Nichirei Corporation; Nichirei Logistics (~140 refrigerated distribution centers, ~5,000 customers); KFC Japan; Aeon; Kura Sushi; Nissui; York Benimaru',
        'Financial Cost': 'Not available (financial impact still being assessed as of disclosure)',
        'APT vs Opportunistic': 'Other/Unknown',
        'Source': 'Public reporting',
        'Source URL': 'https://www.salmonbusiness.com/nichirei-cyberattack-sends-shockwaves-through-japans-food-supply-chain/',
        'Notes': 'Physical/operational supply chain attack (not software supply chain). Compromise of Japan\'s largest cold-storage logistics network cascaded to multiple consumer-facing food and retail brands within days; personal data exposure reported to Japan\'s Personal Information Protection Commission; recovery began July 17, 2026.'
    },
]

# ============================================================
# PART 5: Consolidate, deduplicate, and write CSV
# ============================================================

def deduplicate(incidents):
    """Deduplicate incidents by matching on name similarity and date proximity."""
    seen = []
    deduped = []
    
    for inc in incidents:
        name_lower = inc['Incident Name'].lower()
        date = inc['Incident Date']
        
        # Check if this is a duplicate of something already seen
        is_dup = False
        for seen_inc in seen:
            seen_name = seen_inc['Incident Name'].lower()
            seen_date = seen_inc['Incident Date']
            
            # Match by key technology/entity in name + same year
            name_words = set(name_lower.split())
            seen_words = set(seen_name.split())
            common = name_words & seen_words
            
            # Check for strong matches
            if len(common) >= 2 and date[:4] == seen_date[:4]:
                # Likely duplicate - merge sources
                if 'Source URL' in seen_inc and inc['Source URL'] not in seen_inc.get('Source URL', ''):
                    seen_inc['Source URL'] += '; ' + inc['Source URL']
                if inc['Source'] not in seen_inc.get('Source', ''):
                    seen_inc['Source'] += '; ' + inc['Source']
                is_dup = True
                break
        
        if not is_dup:
            deduped.append(inc)
            seen.append(inc)  # Same reference so merges propagate to deduped
    
    return deduped

def sort_by_date(incidents):
    """Sort incidents by date (earliest first)."""
    def get_date_key(inc):
        date_str = inc.get('Incident Date', '')
        # Try to parse various formats
        for fmt in ['%Y-%m-%d', '%Y-%m', '%Y']:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return datetime(1900, 1, 1)  # Unknown dates go first
    return sorted(incidents, key=get_date_key)

def main():
    all_incidents = []
    
    # 1. Parse IQT Labs CSV (Atlantic Council Breaking Trust)
    try:
        iqt_rows = parse_iqt_csv('/home/user/workspace/iqt_supply_chain.csv')
        for row in iqt_rows:
            normalized = normalize_iqt_row(row)
            if normalized:
                all_incidents.append(normalized)
        print(f"Parsed {len(iqt_rows)} incidents from IQT Labs CSV (2020+)")
    except Exception as e:
        print(f"Error parsing IQT CSV: {e}")
    
    # 2. Add CNCF catalog incidents
    all_incidents.extend(cncf_incidents)
    print(f"Added {len(cncf_incidents)} incidents from CNCF catalog")
    
    # 3. Add ENISA incidents
    all_incidents.extend(enisa_incidents)
    print(f"Added {len(enisa_incidents)} incidents from ENISA report")
    
    # 4. Add additional incidents
    all_incidents.extend(additional_incidents)
    print(f"Added {len(additional_incidents)} additional incidents from public reporting")

    # 5. Add physical/operational supply chain incidents (broader category)
    all_incidents.extend(physical_supply_chain_incidents)
    print(f"Added {len(physical_supply_chain_incidents)} physical/operational supply chain incidents")

    # Tag every incident with a Category: software vs. physical/operational supply chain
    physical_names = {inc['Incident Name'] for inc in physical_supply_chain_incidents}
    for inc in all_incidents:
        if inc['Incident Name'] in physical_names:
            inc['Category'] = 'Physical/Operational Supply Chain'
        else:
            inc['Category'] = 'Software Supply Chain'
    
    # Deduplicate
    deduped = deduplicate(all_incidents)
    print(f"After deduplication: {len(deduped)} unique incidents")
    
    # Sort by date
    sorted_incidents = sort_by_date(deduped)
    
    # Filter for 2020-01-01 to 2026-07-31
    filtered = []
    for inc in sorted_incidents:
        date_str = inc.get('Incident Date', '')
        if date_str >= '2020-01-01' and date_str <= '2026-07-31':
            filtered.append(inc)
    
    print(f"After date filtering (2020-01-01 to 2026-07-31): {len(filtered)} incidents")
    
    # Write CSV
    fieldnames = [
        'Incident Date',
        'Incident Name',
        'Category',
        'Target Industry',
        'Attack Vector',
        'Attributed Actor Type',
        'Impacted Entities',
        'Financial Cost',
        'APT vs Opportunistic',
        'Source',
        'Source URL',
        'Notes'
    ]
    
    output_path = '/home/user/workspace/software_supply_chain_attacks_2020_2026.csv'
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for inc in filtered:
            # Ensure all fields exist
            row = {k: inc.get(k, '') for k in fieldnames}
            writer.writerow(row)
    
    print(f"\nCSV written to: {output_path}")
    print(f"Total incidents: {len(filtered)}")
    
    # Summary statistics
    apt_count = sum(1 for i in filtered if i.get('APT vs Opportunistic') == 'APT')
    opportunistic_count = sum(1 for i in filtered if i.get('APT vs Opportunistic') == 'Opportunistic')
    other_count = sum(1 for i in filtered if i.get('APT vs Opportunistic') == 'Other/Unknown')
    
    print(f"\n--- Summary Statistics ---")
    print(f"APT-attributed incidents: {apt_count}")
    print(f"Opportunistic attacks: {opportunistic_count}")
    print(f"Other/Unknown: {other_count}")
    
    # Source breakdown
    ac_count = sum(1 for i in filtered if 'Atlantic Council' in i.get('Source', ''))
    cncf_count = sum(1 for i in filtered if 'CNCF' in i.get('Source', ''))
    enisa_count = sum(1 for i in filtered if 'ENISA' in i.get('Source', ''))
    additional_count = sum(1 for i in filtered if 'Public reporting' in i.get('Source', ''))
    
    print(f"\nSource breakdown:")
    print(f"  Atlantic Council Breaking Trust: {ac_count}")
    print(f"  CNCF TAG Security Catalog: {cncf_count}")
    print(f"  ENISA: {enisa_count}")
    print(f"  Additional public reporting: {additional_count}")

if __name__ == '__main__':
    main()
