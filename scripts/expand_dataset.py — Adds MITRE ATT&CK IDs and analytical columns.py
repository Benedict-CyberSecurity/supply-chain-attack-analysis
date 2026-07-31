#!/usr/bin/env python3
"""
expand_dataset.py

Expands the software supply chain attacks dataset (2020-2026) with:
  * 4 additional physical / operational supply chain incidents
    (Colonial Pipeline, Garmin/WastedLocker, Honda/Snake, Maersk/NotPetya)
  * 13 new analytical columns covering MITRE ATT&CK mapping, attacker behavior,
    indicators, artifacts, detection, failure points, compliance, contingency
    planning, disruption type and business impact.

Detailed, publicly-reported values are hard-coded for ~25 landmark incidents.
All remaining rows are populated by deterministic rules-based inference driven
by the existing "Attack Vector", "Target Industry", "Impacted Entities" and
"Financial Cost" fields, so that EVERY row has a value in EVERY column.

Input :  /home/user/workspace/software_supply_chain_attacks_2020_2026.csv
Output:  /home/user/workspace/software_supply_chain_attacks_expanded.csv

Key public sources used for the detailed incident annotations:
  - CISA advisories:                 https://www.cisa.gov/news-events/cybersecurity-advisories
  - MITRE ATT&CK:                    https://attack.mitre.org/techniques/T1195/
  - Mandiant/FireEye SUNBURST:       https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor/
  - SentinelOne 3CX analysis:        https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-teams-3cx-software-in-software-supply-chain-attack/
  - Progress MOVEit advisory:        https://www.progress.com/security/moveit-transfer-and-moveit-cloud-vulnerability
  - US Senate/DOJ Colonial Pipeline: https://www.justice.gov/opa/pr/department-justice-seizes-23-million-cryptocurrency-paid-ransomware-extortionists-darkside
  - Wired, "The Untold Story of NotPetya":  https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/
  - Openwall xz-utils disclosure:    https://www.openwall.com/lists/oss-security/2024/03/29/4
"""

import csv
import os
import sys

SRC = "/home/user/workspace/software_supply_chain_attacks_2020_2026.csv"
DST = "/home/user/workspace/software_supply_chain_attacks_expanded.csv"

BASE_COLUMNS = [
    "Incident Date", "Incident Name", "Category", "Target Industry",
    "Attack Vector", "Attributed Actor Type", "Impacted Entities",
    "Financial Cost", "APT vs Opportunistic", "Source", "Source URL", "Notes",
]

NEW_COLUMNS = [
    "MITRE ATT&CK ID", "Attack Technique", "Attack Behavior", "Attack Indicator",
    "Artifact", "Detection Method", "Time to Detect", "Detection Coverage",
    "Incident Failure Point", "Compliance Status", "Contingency/Backup Plan",
    "Disruption Type", "Business Impact",
]

OUT_COLUMNS = BASE_COLUMNS + NEW_COLUMNS

PHYS = "Physical/Operational Supply Chain"
SOFT = "Software Supply Chain"

# ---------------------------------------------------------------------------
# 1. The four additional physical / operational supply chain incidents
# ---------------------------------------------------------------------------
NEW_INCIDENTS = [
    {
        "Incident Date": "2021-05-07",
        "Incident Name": "Colonial Pipeline ransomware (DarkSide)",
        "Category": PHYS,
        "Target Industry": "Energy/Fuel Pipeline",
        "Attack Vector": "Credential compromise (legacy VPN, no MFA); Ransomware",
        "Attributed Actor Type": "Cybercriminal / Ransomware-as-a-Service (DarkSide)",
        "Impacted Entities": "Colonial Pipeline; fuel distribution across US East Coast; 17 states + DC declared emergency",
        "Financial Cost": "$4.4M ransom paid (~$2.3M recovered by DOJ); regional fuel shortages",
        "APT vs Opportunistic": "Opportunistic",
        "Source": "US DOJ / CISA / Congressional testimony",
        "Source URL": "https://www.justice.gov/opa/pr/department-justice-seizes-23-million-cryptocurrency-paid-ransomware-extortionists-darkside",
        "Notes": "Largest US fuel pipeline shut down for 6 days; catalyst for TSA pipeline security directives",
        "MITRE ATT&CK ID": "T1078 + T1133 + T1486 + T0822 (ICS)",
        "Attack Technique": "Valid Accounts; External Remote Services; Data Encrypted for Impact; External Remote Services (ICS)",
        "Attack Behavior": "DarkSide affiliates logged into a legacy, unused VPN profile using a single compromised password with no MFA, moved through the IT network, exfiltrated ~100GB of data, then deployed DarkSide ransomware against IT systems.",
        "Attack Indicator": "Login to a decommissioned VPN account from an unusual IP; ~100GB outbound data transfer; DarkSide ransom note on operator workstation; encrypted billing/IT file shares",
        "Artifact": "DarkSide ransomware; stolen VPN credential (found in a password dump); commodity remote-access tooling",
        "Detection Method": "Employee discovery - control-room operator found a ransom note on a computer screen",
        "Time to Detect": "8 days (initial access 2021-04-29; discovered 2021-05-07)",
        "Detection Coverage": "No",
        "Incident Failure Point": "VPN credential management - dormant remote-access account without multifactor authentication",
        "Compliance Status": "TSA Security Directive Pipeline-2021-01/02 issued; mandatory CISA incident reporting; Congressional testimony",
        "Contingency/Backup Plan": "Backups existed but restoration judged too slow for billing systems; company paid $4.4M ransom for the decryptor",
        "Disruption Type": "Operational shutdown",
        "Business Impact": "Precautionary shutdown of a 5,500-mile pipeline carrying ~45% of East Coast fuel for six days, triggering panic buying, station outages and an emergency declaration in 17 states and DC.",
    },
    {
        "Incident Date": "2020-07-23",
        "Incident Name": "Garmin WastedLocker ransomware (Evil Corp)",
        "Category": PHYS,
        "Target Industry": "Consumer Electronics/Aviation Navigation Services",
        "Attack Vector": "Credential compromise; Lateral movement; Ransomware",
        "Attributed Actor Type": "Cybercriminal (Evil Corp / INDRIK SPIDER, OFAC-sanctioned)",
        "Impacted Entities": "Garmin Connect users worldwide; flyGarmin/Garmin Pilot aviation database services; call centers; production lines",
        "Financial Cost": "Reported ~$10M ransom paid (unconfirmed by Garmin)",
        "APT vs Opportunistic": "Opportunistic",
        "Source": "BleepingComputer / Sky News reporting; CrowdStrike Evil Corp research",
        "Source URL": "https://www.bleepingcomputer.com/news/security/garmin-outage-caused-by-confirmed-wastedlocker-ransomware-attack/",
        "Notes": "Multi-day global outage of Garmin Connect; OFAC sanctions on Evil Corp created legal exposure around the payment",
        "MITRE ATT&CK ID": "T1486 + T1059.001 + T1003 + T1189",
        "Attack Technique": "Data Encrypted for Impact; Command and Scripting Interpreter: PowerShell; OS Credential Dumping; Drive-by Compromise",
        "Attack Behavior": "Evil Corp gained a foothold via a fake-update/drive-by chain (SocGholish-style), used Cobalt Strike and PowerShell for lateral movement and Mimikatz-style credential dumping, disabled security tooling, then detonated WastedLocker across servers and workstations.",
        "Attack Indicator": "'.garminwasted' encrypted-file extension and matching ransom notes; Cobalt Strike beacons; PsExec/PowerShell mass execution; abrupt failure of Garmin Connect sync APIs",
        "Artifact": "WastedLocker ransomware; Cobalt Strike; Mimikatz; PsExec",
        "Detection Method": "Internal monitoring plus customer-facing service failure (global Garmin Connect outage and support-line collapse)",
        "Time to Detect": "~1 month of pre-encryption dwell time; encryption itself detected same day",
        "Detection Coverage": "No",
        "Incident Failure Point": "Endpoint and lateral-movement controls - flat internal network with insufficient privileged-credential segmentation",
        "Compliance Status": "OFAC sanctions exposure for paying an Evil Corp-linked actor; FAA-regulated aviation database service disruption reported",
        "Contingency/Backup Plan": "Backups insufficient for rapid restoration at scale; a decryptor was reportedly obtained via a ~$10M payment brokered through a third party",
        "Disruption Type": "Operational shutdown",
        "Business Impact": "Garmin Connect, flyGarmin, Garmin Pilot, call centers and some Taiwan production lines were down for several days, blocking pilot navigation-database updates and consumer fitness sync worldwide.",
    },
    {
        "Incident Date": "2020-06-08",
        "Incident Name": "Honda Snake/EKANS ransomware production halt",
        "Category": PHYS,
        "Target Industry": "Automotive Manufacturing",
        "Attack Vector": "Ransomware (ICS-aware); Internet-exposed remote access",
        "Attributed Actor Type": "Cybercriminal / Unknown operator (Snake/EKANS)",
        "Impacted Entities": "Honda global IT network; plants in Ohio, Turkey, India, Brazil; customer service and financial services systems",
        "Financial Cost": "Not disclosed (multi-day production loss across several plants)",
        "APT vs Opportunistic": "Opportunistic",
        "Source": "BBC / Dragos EKANS analysis",
        "Source URL": "https://www.bbc.com/news/technology-52982427",
        "Notes": "Snake/EKANS samples referenced Honda-specific internal hostnames, indicating targeted deployment against OT-adjacent IT",
        "MITRE ATT&CK ID": "T1486 + T1489 + T1133",
        "Attack Technique": "Data Encrypted for Impact; Service Stop; External Remote Services",
        "Attack Behavior": "Operators deployed Snake/EKANS ransomware configured with Honda-specific internal domain references; the malware killed industrial and database processes before encrypting files, disrupting the IT systems that feed manufacturing operations.",
        "Attack Indicator": "EKANS sample containing internal Honda hostname/domain check; mass termination of ICS-related and database services; unreachable internal servers; halted production-line scheduling",
        "Artifact": "Snake/EKANS ransomware",
        "Detection Method": "Internal detection via production and network failures (plants unable to reach internal systems)",
        "Time to Detect": "Unknown pre-encryption dwell; impact detected within hours of encryption",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "IT/OT segmentation - manufacturing-dependent IT services reachable from a compromised enterprise network",
        "Compliance Status": "Not reported (public statements only; no regulatory action disclosed)",
        "Contingency/Backup Plan": "Manual fallback and staged restoration used; most plants resumed within days, one US plant remained down longer",
        "Disruption Type": "Operational shutdown",
        "Business Impact": "Vehicle and motorcycle production was suspended at multiple international plants and customer service/financial services systems were taken offline, with most sites restarting within one to several days.",
    },
    {
        "Incident Date": "2017-06-27",
        "Incident Name": "Maersk NotPetya destructive supply chain attack",
        "Category": PHYS,
        "Target Industry": "Shipping/Global Logistics",
        "Attack Vector": "Update mechanism compromise (M.E.Doc accounting software); Wiper/pseudo-ransomware; Credential harvesting + EternalBlue propagation",
        "Attributed Actor Type": "Nation-state (Russian GRU / Sandworm, per US, UK and EU attributions)",
        "Impacted Entities": "A.P. Moller-Maersk (76 port terminals, 800 vessels); Merck, FedEx/TNT, Mondelez, Saint-Gobain and hundreds of other firms",
        "Financial Cost": "$250-300M impact to Maersk; ~$10B global damage estimate",
        "APT vs Opportunistic": "APT",
        "Source": "Wired / Maersk public statements / UK NCSC attribution",
        "Source URL": "https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/",
        "Notes": "PRE-2020 INCIDENT (2017) - included at user request as the canonical physical/logistics supply chain catastrophe; predates the 2020-2026 window of the rest of the dataset",
        "MITRE ATT&CK ID": "T1195.002 + T1486 + T1561.002 + T1210 + T1003.001",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Supply Chain; Data Encrypted for Impact; Disk Structure Wipe; Exploitation of Remote Services; OS Credential Dumping: LSASS Memory",
        "Attack Behavior": "Sandworm backdoored the update server of Ukrainian M.E.Doc tax software and pushed NotPetya, which harvested credentials from memory and spread via PsExec/WMI and the EternalBlue/EternalRomance SMB exploits, then overwrote the master boot record - encryption was irreversible by design.",
        "Attack Indicator": "M.E.Doc update package delivering perfc.dat; mass LSASS access and PsExec/WMI execution; SMB exploitation traffic on 445/TCP; simultaneous fleet-wide reboots showing a fake CHKDSK screen and MBR ransom note",
        "Artifact": "NotPetya (ExPetr/Nyetya) wiper; EternalBlue/EternalRomance exploits; Mimikatz-derived credential stealer; PsExec",
        "Detection Method": "Immediate self-evident detection - screens across offices and terminals went dark within minutes as machines encrypted and rebooted",
        "Time to Detect": "Minutes (destruction was instantaneous); root-cause tracing to M.E.Doc took days",
        "Detection Coverage": "No",
        "Incident Failure Point": "Third-party software update integrity plus unpatched SMB and flat network trust; no offline/immutable domain-controller backups",
        "Compliance Status": "Insurance dispute over 'act of war' exclusions (NotPetya cyber-insurance litigation); state attribution by US/UK/EU governments; breach notifications by multiple affected multinationals",
        "Contingency/Backup Plan": "No usable offline backups of Active Directory; recovery depended on a single surviving domain-controller backup found in Ghana; 45,000 PCs and 4,000 servers rebuilt from scratch",
        "Disruption Type": "Operational shutdown",
        "Business Impact": "Maersk's global booking and terminal-operating systems were destroyed, halting container gates at 76 ports and forcing ten days of manual operations, with roughly $250-300M in losses and cascading delays across world trade.",
    },
]

# ---------------------------------------------------------------------------
# 2. Detailed analytical data for ~25 landmark incidents
#    Keyed by a distinctive substring of the incident name (case-insensitive).
# ---------------------------------------------------------------------------
DETAILED = {
    "solarwinds orion": {
        "MITRE ATT&CK ID": "T1195.002 + T1078.004 + T1071.001 + T1554 + T1027 + T1550.001 + T1606.002",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Supply Chain; Valid Accounts: Cloud Accounts; Application Layer Protocol: Web Protocols; Compromise Host Software Binary; Obfuscated Files or Information; Use Alternate Authentication Material; Forge Web Credentials: SAML Tokens",
        "Attack Behavior": "APT29/UNC2452 implanted SUNSPOT into the SolarWinds Orion build pipeline so that the SUNBURST backdoor was inserted into legitimately signed Orion updates; from selected victims they escalated to Teardrop/Raindrop loaders, stole AD FS token-signing certificates and forged SAML tokens to reach cloud email.",
        "Attack Indicator": "Signed SolarWinds.Orion.Core.BusinessLayer.dll with anomalous hash; avsvmcloud[.]com DGA subdomain beaconing; jittered 12+ hour first callback delay; anomalous SAML tokens with long lifetimes; new service principals/credentials added to Azure AD applications",
        "Artifact": "SUNBURST (Solorigate) backdoor; SUNSPOT build injector; Teardrop and Raindrop Cobalt Strike loaders; GOLDMAX/SIBOT/GOLDFINDER; SUPERNOVA webshell",
        "Detection Method": "Third-party report - FireEye/Mandiant discovered it while investigating its own breach (an anomalous MFA device enrollment) and disclosed publicly",
        "Time to Detect": "~9 months (build system access from ~September 2019/March 2020 trojanized builds; disclosed December 2020)",
        "Detection Coverage": "No",
        "Incident Failure Point": "Build system integrity - no verification that compiled artifacts matched reviewed source, and code-signing applied to a tampered build",
        "Compliance Status": "SEC disclosure required (SolarWinds 8-K; later SEC enforcement action against the company and its CISO); CISA Emergency Directive 21-01 for federal agencies",
        "Contingency/Backup Plan": "Backups available; victims rebuilt Orion servers and rotated credentials/certificates, though token-signing key theft required full identity-trust reissuance",
        "Disruption Type": "Data breach",
        "Business Impact": "About 18,000 organizations received the trojanized update and roughly 100 were actively exploited, including nine US federal agencies, forcing government-wide disconnection of Orion, mass credential resets and a multi-year loss of trust in signed vendor updates.",
    },
    "3cx desktopapp": {
        "MITRE ATT&CK ID": "T1195.002 + T1574.001 + T1553.002 + T1027.003 + T1071.001",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Supply Chain; Hijack Execution Flow: DLL Search Order Hijacking; Subvert Trust Controls: Code Signing; Obfuscated Files or Information: Steganography; Application Layer Protocol: Web Protocols",
        "Attack Behavior": "North Korean operators (UNC4736/Labyrinth Chollima) first compromised 3CX via a trojanized X_TRADER financial app on an employee machine, then poisoned 3CX's own build to ship signed installers that side-loaded malicious DLLs and pulled encrypted C2 config from icon files in a GitHub repo.",
        "Attack Indicator": "Signed 3CXDesktopApp shipping ffmpeg.dll/d3dcompiler_47.dll with appended encrypted payload; ICO files in a GitHub repo containing base64 C2 strings; beaconing to azureonlinecloud[.]com and similar look-alike domains; EDR alerts on 3CXDesktopApp.exe spawning network activity",
        "Artifact": "ICONICSTEALER info-stealer; POOLRAT/SIMPLESEA macOS backdoor; VEILEDSIGNAL modular backdoor; TAXHAUL/COLDCAT loaders; trojanized X_TRADER (VEILEDSIGNAL) as the upstream vector",
        "Detection Method": "Researcher/vendor disclosure - SentinelOne, CrowdStrike and Sophos telemetry flagged the signed 3CX binary before 3CX confirmed",
        "Time to Detect": "~4 months (initial employee compromise ~November-December 2022; trojanized builds detected late March 2023)",
        "Detection Coverage": "No",
        "Incident Failure Point": "Build environment compromise - developer workstation malware reached the release pipeline and signed artifacts were never independently validated",
        "Compliance Status": "CISA/vendor advisories issued; customer breach notifications; sanctions-relevant DPRK attribution",
        "Contingency/Backup Plan": "Clean rebuild of build infrastructure and re-issued installers; Mandiant-led IR and certificate/credential rotation",
        "Disruption Type": "Data breach",
        "Business Impact": "A vendor with roughly 600,000 customer organizations and 12 million daily users shipped malware to Windows and macOS users, forcing emergency uninstall/rollback across enterprises and the first widely documented cascading double software supply chain compromise.",
    },
    "moveit transfer": {
        "MITRE ATT&CK ID": "T1190 + T1505.003 + T1567 + T1486",
        "Attack Technique": "Exploit Public-Facing Application; Server Software Component: Web Shell; Exfiltration Over Web Service; Data Encrypted for Impact (extortion without encryption in most cases)",
        "Attack Behavior": "CL0P exploited a SQL injection zero-day (CVE-2023-34362) in Progress MOVEit Transfer to plant the LEMURHUMAN/LEMURLOOT webshell (human2.aspx), enumerate Azure/SQL storage credentials and bulk-exfiltrate transferred files for extortion.",
        "Attack Indicator": "human2.aspx or similar unexpected .aspx files in the MOVEit wwwroot; new sysadmin-level MOVEit user 'Health Check Service'; unusual large outbound transfers; suspicious SQL activity in MOVEit database logs",
        "Artifact": "LEMURLOOT (human2.aspx) webshell; CL0P extortion infrastructure; custom SQL injection exploit for CVE-2023-34362",
        "Detection Method": "Customer reports of suspicious activity plus vendor investigation; Progress published an advisory and emergency patch",
        "Time to Detect": "~4 days of mass exploitation before public detection (activity from ~2023-05-27; advisory 2023-05-31); earlier probing observed in 2021-2022",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "Application security of an internet-facing managed file transfer product - unauthenticated SQL injection in a system holding aggregated sensitive data",
        "Compliance Status": "SEC and state breach-notification filings by many victims; HIPAA notifications (health data); GDPR notifications in the EU/UK; class-action litigation",
        "Contingency/Backup Plan": "Backups largely unaffected (data theft, not destruction); response focused on patching, webshell removal and mass notification",
        "Disruption Type": "Data breach",
        "Business Impact": "More than 2,700 organizations and an estimated 90+ million individuals were affected through a single file-transfer product, generating one of the largest multi-year notification and litigation cascades on record.",
    },
    "kaseya vsa": {
        "MITRE ATT&CK ID": "T1190 + T1195.002 + T1486 + T1562.001",
        "Attack Technique": "Exploit Public-Facing Application; Supply Chain Compromise: Compromise Software Supply Chain; Data Encrypted for Impact; Impair Defenses: Disable or Modify Tools",
        "Attack Behavior": "REvil affiliates exploited authentication-bypass and code-injection zero-days (CVE-2021-30116 chain) in on-premises Kaseya VSA servers to push a fake 'Kaseya VSA Agent Hot-fix' that disabled Defender and ran REvil ransomware on downstream MSP customer endpoints.",
        "Attack Indicator": "agent.crt/agent.exe dropped into c:\\kworking; certutil-based decoding; Defender exclusions added via PowerShell; simultaneous encryption across many unrelated customers of one MSP",
        "Artifact": "REvil/Sodinokibi ransomware; trojanized Kaseya agent hotfix; legitimate but abused MsMpEng.exe side-loading of mpsvc.dll",
        "Detection Method": "Internal monitoring - Kaseya's own detection plus near-simultaneous MSP reports; Kaseya shut down SaaS and told customers to take VSA offline within hours",
        "Time to Detect": "~2 hours from exploitation to Kaseya shutdown notice",
        "Detection Coverage": "Yes",
        "Incident Failure Point": "Vulnerability management in a highly privileged remote-management platform (known-but-unpatched zero-days in an agent with SYSTEM rights)",
        "Compliance Status": "CISA-FBI joint guidance issued; White House response and later DOJ indictment/arrests; customer breach notifications",
        "Contingency/Backup Plan": "Mixed - many MSPs restored from backups; a universal decryptor was later obtained by the FBI and distributed, and Kaseya stated it did not pay",
        "Disruption Type": "Service disruption",
        "Business Impact": "Roughly 50-60 MSPs and up to 1,500 downstream businesses were encrypted over a holiday weekend, closing hundreds of Coop supermarkets in Sweden and schools in New Zealand, against a $70M collective ransom demand.",
    },
    "jbs foods": {
        "MITRE ATT&CK ID": "T1486 + T1078 + T1567",
        "Attack Technique": "Data Encrypted for Impact; Valid Accounts; Exfiltration Over Web Service",
        "Attack Behavior": "REvil affiliates obtained access to JBS's network months before deployment, staged and exfiltrated data, then encrypted servers supporting North American and Australian beef and pork processing operations.",
        "Attack Indicator": "Long-running unauthorized access to internal servers; REvil ransom note and encrypted plant scheduling systems; outbound staging of company data",
        "Artifact": "REvil/Sodinokibi ransomware",
        "Detection Method": "Internal monitoring - IT teams detected irregular activity affecting North American and Australian servers",
        "Time to Detect": "~3 months of dwell time before encryption (access from ~February-March 2021; encryption late May 2021)",
        "Detection Coverage": "No",
        "Incident Failure Point": "Credential/access management and network segmentation across a global multi-plant OT-adjacent IT estate",
        "Compliance Status": "US Congressional inquiry and testimony; USDA/White House engagement; ransom payment publicly disclosed",
        "Contingency/Backup Plan": "Encrypted backup servers were unaffected in part, but JBS paid an $11M ransom to limit further disruption and data exposure",
        "Disruption Type": "Operational shutdown",
        "Business Impact": "All US beef plants and multiple Australian and Canadian facilities halted for roughly a day or more, cutting US beef slaughter capacity by about a fifth and briefly moving wholesale meat prices.",
    },
    "kojima": {
        "MITRE ATT&CK ID": "T1486 + T1078",
        "Attack Technique": "Data Encrypted for Impact; Valid Accounts",
        "Attack Behavior": "Attackers compromised Tier-1 plastic parts supplier Kojima Industries and deployed ransomware that disabled the file servers used to exchange just-in-time production data with Toyota's kanban system.",
        "Attack Indicator": "File server anomaly and threatening message discovered by Kojima staff; loss of EDI/kanban connectivity to Toyota; encrypted supplier production files",
        "Artifact": "Ransomware (family not publicly confirmed)",
        "Detection Method": "Internal detection - supplier staff noticed a file server malfunction and an accompanying ransom message",
        "Time to Detect": "Unknown pre-encryption dwell; disruption detected within hours",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "Third-party/supplier security assurance - a small Tier-1 supplier's IT became a single point of failure for just-in-time production",
        "Compliance Status": "Not reported (prompted Japanese METI supply chain cybersecurity guidance to manufacturers)",
        "Contingency/Backup Plan": "Unknown at supplier; Toyota's contingency was a one-day production stop and manual restart once data exchange resumed",
        "Disruption Type": "Operational shutdown",
        "Business Impact": "Toyota suspended operations at all 14 domestic plants and 28 lines for a day, cutting roughly 13,000 vehicles of output and demonstrating how one small supplier can idle a global manufacturer.",
    },
    "nichirei": {
        "MITRE ATT&CK ID": "T1486 (suspected) + T1190",
        "Attack Technique": "Data Encrypted for Impact (suspected); Exploit Public-Facing Application",
        "Attack Behavior": "Unauthorized access to Nichirei group servers disabled the systems coordinating temperature-controlled warehousing and distribution, with indicators consistent with ransomware deployment.",
        "Attack Indicator": "Sudden failure of order-processing and warehouse management systems; unauthorized server access detected; inability to issue shipping instructions",
        "Artifact": "Unconfirmed (suspected ransomware)",
        "Detection Method": "Internal detection via system failures - operations staff found core logistics systems unavailable",
        "Time to Detect": "Unknown (impact detected same day as system failures)",
        "Detection Coverage": "Unknown",
        "Incident Failure Point": "Resilience of centralized logistics IT with no manual fallback for cold-chain scheduling",
        "Compliance Status": "Japanese personal information protection notification/disclosure obligations under review",
        "Contingency/Backup Plan": "Partial manual/phone-and-fax fallback for shipping instructions during restoration",
        "Disruption Type": "Operational shutdown",
        "Business Impact": "Frozen and chilled food distribution to supermarkets, convenience stores and restaurants was delayed as cold-chain ordering and warehouse systems went offline, cascading into downstream retail stockouts.",
    },
    "codecov": {
        "MITRE ATT&CK ID": "T1195.002 + T1552.001 + T1078.004 + T1567",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Supply Chain; Unsecured Credentials: Credentials In Files; Valid Accounts: Cloud Accounts; Exfiltration Over Web Service",
        "Attack Behavior": "An error in Codecov's Docker image creation process exposed a credential that let the attacker modify the widely used Bash Uploader script so that every CI run exported its environment variables - including cloud keys and tokens - to an attacker-controlled server.",
        "Attack Indicator": "Unexpected curl POST to 178.62.86.114 in CI logs; altered checksum of codecov-bash uploader; subsequent unauthorized use of leaked CI secrets and Git tokens",
        "Artifact": "Modified Codecov Bash Uploader script (one-line curl exfiltration)",
        "Detection Method": "Customer report - a client noticed a checksum mismatch between the served Bash Uploader and the GitHub source",
        "Time to Detect": "~2 months (modification 2021-01-31; discovered/disclosed 2021-04-01/15)",
        "Detection Coverage": "No",
        "Incident Failure Point": "Artifact integrity and secret hygiene - unsigned, unverified CI script served over the network with no checksum enforcement",
        "Compliance Status": "Customer breach notifications (e.g. HashiCorp GPG key rotation, Rapid7 and Twilio disclosures); federal investigation reported",
        "Contingency/Backup Plan": "Remediation via mass credential rotation and signing-key replacement rather than restoration; no data destruction",
        "Disruption Type": "Credential theft",
        "Business Impact": "Secrets from CI pipelines across an estimated 29,000 customers were exposed, forcing industry-wide token and signing-key rotation at companies including HashiCorp, Twilio, Rapid7 and Monday.com.",
    },
    "xz utils": {
        "MITRE ATT&CK ID": "T1195.001 + T1195.002 + T1554 + T1556 + T1608",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools; Compromise Software Supply Chain; Compromise Host Software Binary; Modify Authentication Process; Stage Capabilities",
        "Attack Behavior": "The persona 'Jia Tan' spent roughly two years building maintainer trust in xz-utils, then hid an obfuscated payload in test fixture files that the release-tarball build scripts assembled into liblzma, hooking RSA_public_decrypt so that a specific attacker key granted pre-authentication remote code execution via systemd-linked sshd.",
        "Attack Indicator": "xz 5.6.0/5.6.1 release tarballs differing from the Git tree; binary 'test' files not present in source control; ~500ms extra CPU during sshd logins; Valgrind errors in liblzma; IFUNC resolver hooking symbols in OpenSSL",
        "Artifact": "Backdoored liblzma in xz 5.6.0/5.6.1 (CVE-2024-3094); obfuscated bad-3-corrupt_lzma2.xz / good-large_compressed.lzma test payloads; malicious m4/build-to-host.m4 build script",
        "Detection Method": "Researcher disclosure - Andres Freund investigated sshd performance anomalies and Valgrind errors and reported to oss-security",
        "Time to Detect": "~2 years of social engineering and ~1 month of backdoored releases before discovery",
        "Detection Coverage": "No",
        "Incident Failure Point": "Open-source maintainer trust and release-tarball reproducibility - shipped tarballs were not built from, or comparable to, the reviewed source repository",
        "Compliance Status": "CISA and distribution vendor advisories; CVE-2024-3094 assigned CVSS 10.0; federal SBOM/open-source policy discussion",
        "Contingency/Backup Plan": "Distributions rolled back to xz 5.4.x before wide production exposure; no restoration needed because unstable channels were caught first",
        "Disruption Type": "Backdoor/unauthorized access (potential)",
        "Business Impact": "A near-miss that would have given a single actor remote root on much of the Linux internet had it reached stable Debian, Fedora and Ubuntu releases; forced emergency downgrades and a durable rethink of solo-maintainer dependency risk.",
    },
    "log4j": {
        "MITRE ATT&CK ID": "T1190 + T1059 + T1203",
        "Attack Technique": "Exploit Public-Facing Application; Command and Scripting Interpreter; Exploitation for Client Execution",
        "Attack Behavior": "Attackers sent crafted JNDI lookup strings (for example ${jndi:ldap://...}) in headers, form fields and user agents so that vulnerable Log4j2 versions fetched and executed remote classes, enabling unauthenticated RCE across countless Java applications.",
        "Attack Indicator": "${jndi:ldap/rmi/dns...} patterns in request logs and user-agent strings; outbound LDAP/RMI from application servers; cryptominer, Mirai/Muhstik and Cobalt Strike follow-on payloads",
        "Artifact": "CVE-2021-44228 (Log4Shell) exploit strings; JNDI-Exploit-Kit; follow-on Kinsing, XMRig, Mirai, Muhstik, Cobalt Strike and later Conti/Khonsari ransomware",
        "Detection Method": "Researcher disclosure - reported to Apache by Alibaba Cloud's security team, then rapid public exploitation and vendor detection",
        "Time to Detect": "~2 weeks between first observed in-the-wild exploitation and public disclosure; the flaw itself existed since 2013",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "Transitive dependency visibility - organizations could not inventory where a ubiquitous logging library was embedded",
        "Compliance Status": "CISA Emergency Directive 22-02 and KEV listing; FTC warning of enforcement for failure to remediate; global vendor advisories",
        "Contingency/Backup Plan": "Not applicable to a vulnerability class; response relied on patching, WAF virtual patching and dependency inventory/SBOM efforts",
        "Disruption Type": "Service disruption",
        "Business Impact": "Hundreds of millions of devices and services required emergency patching over the December 2021 holidays, with sustained exploitation against VMware Horizon, ecommerce and government systems and long-tail remediation costs across nearly every enterprise.",
    },
    "polyfill": {
        "MITRE ATT&CK ID": "T1195.002 + T1189 + T1071.001",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Supply Chain; Drive-by Compromise; Application Layer Protocol: Web Protocols",
        "Attack Behavior": "After the polyfill.io domain and GitHub account changed hands, the new operator served conditionally malicious JavaScript from cdn.polyfill.io that redirected mobile users to scam and betting sites while evading admin/devtools sessions.",
        "Attack Indicator": "cdn.polyfill[.]io responses varying by user agent; injected redirects to googie-anaiytics[.]com and similar typosquat domains; delayed mobile-only redirects; Cloudflare/Namecheap intervention notices",
        "Artifact": "Malicious dynamically served polyfill JavaScript; googie-anaiytics[.]com redirect infrastructure",
        "Detection Method": "Researcher disclosure - Sansec published analysis after community warnings about the domain sale",
        "Time to Detect": "~4 months from domain acquisition (February 2024) to confirmed malicious injection reporting (June 2024)",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "Third-party script trust - production sites loading executable code from a remote CDN they did not control, with no SRI or self-hosting",
        "Compliance Status": "PCI DSS 4.0 script-integrity requirements implicated for ecommerce sites; Google ad warnings to affected merchants",
        "Contingency/Backup Plan": "Mitigation by switching to Fastly/Cloudflare mirrors or self-hosted polyfills; Cloudflare auto-rewrote links",
        "Disruption Type": "Malicious code injection / user redirection",
        "Business Impact": "Over 100,000 websites - including major ecommerce and government sites - unknowingly served malicious script to visitors, triggering emergency removal of the dependency and renewed enforcement of subresource integrity.",
    },
    "okta support": {
        "MITRE ATT&CK ID": "T1078 + T1552.004 + T1550.001 + T1539",
        "Attack Technique": "Valid Accounts; Unsecured Credentials: Private Keys; Use Alternate Authentication Material: Application Access Token; Steal Web Session Cookie",
        "Attack Behavior": "An attacker used a stolen service-account credential (saved in a personal Google profile on an Okta-managed laptop) to access Okta's customer support case system and harvest HAR files containing live session tokens, then replayed those tokens against customer tenants.",
        "Attack Indicator": "Support-system access from unusual IPs; bulk downloading of customer HAR files; session-token replay creating admin activity in customer Okta tenants; suspicious IdP additions reported by customers",
        "Artifact": "Stolen HAR files with embedded session cookies; compromised Okta support service account",
        "Detection Method": "Customer report - 1Password (and later BeyondTrust and Cloudflare) reported suspicious activity to Okta before Okta confirmed",
        "Time to Detect": "~2-3 weeks (access from late September 2023; confirmed and disclosed 2023-10-19/20), with the broader case-data exposure disclosed a month later",
        "Detection Coverage": "No",
        "Incident Failure Point": "Support-process data handling and credential management - sensitive HAR artifacts stored with live tokens, and a service account without adequate isolation or MFA",
        "Compliance Status": "SEC 8-K disclosure by Okta; customer breach notifications; regulatory scrutiny of identity-provider controls",
        "Contingency/Backup Plan": "Response by session revocation, token sanitization requirements and administrative MFA enforcement rather than backup restoration",
        "Disruption Type": "Credential theft",
        "Business Impact": "134 customers were directly affected with five suffering session hijacking, and the later disclosure that names/emails of all ~18,400 support customers were taken drove sector-wide changes to HAR handling and admin session policy.",
    },
    "pytorch": {
        "MITRE ATT&CK ID": "T1195.001 + T1552.001 + T1041",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools; Unsecured Credentials: Credentials In Files; Exfiltration Over C2 Channel",
        "Attack Behavior": "An actor uploaded a malicious PyPI package named 'torchtriton', which pip resolved in preference to PyTorch's own private-index dependency, and its binary harvested hostname, /etc/hosts, /etc/passwd, ~/.gitconfig, ~/.ssh and up to 1,000 files per directory to a remote DNS-exfiltration endpoint.",
        "Attack Indicator": "torchtriton package installed from PyPI rather than the PyTorch index; DNS queries to *.h4ck[.]cfd; triton binary reading SSH keys and /etc/passwd; nightly-build environments only",
        "Artifact": "Malicious torchtriton PyPI package with trojanized 'triton' ELF binary; h4ck[.]cfd exfiltration domain",
        "Detection Method": "Researcher/community disclosure followed by PyTorch team investigation and public advisory",
        "Time to Detect": "~5 days (malicious package live 2022-12-25 to 2022-12-30)",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "Package registry resolution order - dependency confusion between a private index and public PyPI, with no namespace reservation",
        "Compliance Status": "Not reported (project advisory and user notification only)",
        "Contingency/Backup Plan": "Package renamed to pytorch-triton and the PyPI name registered as a placeholder; users instructed to uninstall and rotate SSH keys",
        "Disruption Type": "Credential theft",
        "Business Impact": "Machine-learning developers running PyTorch nightly builds over a holiday week had SSH keys and local files exfiltrated, forcing key rotation and hardening of PyPI namespace policy for a project with millions of installs.",
    },
    "npm chalk/debug": {
        "MITRE ATT&CK ID": "T1195.001 + T1566.002 + T1111 + T1557",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools; Phishing: Spearphishing Link; Multi-Factor Authentication Interception; Adversary-in-the-Middle",
        "Attack Behavior": "A phishing email from a look-alike npmjs support domain harvested maintainer credentials and 2FA/TOTP codes, letting the attacker publish trojanized versions of chalk, debug, ansi-styles and 15+ other packages containing a browser-side crypto clipper that silently swapped wallet addresses in window.ethereum and Solana transactions.",
        "Attack Indicator": "Publishes from an unusual IP shortly after a support-themed phishing email from npmjs[.]help; obfuscated 'checkethereumw' function injected into bundled JS; wallet-address substitution using Levenshtein-similar attacker addresses",
        "Artifact": "Trojanized chalk/debug/ansi-styles/color-convert npm versions; browser crypto-clipper payload",
        "Detection Method": "Community/vendor detection - developers and security vendors (Aikido, Socket, Wiz) flagged anomalous releases within roughly two hours",
        "Time to Detect": "~2 hours from malicious publish to public detection and package removal",
        "Detection Coverage": "Yes",
        "Incident Failure Point": "Maintainer account security and publish authorization - phishable TOTP-based 2FA rather than phishing-resistant keys or trusted publishing",
        "Compliance Status": "Not reported (npm/GitHub security advisories; ecosystem-wide notification)",
        "Contingency/Backup Plan": "Rapid version yanking and republication of clean releases; lockfile pinning let most consumers avoid the bad versions",
        "Disruption Type": "Financial fraud",
        "Business Impact": "Packages with over 2 billion weekly downloads combined were briefly poisoned, prompting mass lockfile audits and CI rebuilds across the JavaScript ecosystem, though actual crypto theft was limited to a few hundred dollars because detection was fast.",
    },
    "trust wallet": {
        "MITRE ATT&CK ID": "T1195.002 + T1556 + T1539 + T1552.001",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Supply Chain; Modify Authentication Process; Steal Web Session Cookie; Unsecured Credentials: Credentials In Files",
        "Attack Behavior": "Attackers pushed a trojanized build of the Trust Wallet browser extension through the compromised publishing pipeline, which exfiltrated seed phrases and private keys and rewrote transaction destinations, draining user wallets.",
        "Attack Indicator": "Unexpected extension version update outside the normal release cadence; outbound POSTs of encrypted key material from the extension; unauthorized outbound transfers from many wallets in a short window",
        "Artifact": "Trojanized Trust Wallet extension build; wallet-drainer JavaScript payload",
        "Detection Method": "Customer complaints of unauthorized transfers plus blockchain analysts tracing a common drainer address",
        "Time to Detect": "Hours to days (detected after user funds began moving)",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "Extension release/publishing pipeline integrity and code-signing review for a high-value crypto client",
        "Compliance Status": "Not reported (user notifications and reimbursement commitments; law-enforcement referrals)",
        "Contingency/Backup Plan": "Extension pulled and rolled back to a verified build; users instructed to migrate to new seed phrases",
        "Disruption Type": "Financial fraud",
        "Business Impact": "Roughly $8.5M in user crypto assets was stolen through a single trusted wallet extension update, damaging confidence in browser-extension custody and forcing emergency seed-phrase migration guidance.",
    },
    "retool": {
        "MITRE ATT&CK ID": "T1566.004 + T1621 + T1111 + T1078",
        "Attack Technique": "Phishing: Spearphishing Voice; Multi-Factor Authentication Request Generation; Multi-Factor Authentication Interception; Valid Accounts",
        "Attack Behavior": "An SMS phishing lure plus an AI-voice phone call impersonating IT convinced a Retool employee to hand over an MFA code; because Google Authenticator's new cloud sync mirrored OTP seeds to the compromised Google account, the attacker inherited durable MFA for internal admin systems and pivoted into 27 crypto customer accounts.",
        "Attack Indicator": "SMS with a fake Retool identity-portal link; deepfaked voice call to an employee; Google account sync of Authenticator seeds; admin session takeover and customer account changes",
        "Artifact": "Phishing kit impersonating Retool IdP; AI voice-cloning; abuse of Google Authenticator cloud sync",
        "Detection Method": "Internal monitoring and customer reports of unauthorized account changes; Retool published a post-mortem",
        "Time to Detect": "Hours to days (same-day discovery of the compromised account, with impact confirmed shortly after)",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "MFA design and human process - cloud-synced OTP seeds and no phishing-resistant hardware keys for privileged internal access",
        "Compliance Status": "Not reported (public post-mortem; affected crypto customers notified)",
        "Contingency/Backup Plan": "Credential and MFA reset, migration toward hardware security keys; no data restoration needed",
        "Disruption Type": "Financial fraud",
        "Business Impact": "27 cloud customers - all in crypto - had accounts taken over with about $15M drained from one (Fortress Trust), and the incident became the reference case against cloud-synced MFA seeds in enterprises.",
    },
    "shai-hulud": {
        "MITRE ATT&CK ID": "T1195.001 + T1552.001 + T1078.004 + T1567.001 + T1053",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools; Unsecured Credentials: Credentials In Files; Valid Accounts: Cloud Accounts; Exfiltration to Code Repository; Scheduled Task/Job",
        "Attack Behavior": "The second-generation Shai-Hulud worm ran on npm preinstall, harvested npm/GitHub/cloud tokens with TruffleHog-style scanning, published itself into every package the stolen maintainer token could reach and pushed stolen secrets to public GitHub repositories, adding destructive behavior when no token was found.",
        "Attack Indicator": "preinstall scripts invoking bundled setup_bun.js/bun_environment.js; new public GitHub repos containing secrets with Shai-Hulud branding; unexpected package versions published under many maintainers within minutes; GitHub Actions workflow injection",
        "Artifact": "Shai-Hulud 2.0 npm worm ('The Second Coming'); TruffleHog-based credential scanner; Bun-based loader",
        "Detection Method": "Third-party security research plus registry telemetry - vendors (Wiz, Aikido, Socket, HelixGuard) and GitHub detected mass anomalous publishes",
        "Time to Detect": "Hours (rapid worm propagation detected the same day it began spreading)",
        "Detection Coverage": "Yes",
        "Incident Failure Point": "Lifecycle script execution and token scope - npm install-time code execution combined with long-lived, broadly scoped publish tokens",
        "Compliance Status": "Not reported (npm/GitHub advisories; mandatory token revocation and trusted-publishing rollout)",
        "Contingency/Backup Plan": "Ecosystem response was mass token revocation, version unpublishing and lockfile pinning; some victims restored repos from Git history",
        "Disruption Type": "Credential theft",
        "Business Impact": "Hundreds of npm packages across major vendors were republished with worm code, leaking tens of thousands of developer and cloud secrets and accelerating npm's shift to trusted publishing and short-lived tokens.",
    },
    "appsflyer": {
        "MITRE ATT&CK ID": "T1195.002 + T1189 + T1565.002",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Supply Chain; Drive-by Compromise; Data Manipulation: Transmitted Data Manipulation",
        "Attack Behavior": "Attackers modified the AppsFlyer analytics SDK delivered from the vendor's CDN so that applications embedding it silently substituted attacker-controlled crypto wallet addresses in transaction flows.",
        "Attack Indicator": "Unexpected change in CDN-hosted SDK bundle hash; wallet address mismatch between UI and signed transaction; anomalous outbound calls from the analytics SDK",
        "Artifact": "Trojanized AppsFlyer SDK bundle; wallet-swap (clipper) payload",
        "Detection Method": "Third-party security research and customer reports of mismatched wallet addresses",
        "Time to Detect": "Days (detected after wallet-swap reports surfaced)",
        "Detection Coverage": "Partial",
        "Incident Failure Point": "CDN and third-party SDK integrity - no subresource integrity or signed-artifact verification on a dynamically delivered analytics bundle",
        "Compliance Status": "Not reported (vendor advisory and customer notification)",
        "Contingency/Backup Plan": "Vendor reverted the CDN artifact to a verified build and rotated distribution credentials",
        "Disruption Type": "Financial fraud",
        "Business Impact": "Consumer applications embedding a mainstream analytics SDK became crypto-theft vectors for their own users, forcing emergency SDK version pinning and integrity checks across mobile and web publishers.",
    },
    "tj-actions": {
        "MITRE ATT&CK ID": "T1195.002 + T1552.001 + T1078 + T1195",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Supply Chain; Unsecured Credentials: Credentials In Files; Valid Accounts; Tag retagging of a mutable Git reference",
        "Attack Behavior": "After compromising a bot personal access token (originally via the reviewdog/action-setup action), the attacker retagged all version tags of tj-actions/changed-files to a malicious commit that dumped CI runner memory and printed secrets into public workflow logs.",
        "Attack Indicator": "All tj-actions/changed-files tags pointing to one unexpected commit; workflow logs containing double-base64-encoded secrets; outbound fetch of a gist-hosted Python memory-dump script; CVE-2025-30066",
        "Artifact": "Malicious changed-files commit; memory-scraping Python payload hosted in a GitHub gist; compromised reviewdog/action-setup as upstream vector",
        "Detection Method": "Third-party security research - StepSecurity and Wiz detected anomalous network calls from CI runners and public log leakage",
        "Time to Detect": "~2 days (malicious retag 2025-03-14; public detection and GitHub takedown 2025-03-15/16)",
        "Detection Coverage": "Yes",
        "Incident Failure Point": "CI/CD dependency pinning - referencing mutable Git tags instead of immutable commit SHAs, plus over-privileged bot tokens",
        "Compliance Status": "CISA KEV listing for CVE-2025-30066; GitHub advisory; downstream customer notifications",
        "Contingency/Backup Plan": "GitHub removed the action, maintainers rotated the PAT and republished clean tags; affected repos rotated leaked secrets",
        "Disruption Type": "Credential theft",
        "Business Impact": "More than 23,000 repositories referenced the action and roughly 200 leaked secrets into public logs, driving an industry-wide move to SHA-pinned GitHub Actions and least-privilege workflow tokens.",
    },
    "solana web3.js": {
        "MITRE ATT&CK ID": "T1195.001 + T1078 + T1552.001",
        "Attack Technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools; Valid Accounts; Unsecured Credentials: Credentials In Files",
        "Attack Behavior": "A phishing-driven takeover of an npm publish account allowed release of @solana/web3.js 1.95.6 and 1.95.7 containing an addToQueue backdoor that exfiltrated private keys through a fake CloudFlare header to an attacker server.",
        "Attack Indicator": "Versions 1.95.6/1.95.7 only; 'addToQueue' function sending keys via an X-Cloudflare-* style header to sol-rpc[.]xyz; unauthorized transfers from bot/backend wallets",
        "Artifact": "Backdoored @solana/web3.js 1.95.6/1.95.7; sol-rpc[.]xyz exfiltration endpoint",
        "Detection Method": "Third-party security research and maintainer investigation after community reports of drained wallets",
        "Time to Detect": "~5 hours of exposure window; publicly confirmed within about a day",
        "Detection Coverage": "Yes",
        "Incident Failure Point": "Publish-account security for a critical blockchain SDK - phishable credentials with unrestricted publish rights",
        "Compliance Status": "Not reported (project advisory; affected projects notified)",
        "Contingency/Backup Plan": "Malicious versions deprecated and 1.95.8 released within hours; affected operators rotated keys and moved funds",
        "Disruption Type": "Financial fraud",
        "Business Impact": "An SDK with ~400,000 weekly downloads leaked private keys from server-side bots and custodial services, with roughly $130,000 in crypto stolen before the window closed.",
    },
}

# Additional detailed mappings for a few remaining landmark rows in the CSV
DETAILED.update({
    "great npm heist": DETAILED["npm chalk/debug"],
})

# ---------------------------------------------------------------------------
# 3. Rules-based inference for the remaining incidents
# ---------------------------------------------------------------------------

# vector keyword -> (technique id, technique name, failure point)
VECTOR_RULES = [
    ("build system compromise",        "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Build system integrity"),
    ("ci/cd compromise",               "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "CI/CD pipeline access control"),
    ("update mechanism compromise",    "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Update channel integrity"),
    ("publishing infrastructure",      "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Distribution/publishing infrastructure integrity"),
    ("delivery system compromise",     "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Software delivery channel integrity"),
    ("cdn compromise",                 "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "CDN/third-party script integrity"),
    ("source code compromise",         "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Source repository integrity"),
    ("dependency confusion",           "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Package resolution order / namespace control"),
    ("typosquatting",                  "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Package registry verification"),
    ("malicious package",              "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Package registry verification"),
    ("dependency compromise",          "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Dependency review and pinning"),
    ("dev tooling compromise",         "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Developer tooling trust boundary"),
    ("self-propagating worm",          "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Install-time script execution and token scope"),
    ("malicious maintainer",           "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Maintainer trust and release review"),
    ("firmware implant",               "T1195.003", "Supply Chain Compromise: Compromise Hardware Supply Chain", "Hardware/firmware provenance verification"),
    ("certificate attack",             "T1553.002", "Subvert Trust Controls: Code Signing", "Code-signing key and certificate governance"),
    ("trust and signing compromise",   "T1553.002", "Subvert Trust Controls: Code Signing", "Code-signing trust validation"),
    ("ransomware",                     "T1486",     "Data Encrypted for Impact", "Backup integrity and network segmentation"),
    ("oauth token compromise",         "T1078 + T1550.001", "Valid Accounts; Use Alternate Authentication Material: Application Access Token", "OAuth token scope and lifecycle management"),
    ("account takeover",               "T1078",     "Valid Accounts", "Credential management / account security"),
    ("credential compromise",          "T1078 + T1552", "Valid Accounts; Unsecured Credentials", "Credential management"),
    ("credential/access compromise",   "T1078 + T1552", "Valid Accounts; Unsecured Credentials", "Credential management"),
    ("session token theft",            "T1539",     "Steal Web Session Cookie", "Session token handling"),
    ("phishing",                       "T1566",     "Phishing", "Human/identity controls (phishing resistance)"),
    ("spear phishing",                 "T1566.001", "Phishing: Spearphishing Attachment", "Human/identity controls (phishing resistance)"),
    ("vulnerability exploitation",     "T1190",     "Exploit Public-Facing Application", "Vulnerability management on internet-facing systems"),
    ("misconfigured service",          "T1190",     "Exploit Public-Facing Application", "Configuration management of exposed services"),
    ("server compromise",              "T1190",     "Exploit Public-Facing Application", "Perimeter server hardening"),
    ("code injection",                 "T1059",     "Command and Scripting Interpreter", "Code review and artifact integrity"),
    ("data exfiltration",              "T1567",     "Exfiltration Over Web Service", "Data loss prevention and egress monitoring"),
    ("attack chaining",                "T1195",     "Supply Chain Compromise", "Third-party trust chain validation"),
    ("cloud access",                   "T1078.004", "Valid Accounts: Cloud Accounts", "Cloud identity and access management"),
    ("preinstall execution",           "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Install-time script execution"),
    ("tag retagging",                  "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Immutable dependency pinning"),
    ("malicious documents",            "T1204.002", "User Execution: Malicious File", "Email/document content filtering"),
    ("tier-1 supplier compromise",     "T1486",     "Data Encrypted for Impact", "Third-party/supplier security assurance"),
]

REGISTRY_HINTS = ("npm", "pypi", "pypi ", "rubygems", "packagist", "docker hub",
                  "chrome web store", "google play", "wordpress", "pear",
                  "jfrog", "homebrew", "travis ci", "github", "gem", "pip",
                  "nuget", "crates")


def norm(s):
    return (s or "").strip().lower()


def match_detailed(name):
    n = norm(name)
    for key, data in DETAILED.items():
        if key in n:
            return data
    return None


def vector_mapping(vector):
    """Return (ids, techniques, failure_points) inferred from the Attack Vector."""
    v = norm(vector)
    ids, techs, fails = [], [], []
    for kw, tid, tname, fail in VECTOR_RULES:
        if kw in v:
            for part in tid.split(" + "):
                if part not in ids:
                    ids.append(part)
            if tname not in techs:
                techs.append(tname)
            if fail not in fails:
                fails.append(fail)
    if not ids:
        ids = ["T1195"]
        techs = ["Supply Chain Compromise"]
        fails = ["Third-party trust chain validation"]
    return ids, techs, fails


def is_registry_incident(row):
    hay = norm(row["Incident Name"]) + " " + norm(row["Target Industry"]) + " " + norm(row["Attack Vector"])
    return any(h in hay for h in REGISTRY_HINTS) or "package" in hay or "extension" in hay


def infer_detection_method(row):
    v = norm(row["Attack Vector"])
    if is_registry_incident(row) or any(k in v for k in (
            "firmware implant", "typosquatting", "malicious package",
            "dependency confusion", "malicious maintainer", "certificate attack",
            "trust and signing")):
        return "Third-party security research"
    industry = norm(row["Target Industry"])
    enterprise = any(k in industry for k in (
        "financial", "government", "energy", "manufactur", "health", "telecom",
        "defense", "retail", "transport", "logistics", "aviation", "utility",
        "technology", "it services", "software", "consulting", "insurance",
        "education", "media"))
    if enterprise:
        return "Internal monitoring"
    return "Unknown"


def infer_disruption(row):
    v = norm(row["Attack Vector"]) + " " + norm(row["Notes"]) + " " + norm(row["Incident Name"])
    if "ransomware" in v or "wiper" in v:
        return "Operational shutdown" if row["Category"] == PHYS else "Service disruption"
    if any(k in v for k in ("session token", "credential", "token compromise", "stealer",
                            "credential stealer", "oauth", "password")):
        return "Credential theft"
    if any(k in v for k in ("exfiltration", "data breach", "data theft", "source code")):
        return "Data breach"
    if any(k in v for k in ("crypto", "wallet", "clipper", "miner", "financial fraud", "banking")):
        return "Financial fraud"
    if any(k in v for k in ("backdoor", "implant", "firmware", "trojan")):
        return "Backdoor/unauthorized access"
    if any(k in v for k in ("malicious package", "typosquat", "dependency confusion", "code injection")):
        return "Malicious code injection"
    return "Service disruption"


def infer_behavior(row, ids):
    vector = row["Attack Vector"].strip()
    actor = row["Attributed Actor Type"].strip()
    name = row["Incident Name"].strip()
    return (f"Attacker leveraged {vector.lower()} against {name} to insert or execute "
            f"unauthorized code in the victim's software supply chain; actor profile: {actor}. "
            f"Mapped to {', '.join(ids)} based on the reported vector.")


def infer_indicator(row, ids):
    v = norm(row["Attack Vector"])
    parts = []
    if "typosquat" in v or "malicious package" in v or "dependency confusion" in v:
        parts.append("newly published or renamed package versions with install-time scripts; outbound connections from build/CI hosts")
    if "build system" in v or "ci/cd" in v or "update mechanism" in v or "publishing infrastructure" in v:
        parts.append("signed artifact whose hash does not match reviewed source; unexpected release outside normal cadence")
    if "credential" in v or "account takeover" in v or "oauth" in v:
        parts.append("logins/publishes from unfamiliar IPs or geographies; new API tokens or app credentials")
    if "ransomware" in v:
        parts.append("mass file encryption, ransom note, shadow-copy deletion and service termination")
    if "firmware" in v:
        parts.append("unexpected pre-installed applications or persistent system components on shipped devices")
    if "vulnerability exploitation" in v or "code injection" in v:
        parts.append("exploit attempts in application logs; unexpected web shells or child processes")
    if not parts:
        parts.append("anomalous change to a trusted third-party component; unexpected outbound network activity")
    return "; ".join(parts)


def infer_artifact(row):
    notes = row["Notes"]
    v = norm(row["Attack Vector"])
    if "ransomware" in v:
        return "Ransomware payload (family per public reporting); commodity intrusion tooling"
    if "typosquat" in v or "malicious package" in v or "dependency confusion" in v:
        return "Malicious registry package with install-time script (payload varies: infostealer, backdoor, cryptominer)"
    if "firmware" in v:
        return "Pre-installed firmware/OS-level implant"
    if "certificate" in v or "signing" in v:
        return "Abused code-signing certificate and signed malware"
    if "build system" in v or "update mechanism" in v or "publishing" in v:
        return "Trojanized legitimate installer/update package"
    if "webshell" in norm(notes) or "vulnerability exploitation" in v:
        return "Exploit for a public-facing application; follow-on webshell or loader"
    return "Not publicly detailed"


def infer_time_to_detect(row):
    return "Unknown"


def infer_coverage(row, ttd):
    t = norm(ttd)
    if t in ("", "unknown"):
        return "Unknown"
    if any(k in t for k in ("month", "year")):
        return "No"
    if "hour" in t or "minute" in t:
        return "Yes"
    return "Partial"


def infer_compliance(row):
    industry = norm(row["Target Industry"])
    if "government" in industry or "public sector" in industry or "defense" in industry:
        return "Government incident reporting/advisory (CISA or national CERT)"
    if "health" in industry:
        return "HIPAA/health data breach notification likely required"
    if "financial" in industry or "bank" in industry or "crypto" in industry:
        return "Financial regulator notification likely required"
    return "Not reported"


def infer_business_impact(row):
    ents = row["Impacted Entities"].strip() or "Not specified"
    cost = row["Financial Cost"].strip() or "Not available"
    dis = row["Disruption Type"]
    cost_txt = ("no public financial figure" if cost.lower() in ("not available", "not disclosed", "", "unknown")
                else f"reported financial impact of {cost}")
    return (f"{dis} affecting {ents}; {cost_txt}. Downstream effect flowed through the "
            f"compromised component to dependent organizations and users.")


def enrich(row):
    """Populate the 13 new columns for a single row."""
    # Rows added by this script already carry fully researched values.
    if all(str(row.get(c, "")).strip() for c in NEW_COLUMNS):
        return row

    detailed = match_detailed(row["Incident Name"])
    if detailed:
        for col in NEW_COLUMNS:
            row[col] = detailed.get(col, "Unknown") or "Unknown"
        return row

    ids, techs, fails = vector_mapping(row["Attack Vector"])
    row["MITRE ATT&CK ID"] = " + ".join(ids)
    row["Attack Technique"] = "; ".join(techs)
    row["Attack Behavior"] = infer_behavior(row, ids)
    row["Attack Indicator"] = infer_indicator(row, ids)
    row["Artifact"] = infer_artifact(row)
    row["Detection Method"] = infer_detection_method(row)
    row["Time to Detect"] = infer_time_to_detect(row)
    row["Detection Coverage"] = infer_coverage(row, row["Time to Detect"])
    row["Incident Failure Point"] = "; ".join(fails)
    row["Compliance Status"] = infer_compliance(row)
    row["Contingency/Backup Plan"] = "Unknown"
    row["Disruption Type"] = infer_disruption(row)
    row["Business Impact"] = infer_business_impact(row)
    return row


PHYSICAL_KEYS = ("jbs", "kojima", "nichirei", "colonial pipeline", "garmin",
                 "honda", "maersk")


def set_category(row):
    n = norm(row["Incident Name"])
    row["Category"] = PHYS if any(k in n for k in PHYSICAL_KEYS) else SOFT
    return row


def main():
    if not os.path.exists(SRC):
        sys.exit(f"Input CSV not found: {SRC}")

    with open(SRC, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    print(f"Read {len(rows)} existing rows from {SRC}")

    # normalize existing rows to the base schema
    clean = []
    for r in rows:
        clean.append({c: (r.get(c) or "").strip() for c in BASE_COLUMNS})

    # add the four new physical/operational incidents
    for inc in NEW_INCIDENTS:
        clean.append({c: inc.get(c, "") for c in OUT_COLUMNS})
    print(f"Added {len(NEW_INCIDENTS)} new physical/operational incidents "
          f"-> {len(clean)} total rows")

    out = []
    for r in clean:
        r = set_category(r)
        r = enrich(r)
        # guarantee no blanks anywhere
        for c in OUT_COLUMNS:
            if not str(r.get(c, "")).strip():
                r[c] = "Not reported" if c in ("Compliance Status",) else "Unknown"
        out.append({c: r[c] for c in OUT_COLUMNS})

    out.sort(key=lambda r: (r["Incident Date"], r["Incident Name"]))

    with open(DST, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=OUT_COLUMNS)
        w.writeheader()
        w.writerows(out)

    hand_named = set(i["Incident Name"] for i in NEW_INCIDENTS)
    detailed_n = sum(1 for r in out
                     if match_detailed(r["Incident Name"]) or r["Incident Name"] in hand_named)
    print(f"Wrote {len(out)} rows x {len(OUT_COLUMNS)} columns to {DST}")
    print(f"  Detailed (hand-researched) rows : {detailed_n}")
    print(f"  Rules-inferred rows             : {len(out) - detailed_n}")
    print(f"  Physical/Operational rows       : {sum(1 for r in out if r['Category'] == PHYS)}")
    print(f"  Software Supply Chain rows      : {sum(1 for r in out if r['Category'] == SOFT)}")
    blanks = [(r["Incident Name"], c) for r in out for c in OUT_COLUMNS if not str(r[c]).strip()]
    print(f"  Empty cells                     : {len(blanks)}")


if __name__ == "__main__":
    main()
