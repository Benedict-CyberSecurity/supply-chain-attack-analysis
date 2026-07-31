# Supply Chain Attack Analysis: A Data-Driven GRC Study (2020–2026)

## Overview

This project analyzes **116 software and operational supply chain attacks** from 2020 to July 2026, aggregating data from three authoritative sources and enriching it with MITRE ATT&CK mappings, detection metrics, and governance-layer analysis. The goal is to identify trends, shifts, and gaps in how supply chain risk is governed — and to challenge the conventional narrative that supply chain security is primarily a nation-state APT problem.

## Key Finding: The Governance-Exposure Inversion

Post-SolarWinds GRC frameworks (NIST SSDF, Executive Order 14028) focus on **producer-side build controls** — but the data shows the dominant attack pattern exploits the **consumption and dependency layer**:

| Metric | What GRC Focuses On | What the Data Shows |
|--------|--------------------|--------------------|
| Top MITRE technique | T1195.002 (build system) | T1195.001 (dependency/package compromise) — 48 vs 39 |
| #1 failure point | Build pipeline integrity | Package registry verification — 43 incidents |
| Actor type | Nation-state APT | Opportunistic/criminal — 28 vs 12 APT (71 unknown) |
| Detection | Producer attestations | 67% detected by third parties, not the victim |
| Aggregate cost | APT espionage | Opportunistic attacks drove ~$2.9B in known losses |

## Dataset

**116 incidents × 25 columns** including: Incident Date, Incident Name, Category (Software vs Physical/Operational), Target Industry, Attack Vector, Attributed Actor Type, Impacted Entities, Financial Cost, APT vs Opportunistic flag, MITRE ATT&CK ID, Attack Technique, Attack Behavior, Attack Indicator, Artifact, Detection Method, Time to Detect, Detection Coverage, Incident Failure Point, Compliance Status, Contingency/Backup Plan, Disruption Type, Business Impact, Source, Source URL, and Notes.

### Sources
- **Atlantic Council Breaking Trust** (via IQT Labs CSV) — 42 incidents
- **CNCF TAG Security Catalog** — 37 incidents
- **ENISA Threat Landscape for Supply Chain Attacks** — 23 incidents
- **Supplementary public reporting** (CISA, Mandiant, vendor advisories) — 14 incidents

### Data Confidence
- 25 incidents carry hand-researched analytical data from primary sources
- 91 incidents use deterministic inference based on attack vector patterns
- Pattern-level observations are robust; individual-row analytical fields are estimates

## Files

| File | Description |
|------|-------------|
| `software_supply_chain_attacks_expanded.csv` | Final dataset (116 rows × 25 columns) |
| `GRC_Analytical_Report.md` | Full analytical report with findings and recommendations |
| `build_dataset.py` | Consolidates data from Atlantic Council, CNCF, ENISA + additional sources |
| `expand_dataset.py` | Adds MITRE ATT&CK IDs and 13 analytical columns |
| `build_dashboard.py` | Generates the original 8-panel comparative analysis dashboard |
| `build_grc_dashboard.py` | Generates the GRC governance dashboards (3 figures) |
| `grc_governance_dashboard.png` | Dashboard: Governance-Exposure Inversion (4 panels) |
| `grc_trends_dashboard.png` | Dashboard: Trends & Shifts (4 panels) |
| `grc_failure_points.png` | Dashboard: Failure Points mapped to Governance Layers |
| `supply_chain_dashboard.png` | Dashboard: Original comparative analysis (8 panels) |
| `supply_chain_trends.png` | Dashboard: Original trend deep dive (4 panels) |

## Three-Layer Governance Model

The analysis proposes a governance framework organized around trust boundaries:

1. **Layer 1 — Producer Controls** (build integrity, code signing, SBOMs) — addresses ~35% of incidents
2. **Layer 2 — Consumer Controls** (dependency admission, lockfiles, package monitoring) — addresses ~55% of incidents — **the governance gap**
3. **Layer 3 — Operational Resilience** (nth-party mapping, offline backups, manual fallback) — addresses ~10% of incidents but highest impact

## How to Reproduce

```bash
# 1. Build the base dataset (requires internet for source CSV download)
python3 build_dataset.py

# 2. Expand with MITRE ATT&CK and analytical columns
python3 expand_dataset.py

# 3. Generate dashboards (requires matplotlib)
pip install matplotlib
python3 build_dashboard.py
python3 build_grc_dashboard.py
```

## Notable Incidents in the Dataset

- **SolarWinds Orion** (2020) — APT29, ~9 month dwell time, SUNBURST backdoor
- **Colonial Pipeline** (2021) — DarkSide ransomware, 5,500-mile pipeline shutdown
- **3CX DesktopApp** (2023) — Lazarus Group, double supply chain compromise
- **MOVEit Transfer** (2023) — Cl0p, ~$2.7B aggregate impact
- **xz Utils** (2024) — ~2 year social engineering campaign, backdoor in liblzma
- **Nichirei** (2026) — cold-chain logistics attack disrupting Japan's food supply

## Limitations

- Dataset is not exhaustive; 2024–2026 incidents are less completely represented
- 91 of 116 rows use inferred analytical fields (directional, not primary-sourced)
- Financial cost data available for only 9 of 116 incidents
- Over-represents English-language public reporting

## License

MIT License — see [LICENSE](LICENSE).

## Acknowledgments

Data sourced from:
- [Atlantic Council Breaking Trust](https://www.atlanticcouncil.org/commentary/trackers-and-data-visualizations/breaking-trust-the-dataset/)
- [ENISA Threat Landscape for Supply Chain Attacks](https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks)
- [CNCF TAG Security Supply Chain Compromises Catalog](https://github.com/cncf/tag-security/tree/main/community/catalog/compromises)

---

*Analysis date: July 2026. This project is for educational and analytical purposes.*
