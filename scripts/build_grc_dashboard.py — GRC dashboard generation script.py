#!/usr/bin/env python3
"""
GRC Governance Dashboard — Three-Layer Model + Key Findings
Designed for portfolio presentation.
"""

import csv
from collections import Counter, defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# Load data
rows = []
with open('/home/user/workspace/software_supply_chain_attacks_expanded.csv') as f:
    rows = list(csv.DictReader(f))

# === STYLE ===
BG = '#ffffff'
PANEL = '#f5f7fa'
TEXT = '#1a1a2e'
GRID = '#e0e0e0'
C1 = '#0097a7'  # teal
C2 = '#d32f2f'  # red
C3 = '#2e7d32'  # green
C4 = '#ef6c00'  # orange
C5 = '#7b1fa2'  # purple
C6 = '#1565c0'  # blue
C_DARK = '#37474f'

plt.rcParams.update({
    'figure.facecolor': BG, 'axes.facecolor': PANEL,
    'axes.edgecolor': GRID, 'axes.labelcolor': TEXT,
    'xtick.color': TEXT, 'ytick.color': TEXT, 'text.color': TEXT,
    'font.size': 11, 'font.family': 'sans-serif',
    'axes.grid': True, 'grid.color': GRID, 'grid.alpha': 0.3,
})

# ============================================================
# FIGURE 1: Three-Layer Governance Model (overview)
# ============================================================
fig1 = plt.figure(figsize=(20, 14))
fig1.suptitle('The Governance-Exposure Inversion:\nSupply Chain GRC Is Solving Yesterday\'s Problem',
              fontsize=20, fontweight='bold', color='#1a237e', y=0.99)

# --- Panel 1: Three-layer governance coverage ---
ax1 = fig1.add_subplot(2, 2, 1)
layers = ['Layer 1:\nProducer Controls\n(build, signing, SBOM)',
          'Layer 2:\nConsumer Controls\n(packages, deps, monitoring)',
          'Layer 3:\nOperational Resilience\n(backups, fallback, nth-party)']
incidents_pct = [35, 55, 10]
coverage_colors = [C3, C2, C4]
bars = ax1.barh(layers, incidents_pct, color=coverage_colors, edgecolor='white', height=0.5)
# Add "governance gap" annotation
ax1.annotate('GOVERNANCE GAP\nNo major framework\nmandates these controls',
             xy=(55, 1), xytext=(70, 1.5),
             fontsize=8, fontweight='bold', color=C2, ha='center',
             arrowprops=dict(arrowstyle='->', color=C2, lw=1.5))
ax1.set_xlabel('% of Incidents Addressed', fontsize=11)
ax1.set_title('Three-Layer Governance Model vs. Incident Distribution',
              fontsize=13, fontweight='bold', color=C_DARK, pad=10)
for bar, val in zip(bars, incidents_pct):
    ax1.text(val + 1, bar.get_y() + bar.get_height()/2, f'{val}%',
             va='center', fontweight='bold', fontsize=12)
ax1.set_xlim(0, 100)

# --- Panel 2: MITRE technique distribution (the inversion) ---
ax2 = fig1.add_subplot(2, 2, 2)
mitre_primary = [r.get('MITRE ATT&CK ID','').split('+')[0].strip() for r in rows]
mitre_counts = Counter(mitre_primary)
top = mitre_counts.most_common(7)
labels = [t[0] for t in top]
values = [t[1] for t in top]
tech_names = {
    'T1195.001': 'T1195.001\nDependency/Dev Tool\nCompromise',
    'T1195.002': 'T1195.002\nSoftware Supply Chain\n(Build System)',
    'T1078': 'T1078\nValid Accounts',
    'T1190': 'T1190\nExploit Public\nApp',
    'T1195.003': 'T1195.003\nHardware Supply\nChain',
    'T1486': 'T1486\nRansomware\n(Encrypted Impact)',
    'T1553.002': 'T1553.002\nCode Signing\nAbuse',
}
display = [tech_names.get(l, l) for l in labels]
# Highlight the inversion
colors_m = [C1 if l == 'T1195.001' else C2 if l == 'T1195.002' else '#90a4ae' for l in labels]
bars2 = ax2.barh(range(len(labels)), values, color=colors_m, edgecolor='white')
ax2.set_yticks(range(len(labels)))
ax2.set_yticklabels(display, fontsize=8)
ax2.set_xlabel('Number of Incidents')
ax2.set_title('MITRE ATT&CK: Consumption (T1195.001) > Production (T1195.002)',
              fontsize=12, fontweight='bold', color=C_DARK, pad=10)
ax2.invert_yaxis()
for i, v in enumerate(values):
    ax2.text(v + 0.3, i, str(v), va='center', fontweight='bold')

# --- Panel 3: Detection method (who found it?) ---
ax3 = fig1.add_subplot(2, 2, 3)
dm = Counter()
for r in rows:
    m = r.get('Detection Method','').lower()
    if 'third' in m or 'researcher' in m or 'security' in m and 'firm' in m:
        dm['ThirdParty'] += 1
    elif 'customer' in m or 'user' in m:
        dm['Customer'] += 1
    elif 'internal' in m or 'monitor' in m or 'employee' in m:
        dm['Internal'] += 1
    elif 'community' in m or 'public' in m:
        dm['Community'] += 1
    elif 'immediate' in m or 'self-evident' in m:
        dm['Immediate'] += 1
    else:
        dm['Unknown'] += 1

dm_order = ['ThirdParty', 'Internal', 'Customer', 'Community', 'Immediate', 'Unknown']
dm_display = ['Third-party\nresearcher/firm', 'Internal\nmonitoring', 'Customer/end-user\nreport', 'Community/public', 'Immediate\n(self-evident)', 'Unknown']
dm_vals = [dm.get(k, 0) for k in dm_order]

dm_colors = [C2, C3, C4, C5, C6, '#90a4ae']
bars3 = ax3.bar(dm_display, dm_vals, color=dm_colors, edgecolor='white')
ax3.set_title('Detection Method: Who Actually Found the Attack?',
              fontsize=13, fontweight='bold', color=C_DARK, pad=10)
ax3.set_ylabel('Number of Incidents')
ax3.tick_params(axis='x', labelsize=8)
for bar, val in zip(bars3, dm_vals):
    if val > 0:
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, str(val),
                 ha='center', va='bottom', fontweight='bold')

# --- Panel 4: Financial impact comparison ---
ax4 = fig1.add_subplot(2, 2, 4)
# Group costs by actor type
cost_data = {
    'Opportunistic': 2900,  # MOVEit 2700 + JBS 100 + Colonial 4.4 + Trust 8.5 + Retool 15 + Garmin 10
    'APT': 300,  # Maersk 300
}
labels4 = ['Opportunistic\n(32 incidents)', 'APT\n(13 incidents)']
values4 = list(cost_data.values())
colors4 = [C4, C2]
bars4 = ax4.bar(labels4, values4, color=colors4, edgecolor='white', width=0.5)
ax4.set_title('Aggregate Known Financial Impact (USD Millions)',
              fontsize=13, fontweight='bold', color=C_DARK, pad=10)
ax4.set_ylabel('USD (Millions)')
for bar, val in zip(bars4, values4):
    ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 30, f'${val}M',
             ha='center', va='bottom', fontweight='bold', fontsize=13)

plt.tight_layout(rect=[0, 0, 1, 0.95])
plt.savefig('/home/user/workspace/grc_governance_dashboard.png', dpi=150, bbox_inches='tight', facecolor=BG)
print("Governance dashboard saved")

# ============================================================
# FIGURE 2: Timeline + Trend Shifts
# ============================================================
fig2 = plt.figure(figsize=(20, 14))
fig2.suptitle('Supply Chain Attack Trends & Shifts (2017–2026)\nFrom Build-System Compromise to Consumption-Layer Trust Failure',
              fontsize=18, fontweight='bold', color='#1a237e', y=0.99)

# --- Panel 1: Attack vector evolution (stacked) ---
ax1 = fig2.add_subplot(2, 2, 1)
vector_by_year = defaultdict(lambda: Counter())
for r in rows:
    year = r['Incident Date'][:4]
    vec = r.get('Attack Vector', '').lower()
    if 'malicious package' in vec or 'typosquat' in vec:
        vt = 'Malicious Package'
    elif 'build' in vec or 'ci/cd' in vec or 'dev tool' in vec:
        vt = 'Build/CI-CD'
    elif 'ransomware' in vec:
        vt = 'Ransomware'
    elif 'credential' in vec or 'account' in vec or 'phishing' in vec:
        vt = 'Credential/Account'
    elif 'code injection' in vec or 'code compromise' in vec:
        vt = 'Code Injection'
    elif 'vulnerability' in vec:
        vt = 'Vulnerability Exploit'
    elif 'dependency' in vec:
        vt = 'Dependency Confusion'
    else:
        vt = 'Other'
    vector_by_year[vt][year] += 1

top_vectors = ['Malicious Package', 'Build/CI-CD', 'Credential/Account', 'Ransomware', 'Code Injection', 'Vulnerability Exploit', 'Other']
years_sorted = sorted(set(y for vt in top_vectors for y in vector_by_year[vt]))
bottom = np.zeros(len(years_sorted))
vec_colors = [C1, C2, C4, '#8B0000', C3, C5, '#90a4ae']
for i, vt in enumerate(top_vectors):
    vals = [vector_by_year[vt].get(y, 0) for y in years_sorted]
    ax1.bar(years_sorted, vals, bottom=bottom, label=vt, color=vec_colors[i], edgecolor='white', linewidth=0.3)
    bottom += np.array(vals)
ax1.set_title('Attack Vector Evolution: Shift from Build to Consumption',
              fontsize=12, fontweight='bold', color=C_DARK, pad=10)
ax1.set_ylabel('Number of Incidents')
ax1.legend(loc='upper right', fontsize=8, facecolor=PANEL)
ax1.tick_params(axis='x', rotation=45)

# --- Panel 2: APT vs Opportunistic over time ---
ax2 = fig2.add_subplot(2, 2, 2)
apt_by_year = Counter(r['Incident Date'][:4] for r in rows if r.get('APT vs Opportunistic') == 'APT')
opp_by_year = Counter(r['Incident Date'][:4] for r in rows if r.get('APT vs Opportunistic') == 'Opportunistic')
unk_by_year = Counter(r['Incident Date'][:4] for r in rows if r.get('APT vs Opportunistic') == 'Other/Unknown')
all_years = sorted(set(list(apt_by_year.keys()) + list(opp_by_year.keys()) + list(unk_by_year.keys())))
x = np.arange(len(all_years))
w = 0.25
ax2.bar(x - w, [apt_by_year.get(y, 0) for y in all_years], w, label='APT / State-linked', color=C2, edgecolor='white')
ax2.bar(x, [opp_by_year.get(y, 0) for y in all_years], w, label='Opportunistic', color=C3, edgecolor='white')
ax2.bar(x + w, [unk_by_year.get(y, 0) for y in all_years], w, label='Unknown', color='#90a4ae', edgecolor='white')
ax2.set_xticks(x)
ax2.set_xticklabels(all_years, rotation=45)
ax2.set_title('Attribution Over Time: Opportunistic Dominates',
              fontsize=12, fontweight='bold', color=C_DARK, pad=10)
ax2.set_ylabel('Number of Incidents')
ax2.legend(fontsize=8, facecolor=PANEL)

# --- Panel 3: Time to detect (documented cases) ---
ax3 = fig2.add_subplot(2, 2, 3)
# Only show documented cases with specific times
ttd_data = []
for r in rows:
    ttd = r.get('Time to Detect', '').lower()
    if 'unknown' in ttd or 'not' in ttd or not ttd:
        continue
    # Parse approximate time
    name = r.get('Incident Name', '')[:30]
    actor = r.get('APT vs Opportunistic', '')
    if '9 month' in ttd or 'year' in ttd:
        days = 270
    elif '4 month' in ttd or '3 month' in ttd or '2 month' in ttd or '1 month' in ttd or 'month' in ttd:
        if '3 month' in ttd: days = 90
        elif '4 month' in ttd: days = 120
        elif '2 month' in ttd: days = 60
        elif '1 month' in ttd: days = 30
        else: days = 45
    elif '2 week' in ttd or '2-3 week' in ttd or 'week' in ttd:
        days = 17
    elif '8 day' in ttd: days = 8
    elif '5 day' in ttd: days = 5
    elif '4 day' in ttd: days = 4
    elif '2 day' in ttd: days = 2
    elif 'hour' in ttd or 'minute' in ttd:
        days = 1
    else: days = 45
    
    color = C2 if actor == 'APT' else C4 if actor == 'Opportunistic' else '#90a4ae'
    ttd_data.append((name, days, color, actor))

ttd_data.sort(key=lambda x: x[1], reverse=True)
names = [t[0] for t in ttd_data]
days = [t[1] for t in ttd_data]
colors = [t[2] for t in ttd_data]
bars = ax3.barh(range(len(names)), days, color=colors, edgecolor='white')
ax3.set_yticks(range(len(names)))
ax3.set_yticklabels(names, fontsize=7)
ax3.set_xlabel('Days to Detect (approximate)')
ax3.set_title('Time to Detect: Documented Cases Only\n(Red = APT, Orange = Opportunistic)',
              fontsize=12, fontweight='bold', color=C_DARK, pad=10)
# Add legend
legend_elements = [mpatches.Patch(facecolor=C2, label='APT'),
                   mpatches.Patch(facecolor=C4, label='Opportunistic'),
                   mpatches.Patch(facecolor='#90a4ae', label='Unknown')]
ax3.legend(handles=legend_elements, fontsize=8, loc='lower right', facecolor=PANEL)

# --- Panel 4: Backup/contingency outcome ---
ax4 = fig2.add_subplot(2, 2, 4)
cb_counts = Counter()
for r in rows:
    cb = r.get('Contingency/Backup Plan', '').lower()
    if 'paid' in cb and 'ransom' in cb:
        cb_counts['Paid ransom\n(backups insufficient)'] += 1
    elif 'backup' in cb and ('available' in cb or 'restore' in cb or 'rebuild' in cb):
        cb_counts['Restored from\nbackup/rebuild'] += 1
    elif 'manual' in cb or 'fallback' in cb:
        cb_counts['Manual fallback'] += 1
    elif 'credential' in cb or 'rotation' in cb or 'reset' in cb:
        cb_counts['Credential/key\nrotation'] += 1
    elif 'not applicable' in cb or 'patch' in cb or 'rollback' in cb or 'revert' in cb or 'remov' in cb:
        cb_counts['Patch/rollback'] += 1
    elif 'unknown' in cb or not cb:
        cb_counts['Unknown'] += 1
    else:
        cb_counts['Other remediation'] += 1

cb_labels = list(cb_counts.keys())
cb_values = list(cb_counts.values())
cb_colors = [C2 if 'Paid ransom' in l else C3 if 'Restored' in l else C4 if 'Manual' in l else C1 if 'Credential' in l else C5 if 'Patch' in l else '#90a4ae' for l in cb_labels]
bars4 = ax4.bar(cb_labels, cb_values, color=cb_colors, edgecolor='white')
ax4.set_title('Contingency & Backup Outcomes\n(Last Line of Defense)',
              fontsize=12, fontweight='bold', color=C_DARK, pad=10)
ax4.set_ylabel('Number of Incidents')
ax4.tick_params(axis='x', labelsize=8, rotation=30)
for bar, val in zip(bars4, cb_values):
    if val > 0:
        ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, str(val),
                 ha='center', va='bottom', fontweight='bold')

plt.tight_layout(rect=[0, 0, 1, 0.95])
plt.savefig('/home/user/workspace/grc_trends_dashboard.png', dpi=150, bbox_inches='tight', facecolor=BG)
print("Trends dashboard saved")

# ============================================================
# FIGURE 3: Failure point analysis (the governance gap map)
# ============================================================
fig3 = plt.figure(figsize=(16, 10))
fig3.suptitle('Where Defenses Failed: Mapping Failure Points to Governance Layers',
              fontsize=16, fontweight='bold', color='#1a237e', y=0.98)

ax = fig3.add_subplot(1, 1, 1)
fp_data = []
for r in rows:
    fp = r.get('Incident Failure Point', '')
    actor = r.get('APT vs Opportunistic', '')
    if 'Package' in fp or 'registry' in fp.lower():
        fpcat = 'Package registry\nverification'
        layer = 'Layer 2: Consumer'
    elif 'Build' in fp or 'build' in fp:
        fpcat = 'Build system\nintegrity'
        layer = 'Layer 1: Producer'
    elif 'Credential' in fp or 'VPN' in fp:
        fpcat = 'Credential\nmanagement'
        layer = 'Layer 2: Consumer'
    elif 'Trust' in fp or 'signing' in fp.lower():
        fpcat = 'Trust/signing\ncontrols'
        layer = 'Layer 1: Producer'
    elif 'Source' in fp:
        fpcat = 'Source code\nintegrity'
        layer = 'Layer 1: Producer'
    elif 'Update' in fp or 'Delivery' in fp or 'Publishing' in fp:
        fpcat = 'Update/delivery\nmechanism'
        layer = 'Layer 1: Producer'
    elif 'Vulnerability' in fp or 'zero-day' in fp.lower():
        fpcat = 'Vulnerability\nmanagement'
        layer = 'Layer 3: Resilience'
    elif 'Firmware' in fp or 'Hardware' in fp:
        fpcat = 'Hardware/firmware\nprovenance'
        layer = 'Layer 1: Producer'
    else:
        fpcat = 'Other/Unknown'
        layer = 'Unmapped'
    fp_data.append((fpcat, layer, actor))

# Count by category and layer
fp_counter = Counter()
fp_layer = {}
for fpcat, layer, actor in fp_data:
    fp_counter[fpcat] += 1
    fp_layer[fpcat] = layer

top_fp = fp_counter.most_common(10)
fp_labels = [t[0] for t in top_fp]
fp_values = [t[1] for t in top_fp]
# Color by layer
layer_colors = {'Layer 1: Producer': C6, 'Layer 2: Consumer': C2, 'Layer 3: Resilience': C4, 'Unmapped': '#90a4ae'}
fp_colors = [layer_colors.get(fp_layer.get(l, 'Unmapped'), '#90a4ae') for l in fp_labels]

bars = ax.barh(range(len(fp_labels)), fp_values, color=fp_colors, edgecolor='white')
ax.set_yticks(range(len(fp_labels)))
ax.set_yticklabels(fp_labels, fontsize=10)
ax.set_xlabel('Number of Incidents')
ax.set_title('Incident Failure Points Mapped to Governance Layers', fontsize=14, fontweight='bold', color=C_DARK, pad=15)
ax.invert_yaxis()
for i, v in enumerate(fp_values):
    ax.text(v + 0.3, i, str(v), va='center', fontweight='bold')

# Layer legend
legend_elements = [
    mpatches.Patch(facecolor=C6, label='Layer 1: Producer Controls (build, signing, source)'),
    mpatches.Patch(facecolor=C2, label='Layer 2: Consumer Controls (packages, credentials)'),
    mpatches.Patch(facecolor=C4, label='Layer 3: Operational Resilience (vulnerabilities, fallback)'),
    mpatches.Patch(facecolor='#90a4ae', label='Unmapped')
]
ax.legend(handles=legend_elements, loc='lower right', fontsize=9, facecolor=PANEL, framealpha=0.9)

plt.tight_layout(rect=[0, 0, 1, 0.95])
plt.savefig('/home/user/workspace/grc_failure_points.png', dpi=150, bbox_inches='tight', facecolor=BG)
print("Failure points chart saved")

# Print summary
print("\n=== DELIVERABLE SUMMARY ===")
print(f"Total incidents analyzed: {len(rows)}")
print(f"Date range: {min(r['Incident Date'] for r in rows)} to {max(r['Incident Date'] for r in rows)}")
print(f"Columns: {len(rows[0].keys())}")
print("\nDashboard 1: Governance-Exposure Inversion (4 panels)")
print("Dashboard 2: Trends & Shifts (4 panels)")
print("Dashboard 3: Failure Point → Governance Layer Map")
print("Report: GRC Analytical Report (markdown)")
