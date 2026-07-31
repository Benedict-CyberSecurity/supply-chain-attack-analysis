#!/usr/bin/env python3
"""
Supply Chain Attack Analysis Dashboard
Generates a multi-panel visual dashboard for portfolio project analysis.
"""

import csv
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from collections import Counter, defaultdict
from datetime import datetime

# Load data
rows = []
with open('/home/user/workspace/software_supply_chain_attacks_expanded.csv', 'r') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

# Colors
DARK_BG = '#ffffff'
PANEL_BG = '#f8f9fa'
ACCENT_BLUE = '#1a73e8'
ACCENT_CYAN = '#0097a7'
ACCENT_RED = '#d32f2f'
ACCENT_GREEN = '#2e7d32'
ACCENT_ORANGE = '#ef6c00'
ACCENT_PURPLE = '#7b1fa2'
TEXT_COLOR = '#212121'
GRID_COLOR = '#e0e0e0'

plt.rcParams.update({
    'figure.facecolor': DARK_BG,
    'axes.facecolor': PANEL_BG,
    'axes.edgecolor': GRID_COLOR,
    'axes.labelcolor': TEXT_COLOR,
    'xtick.color': TEXT_COLOR,
    'ytick.color': TEXT_COLOR,
    'text.color': TEXT_COLOR,
    'font.size': 11,
    'font.family': 'sans-serif',
    'axes.grid': True,
    'grid.color': GRID_COLOR,
    'grid.alpha': 0.3,
})

# ============================================================
# FIGURE: 6-panel dashboard
# ============================================================
fig = plt.figure(figsize=(22, 28))
fig.suptitle('Software Supply Chain Attacks: Comparative Analysis (2017–2026)',
             fontsize=22, fontweight='bold', color='#1a237e', y=0.98)

# --- Panel 1: Incidents per year (bar chart) ---
ax1 = fig.add_subplot(4, 2, 1)
years_data = Counter(r['Incident Date'][:4] for r in rows)
years = sorted(years_data.keys())
counts = [years_data[y] for y in years]
colors = [ACCENT_RED if y == '2020' else ACCENT_ORANGE if y == '2021' else ACCENT_CYAN for y in years]
# Make all bars the same accent color for cleaner look
colors = [ACCENT_CYAN] * len(years)
bars = ax1.bar(years, counts, color=colors, edgecolor='white', linewidth=0.5)
ax1.set_title('Incidents per Year', fontsize=13, fontweight='bold', color='#333333', pad=10)
ax1.set_ylabel('Number of Incidents')
for bar, count in zip(bars, counts):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, str(count),
             ha='center', va='bottom', color=TEXT_COLOR, fontweight='bold')
ax1.tick_params(axis='x', rotation=45)

# --- Panel 2: APT vs Opportunistic vs Unknown ---
ax2 = fig.add_subplot(4, 2, 2)
flag_counts = Counter(r.get('APT vs Opportunistic', 'Other/Unknown') for r in rows)
labels = list(flag_counts.keys())
sizes = list(flag_counts.values())
colors_pie = [ACCENT_RED if 'APT' in l else ACCENT_GREEN if 'Opportunistic' in l else '#4a6fa5' for l in labels]
wedges, texts, autotexts = ax2.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors_pie,
                                    startangle=90, textprops={'fontsize': 9, 'color': TEXT_COLOR})
for autotext in autotexts:
    autotext.set_fontweight('bold')
    autotext.set_color('white')
ax2.set_title('Attribution: APT vs Opportunistic', fontsize=13, fontweight='bold', color='#333333', pad=10)

# --- Panel 3: Top MITRE ATT&CK Techniques ---
ax3 = fig.add_subplot(4, 2, 3)
# Extract primary MITRE ID (first one before +)
mitre_primary = []
for r in rows:
    mid = r.get('MITRE ATT&CK ID', '')
    primary = mid.split('+')[0].strip()
    mitre_primary.append(primary)
mitre_counts = Counter(mitre_primary)
top_mitre = mitre_counts.most_common(8)
mitre_labels = [m[0] for m in top_mitre]
mitre_values = [m[1] for m in top_mitre]
# Technique name mapping
tech_names = {
    'T1195.001': 'Compromise Software\nDependencies/Dev Tools',
    'T1195.002': 'Compromise Software\nSupply Chain',
    'T1195.003': 'Compromise Hardware\nSupply Chain',
    'T1190': 'Exploit Public-Facing\nApplication',
    'T1078': 'Valid Accounts',
    'T1486': 'Data Encrypted\nfor Impact (Ransomware)',
    'T1553.002': 'Subvert Trust:\nCode Signing',
    'T1566': 'Phishing',
    'T1059': 'Command & Scripting\nInterpreter',
    'T1552': 'Unsecured\nCredentials',
}
display_labels = [tech_names.get(l, l) for l in mitre_labels]
bars3 = ax3.barh(range(len(mitre_labels)), mitre_values, color=ACCENT_PURPLE, edgecolor='white')
ax3.set_yticks(range(len(mitre_labels)))
ax3.set_yticklabels(display_labels, fontsize=8)
ax3.set_xlabel('Number of Incidents')
ax3.set_title('Top MITRE ATT&CK Techniques', fontsize=13, fontweight='bold', color='#333333', pad=10)
ax3.invert_yaxis()
for i, (v) in enumerate(mitre_values):
    ax3.text(v + 0.3, i, str(v), va='center', color=TEXT_COLOR, fontweight='bold')

# --- Panel 4: Detection Coverage ---
ax4 = fig.add_subplot(4, 2, 4)
dc_counts = Counter(r.get('Detection Coverage', 'Unknown') for r in rows)
dc_labels = list(dc_counts.keys())
dc_values = list(dc_counts.values())
dc_colors = [ACCENT_GREEN if l == 'Yes' else ACCENT_ORANGE if l == 'Partial' else ACCENT_RED if l == 'No' else '#4a6fa5' for l in dc_labels]
bars4 = ax4.bar(dc_labels, dc_values, color=dc_colors, edgecolor='white')
ax4.set_title('Detection Coverage', fontsize=13, fontweight='bold', color='#333333', pad=10)
ax4.set_ylabel('Number of Incidents')
for bar, val in zip(bars4, dc_values):
    ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, str(val),
             ha='center', va='bottom', color=TEXT_COLOR, fontweight='bold')

# --- Panel 5: Category comparison ---
ax5 = fig.add_subplot(4, 2, 5)
cat_counts = Counter(r.get('Category', 'Software Supply Chain') for r in rows)
cat_labels = ['Software\nSupply Chain', 'Physical/Operational\nSupply Chain']
cat_values = [cat_counts.get('Software Supply Chain', 0), cat_counts.get('Physical/Operational Supply Chain', 0)]
cat_colors = [ACCENT_CYAN, ACCENT_ORANGE]
bars5 = ax5.bar(cat_labels, cat_values, color=cat_colors, edgecolor='white', width=0.5)
ax5.set_title('Attack Category Distribution', fontsize=13, fontweight='bold', color='#333333', pad=10)
ax5.set_ylabel('Number of Incidents')
for bar, val in zip(bars5, cat_values):
    ax5.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, str(val),
             ha='center', va='bottom', color=TEXT_COLOR, fontweight='bold')

# --- Panel 6: Top Target Industries ---
ax6 = fig.add_subplot(4, 2, 6)
ind_counts = Counter(r.get('Target Industry', 'Unknown') for r in rows)
# Simplify industry names
ind_simplified = Counter()
for ind, cnt in ind_counts.items():
    if 'Open Source' in ind or 'Package' in ind:
        ind_simplified['Open Source/Package Registry'] += cnt
    elif 'IT' in ind or 'DevOps' in ind or 'Developer' in ind:
        ind_simplified['IT/DevOps/Developer Tools'] += cnt
    elif 'Government' in ind:
        ind_simplified['Government/Public Sector'] += cnt
    elif 'Food' in ind or 'Meat' in ind:
        ind_simplified['Food/Logistics'] += cnt
    elif 'Crypto' in ind:
        ind_simplified['Cryptocurrency/Blockchain'] += cnt
    elif 'Automotive' in ind or 'Manufacturing' in ind:
        ind_simplified['Manufacturing/Automotive'] += cnt
    elif 'Identity' in ind:
        ind_simplified['Identity/Access Mgmt'] += cnt
    elif 'Certificate' in ind:
        ind_simplified['Certificate Authority'] += cnt
    elif 'Security' in ind:
        ind_simplified['Security Software'] += cnt
    else:
        ind_simplified['Other Technology'] += cnt

top_ind = ind_simplified.most_common(8)
ind_labels = [i[0] for i in top_ind]
ind_values = [i[1] for i in top_ind]
bars6 = ax6.barh(range(len(ind_labels)), ind_values, color=ACCENT_GREEN, edgecolor='white')
ax6.set_yticks(range(len(ind_labels)))
ax6.set_yticklabels(ind_labels, fontsize=8)
ax6.set_xlabel('Number of Incidents')
ax6.set_title('Top Target Industries', fontsize=13, fontweight='bold', color='#333333', pad=10)
ax6.invert_yaxis()
for i, v in enumerate(ind_values):
    ax6.text(v + 0.3, i, str(v), va='center', color=TEXT_COLOR, fontweight='bold')

# --- Panel 7: APT incidents timeline ---
ax7 = fig.add_subplot(4, 2, 7)
apt_rows = [r for r in rows if r.get('APT vs Opportunistic') == 'APT']
opp_rows = [r for r in rows if r.get('APT vs Opportunistic') == 'Opportunistic']
# Group by year
apt_by_year = Counter(r['Incident Date'][:4] for r in apt_rows)
opp_by_year = Counter(r['Incident Date'][:4] for r in opp_rows)
all_years = sorted(set(list(apt_by_year.keys()) + list(opp_by_year.keys())))
apt_vals = [apt_by_year.get(y, 0) for y in all_years]
opp_vals = [opp_by_year.get(y, 0) for y in all_years]
x = np.arange(len(all_years))
w = 0.35
ax7.bar(x - w/2, apt_vals, w, label='APT / State-linked', color=ACCENT_RED, edgecolor='white')
ax7.bar(x + w/2, opp_vals, w, label='Opportunistic', color=ACCENT_GREEN, edgecolor='white')
ax7.set_xticks(x)
ax7.set_xticklabels(all_years, rotation=45)
ax7.set_ylabel('Number of Incidents')
ax7.set_title('APT vs Opportunistic Attacks Over Time', fontsize=13, fontweight='bold', color='#333333', pad=10)
ax7.legend(loc='upper right', fontsize=8, facecolor=PANEL_BG, edgecolor=GRID_COLOR)

# --- Panel 8: Incident Failure Points ---
ax8 = fig.add_subplot(4, 2, 8)
fp_counts = Counter()
for r in rows:
    fp = r.get('Incident Failure Point', 'Unknown')
    # Simplify
    if 'Package' in fp or 'registry' in fp.lower():
        fp_counts['Package registry verification'] += 1
    elif 'Build' in fp or 'build' in fp:
        fp_counts['Build system integrity'] += 1
    elif 'Credential' in fp or 'credential' in fp or 'VPN' in fp:
        fp_counts['Credential management'] += 1
    elif 'Code signing' in fp or 'Trust' in fp:
        fp_counts['Trust/signing controls'] += 1
    elif 'Source code' in fp:
        fp_counts['Source code integrity'] += 1
    elif 'Update' in fp or 'Delivery' in fp or 'Publishing' in fp:
        fp_counts['Update/delivery mechanism'] += 1
    elif 'Vulnerability' in fp or 'zero-day' in fp.lower() or 'unpatched' in fp.lower():
        fp_counts['Vulnerability management'] += 1
    elif 'Firmware' in fp or 'Hardware' in fp:
        fp_counts['Hardware/firmware provenance'] += 1
    else:
        fp_counts['Other/Unknown'] += 1

top_fp = fp_counts.most_common(8)
fp_labels = [f[0] for f in top_fp]
fp_values = [f[1] for f in top_fp]
bars8 = ax8.barh(range(len(fp_labels)), fp_values, color=ACCENT_ORANGE, edgecolor='white')
ax8.set_yticks(range(len(fp_labels)))
ax8.set_yticklabels(fp_labels, fontsize=8)
ax8.set_xlabel('Number of Incidents')
ax8.set_title('Where Defenses Failed (Incident Failure Points)', fontsize=13, fontweight='bold', color='#333333', pad=10)
ax8.invert_yaxis()
for i, v in enumerate(fp_values):
    ax8.text(v + 0.3, i, str(v), va='center', color=TEXT_COLOR, fontweight='bold')

plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.savefig('/home/user/workspace/supply_chain_dashboard.png', dpi=150, bbox_inches='tight',
            facecolor=DARK_BG, edgecolor='none')
print("Dashboard saved to supply_chain_dashboard.png")

# ============================================================
# FIGURE 2: Trend Analysis Deep Dive
# ============================================================
fig2 = plt.figure(figsize=(18, 16))
fig2.suptitle('Supply Chain Attack Trends & Shifts: Deep Dive Analysis',
              fontsize=18, fontweight='bold', color='#1a237e', y=0.98)

# --- Panel 1: Attack vector evolution over time ---
ax1 = fig2.add_subplot(2, 2, 1)
# Categorize attack vectors
vector_by_year = defaultdict(lambda: Counter())
for r in rows:
    year = r['Incident Date'][:4]
    vec = r.get('Attack Vector', '').lower()
    if 'malicious package' in vec or 'typosquat' in vec:
        vtype = 'Malicious Package'
    elif 'build' in vec or 'ci/cd' in vec or 'dev tool' in vec:
        vtype = 'Build/CI-CD'
    elif 'ransomware' in vec:
        vtype = 'Ransomware'
    elif 'credential' in vec or 'account' in vec or 'phishing' in vec:
        vtype = 'Credential/Account'
    elif 'code injection' in vec or 'code compromise' in vec:
        vtype = 'Code Injection'
    elif 'vulnerability' in vec:
        vtype = 'Vulnerability Exploit'
    elif 'dependency' in vec:
        vtype = 'Dependency Confusion'
    else:
        vtype = 'Other'
    vector_by_year[vtype][year] += 1

# Plot stacked area for top vectors
top_vectors = ['Malicious Package', 'Build/CI-CD', 'Credential/Account', 'Ransomware', 'Code Injection', 'Other']
years_sorted = sorted(vector_by_year['Malicious Package'].keys())
bottom = np.zeros(len(years_sorted))
vec_colors = [ACCENT_CYAN, ACCENT_PURPLE, ACCENT_ORANGE, ACCENT_RED, ACCENT_GREEN, '#4a6fa5']
for i, vtype in enumerate(top_vectors):
    vals = [vector_by_year[vtype].get(y, 0) for y in years_sorted]
    ax1.bar(years_sorted, vals, bottom=bottom, label=vtype, color=vec_colors[i], edgecolor='white', linewidth=0.3)
    bottom += np.array(vals)
ax1.set_title('Attack Vector Evolution Over Time', fontsize=12, fontweight='bold', color='#333333', pad=10)
ax1.set_ylabel('Number of Incidents')
ax1.legend(loc='upper right', fontsize=9, facecolor=PANEL_BG, edgecolor=GRID_COLOR)
ax1.tick_params(axis='x', rotation=45)

# --- Panel 2: Disruption type analysis ---
ax2 = fig2.add_subplot(2, 2, 2)
dis_types = Counter()
for r in rows:
    dt = r.get('Disruption Type', '')
    if 'Operational' in dt and 'Data' in dt:
        dis_types['Operational + Data'] += 1
    elif 'Operational' in dt or 'Service' in dt:
        dis_types['Operational/Service'] += 1
    elif 'Data' in dt or 'breach' in dt.lower() or 'exfil' in dt.lower():
        dis_types['Data Breach/Theft'] += 1
    elif 'Credential' in dt or 'token' in dt.lower():
        dis_types['Credential/Token Theft'] += 1
    elif 'Financial' in dt or 'crypto' in dt.lower():
        dis_types['Financial Fraud/Theft'] += 1
    else:
        dis_types['Other'] += 1
top_dis = dis_types.most_common(7)
dis_labels = [d[0] for d in top_dis]
dis_values = [d[1] for d in top_dis]
bars = ax2.barh(range(len(dis_labels)), dis_values, color=ACCENT_RED, edgecolor='white')
ax2.set_yticks(range(len(dis_labels)))
ax2.set_yticklabels(dis_labels, fontsize=9)
ax2.set_xlabel('Number of Incidents')
ax2.set_title('Disruption Type Breakdown', fontsize=12, fontweight='bold', color='#333333', pad=10)
ax2.invert_yaxis()
for i, v in enumerate(dis_values):
    ax2.text(v + 0.3, i, str(v), va='center', color=TEXT_COLOR, fontweight='bold')

# --- Panel 3: Compliance status ---
ax3 = fig2.add_subplot(2, 2, 3)
comp_counts = Counter()
for r in rows:
    cs = r.get('Compliance Status', '')
    if 'SEC' in cs or 'TSA' in cs or 'Executive Order' in cs or 'directive' in cs.lower():
        comp_counts['Regulatory action triggered'] += 1
    elif 'GDPR' in cs or 'notification' in cs.lower() or 'report' in cs.lower():
        comp_counts['Notification/breach report'] += 1
    elif 'OFAC' in cs or 'sanctions' in cs.lower():
        comp_counts['Sanctions exposure'] += 1
    elif 'Not reported' in cs or 'Unknown' in cs or 'No specific' in cs:
        comp_counts['No regulatory action'] += 1
    else:
        comp_counts['Other'] += 1
comp_labels = list(comp_counts.keys())
comp_values = list(comp_counts.values())
comp_colors = [ACCENT_RED, ACCENT_ORANGE, ACCENT_PURPLE, ACCENT_BLUE, ACCENT_GREEN][:len(comp_labels)]
bars3 = ax3.bar(comp_labels, comp_values, color=comp_colors, edgecolor='white')
ax3.set_title('Compliance & Regulatory Impact', fontsize=12, fontweight='bold', color='#333333', pad=10)
ax3.set_ylabel('Number of Incidents')
ax3.tick_params(axis='x', rotation=30)
for bar, val in zip(bars3, comp_values):
    ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3, str(val),
             ha='center', va='bottom', color=TEXT_COLOR, fontweight='bold')

# --- Panel 4: Time to Detect distribution ---
ax4 = fig2.add_subplot(2, 2, 4)
# Categorize time to detect
ttd_cats = Counter()
for r in rows:
    ttd = r.get('Time to Detect', '').lower()
    if 'minute' in ttd or 'hour' in ttd:
        ttd_cats['< 1 day'] += 1
    elif 'day' in ttd and ('1' in ttd or '2' in ttd or '3' in ttd or '4' in ttd or '5' in ttd or '6' in ttd or '7' in ttd or '8' in ttd or '9' in ttd):
        ttd_cats['1-9 days'] += 1
    elif 'week' in ttd or '10 day' in ttd or '14 day' in ttd or '2 week' in ttd:
        ttd_cats['1-2 weeks'] += 1
    elif 'month' in ttd:
        ttd_cats['1+ months'] += 1
    elif 'year' in ttd or '9 month' in ttd or '2 year' in ttd:
        ttd_cats['9+ months (long dwell)'] += 1
    elif 'unknown' in ttd or 'not' in ttd:
        ttd_cats['Unknown'] += 1
    else:
        ttd_cats['Unknown'] += 1

ttd_order = ['< 1 day', '1-9 days', '1-2 weeks', '1+ months', '9+ months (long dwell)', 'Unknown']
ttd_values = [ttd_cats.get(k, 0) for k in ttd_order]
ttd_colors = [ACCENT_GREEN, ACCENT_CYAN, ACCENT_ORANGE, ACCENT_RED, '#8B0000', '#4a6fa5']
bars4 = ax4.bar(ttd_order, ttd_values, color=ttd_colors, edgecolor='white')
ax4.set_title('Time to Detect Distribution', fontsize=12, fontweight='bold', color='#333333', pad=10)
ax4.set_ylabel('Number of Incidents')
ax4.tick_params(axis='x', rotation=30)
for bar, val in zip(bars4, ttd_values):
    if val > 0:
        ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3, str(val),
                 ha='center', va='bottom', color=TEXT_COLOR, fontweight='bold')

plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.savefig('/home/user/workspace/supply_chain_trends.png', dpi=150, bbox_inches='tight',
            facecolor=DARK_BG, edgecolor='none')
print("Trends chart saved to supply_chain_trends.png")

# Print summary stats
print("\n=== DASHBOARD SUMMARY ===")
print(f"Total incidents: {len(rows)}")
print(f"Date range: {min(r['Incident Date'] for r in rows)} to {max(r['Incident Date'] for r in rows)}")
print(f"Columns: {len(rows[0].keys())}")
print(f"\nYear distribution:")
for y in sorted(years_data.keys()):
    bar = '#' * years_data[y]
    print(f"  {y}: {years_data[y]:3d} {bar}")
print(f"\nAPT incidents: {sum(1 for r in rows if r.get('APT vs Opportunistic') == 'APT')}")
print(f"Opportunistic: {sum(1 for r in rows if r.get('APT vs Opportunistic') == 'Opportunistic')}")
print(f"Other/Unknown: {sum(1 for r in rows if r.get('APT vs Opportunistic') == 'Other/Unknown')}")
print(f"\nPhysical/Operational: {sum(1 for r in rows if r.get('Category') == 'Physical/Operational Supply Chain')}")
print(f"Software Supply Chain: {sum(1 for r in rows if r.get('Category') == 'Software Supply Chain')}")
