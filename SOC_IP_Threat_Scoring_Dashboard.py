# =============================================================================
# SOC IP Threat Scoring Dashboard
# Author: Reshma Keshireddy
# Description: Simulates a real-world SOC workflow by analyzing log data,
#              enriching IP addresses with threat intelligence feeds, and
#              calculating risk scores for threat prioritization.
# =============================================================================

# =============================================================================
# CELL 1 — Import Libraries
# =============================================================================
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os
from datetime import datetime

# Create output directories if they don't exist
os.makedirs('screenshots', exist_ok=True)
os.makedirs('dashboards', exist_ok=True)

print("=" * 60)
print("SOC IP Threat Scoring Dashboard")
print("=" * 60)
print("Libraries loaded successfully")
print(f"Run timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


# =============================================================================
# CELL 2 — Create Simulated Log Data
# =============================================================================
np.random.seed(42)

log_data = {
    'timestamp': pd.date_range(start='2024-01-01', periods=200, freq='H'),
    'ip_address': [
        f"{np.random.randint(1,255)}.{np.random.randint(0,255)}."
        f"{np.random.randint(0,255)}.{np.random.randint(1,255)}"
        for _ in range(200)
    ],
    'request_method': np.random.choice(
        ['GET', 'POST', 'PUT', 'DELETE'], 200, p=[0.6, 0.25, 0.1, 0.05]
    ),
    'status_code': np.random.choice(
        [200, 301, 404, 403, 500], 200, p=[0.6, 0.1, 0.15, 0.1, 0.05]
    ),
    'bytes_sent': np.random.randint(100, 50000, 200),
    'request_count': np.random.randint(1, 500, 200)
}

df_logs = pd.DataFrame(log_data)

# Inject known malicious IPs into the dataset for realistic simulation
malicious_ips = [
    '192.168.1.100', '10.0.0.55', '172.16.0.23',
    '45.33.32.156', '198.51.100.77'
]
for i, ip in enumerate(malicious_ips):
    df_logs.loc[i, 'ip_address'] = ip
    df_logs.loc[i, 'request_count'] = np.random.randint(300, 500)
    df_logs.loc[i, 'status_code'] = 403

print(f"\nLog data created: {df_logs.shape[0]} records")
print(f"Columns: {list(df_logs.columns)}")
print("\nSample log data (first 10 rows):")
print(df_logs.head(10).to_string(index=False))


# =============================================================================
# CELL 3 — Threat Intelligence Feed
# =============================================================================
threat_feed = {
    '192.168.1.100': {
        'threat_type': 'Brute Force',
        'severity': 'High',
        'reports': 145,
        'first_seen': '2023-11-01',
        'country': 'RU'
    },
    '10.0.0.55': {
        'threat_type': 'Port Scanner',
        'severity': 'High',
        'reports': 89,
        'first_seen': '2023-10-15',
        'country': 'CN'
    },
    '172.16.0.23': {
        'threat_type': 'Malware C2',
        'severity': 'Critical',
        'reports': 231,
        'first_seen': '2023-09-20',
        'country': 'KP'
    },
    '45.33.32.156': {
        'threat_type': 'SQL Injection',
        'severity': 'High',
        'reports': 67,
        'first_seen': '2023-12-01',
        'country': 'BR'
    },
    '198.51.100.77': {
        'threat_type': 'DDoS Source',
        'severity': 'Critical',
        'reports': 312,
        'first_seen': '2023-08-10',
        'country': 'IR'
    },
}

print(f"\nThreat Intelligence Feed loaded: {len(threat_feed)} known malicious IPs")
print(json.dumps(threat_feed, indent=2))


# =============================================================================
# CELL 4 — Risk Scoring Algorithm
# =============================================================================
def calculate_risk_score(row, threat_feed):
    """
    Calculates a risk score (0-100) for each IP address based on:
    - Factor 1: Threat intelligence match (0-50 points)
    - Factor 2: High request volume (0-20 points)
    - Factor 3: Suspicious HTTP status codes (0-20 points)
    - Factor 4: Suspicious request methods (0-10 points)

    Returns:
        int: Risk score between 0 and 100
    """
    score = 0
    ip = row['ip_address']

    # Factor 1: Threat intelligence match (0-50 points)
    if ip in threat_feed:
        severity = threat_feed[ip]['severity']
        if severity == 'Critical':
            score += 50
        elif severity == 'High':
            score += 35
        elif severity == 'Medium':
            score += 20
        else:
            score += 10

    # Factor 2: High request volume (0-20 points)
    if row['request_count'] > 400:
        score += 20
    elif row['request_count'] > 200:
        score += 10
    elif row['request_count'] > 100:
        score += 5

    # Factor 3: Suspicious HTTP status codes (0-20 points)
    if row['status_code'] == 403:
        score += 15
    elif row['status_code'] == 500:
        score += 10
    elif row['status_code'] == 404:
        score += 5

    # Factor 4: Suspicious request methods (0-10 points)
    if row['request_method'] == 'DELETE':
        score += 10
    elif row['request_method'] == 'PUT':
        score += 5

    return min(score, 100)  # Cap score at 100


def get_threat_category(score):
    """Maps risk score to a threat category label."""
    if score >= 70:
        return 'Critical'
    elif score >= 40:
        return 'High'
    elif score >= 20:
        return 'Medium'
    else:
        return 'Low'


# Apply scoring to all log entries
df_logs['risk_score'] = df_logs.apply(
    lambda row: calculate_risk_score(row, threat_feed), axis=1
)
df_logs['threat_category'] = df_logs['risk_score'].apply(get_threat_category)

print("\nRisk scoring complete.")
print("\nTop 10 highest risk IPs:")
print(
    df_logs[['ip_address', 'risk_score', 'threat_category']]
    .sort_values('risk_score', ascending=False)
    .head(10)
    .to_string(index=False)
)

print("\nThreat Category Summary:")
print(df_logs['threat_category'].value_counts())


# =============================================================================
# CELL 5 — Dashboard Visualizations
# =============================================================================
fig, axes = plt.subplots(2, 2, figsize=(16, 12))
fig.suptitle(
    'SOC IP Threat Scoring Dashboard',
    fontsize=18, fontweight='bold', y=1.02
)

# --- Chart 1: Threat Category Distribution (Pie Chart) ---
category_counts = df_logs['threat_category'].value_counts()
colors_pie = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']
axes[0, 0].pie(
    category_counts.values,
    labels=category_counts.index,
    autopct='%1.1f%%',
    colors=colors_pie,
    startangle=90
)
axes[0, 0].set_title('Threat Category Distribution', fontweight='bold')

# --- Chart 2: Top 10 Highest Risk IPs (Horizontal Bar Chart) ---
top_ips = df_logs.nlargest(10, 'risk_score')[['ip_address', 'risk_score']]
colors_bar = [
    '#d32f2f' if s >= 70 else '#f57c00' if s >= 40 else '#fbc02d'
    for s in top_ips['risk_score']
]
axes[0, 1].barh(top_ips['ip_address'], top_ips['risk_score'], color=colors_bar)
axes[0, 1].set_xlabel('Risk Score')
axes[0, 1].set_title('Top 10 Highest Risk IPs', fontweight='bold')
axes[0, 1].axvline(x=70, color='red', linestyle='--', alpha=0.7, label='Critical (70+)')
axes[0, 1].axvline(x=40, color='orange', linestyle='--', alpha=0.7, label='High (40+)')
axes[0, 1].legend()

# --- Chart 3: Risk Score Distribution (Histogram) ---
axes[1, 0].hist(
    df_logs['risk_score'], bins=20,
    color='#1565c0', edgecolor='white', alpha=0.8
)
axes[1, 0].axvline(x=70, color='red', linestyle='--', label='Critical threshold (70)')
axes[1, 0].axvline(x=40, color='orange', linestyle='--', label='High threshold (40)')
axes[1, 0].set_xlabel('Risk Score')
axes[1, 0].set_ylabel('Number of IPs')
axes[1, 0].set_title('Risk Score Distribution', fontweight='bold')
axes[1, 0].legend()

# --- Chart 4: Request Volume vs Risk Score (Scatter Plot) ---
scatter_colors = df_logs['threat_category'].map({
    'Critical': '#d32f2f',
    'High': '#f57c00',
    'Medium': '#fbc02d',
    'Low': '#388e3c'
})
axes[1, 1].scatter(
    df_logs['request_count'], df_logs['risk_score'],
    c=scatter_colors, alpha=0.6, s=50
)
axes[1, 1].set_xlabel('Request Count')
axes[1, 1].set_ylabel('Risk Score')
axes[1, 1].set_title('Request Volume vs Risk Score', fontweight='bold')

# Add legend manually for scatter
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='#d32f2f', label='Critical'),
    Patch(facecolor='#f57c00', label='High'),
    Patch(facecolor='#fbc02d', label='Medium'),
    Patch(facecolor='#388e3c', label='Low')
]
axes[1, 1].legend(handles=legend_elements)

plt.tight_layout()
plt.savefig('screenshots/threat_score_output.png', dpi=150, bbox_inches='tight')
plt.show()
print("\nDashboard saved to screenshots/threat_score_output.png")


# =============================================================================
# CELL 6 — Risk Score Trend Over Time
# =============================================================================
fig2, ax = plt.subplots(figsize=(14, 5))

df_time = df_logs.sort_values('timestamp')
ax.plot(
    df_time['timestamp'], df_time['risk_score'],
    color='#1565c0', alpha=0.5, linewidth=0.8
)
ax.fill_between(
    df_time['timestamp'], df_time['risk_score'],
    alpha=0.15, color='#1565c0'
)
ax.axhline(y=70, color='red', linestyle='--', label='Critical threshold (70)')
ax.axhline(y=40, color='orange', linestyle='--', label='High threshold (40)')
ax.set_title('Risk Score Over Time', fontweight='bold', fontsize=14)
ax.set_xlabel('Timestamp')
ax.set_ylabel('Risk Score')
ax.legend()

plt.tight_layout()
plt.savefig('screenshots/risk_chart.png', dpi=150, bbox_inches='tight')
plt.show()
print("Risk trend chart saved to screenshots/risk_chart.png")


# =============================================================================
# CELL 7 — SOC Priority Alert Table
# =============================================================================
critical_ips = df_logs[
    df_logs['threat_category'].isin(['Critical', 'High'])
].copy()
critical_ips = critical_ips.sort_values('risk_score', ascending=False)

# Enrich with threat intelligence details
critical_ips['threat_type'] = critical_ips['ip_address'].apply(
    lambda ip: threat_feed.get(ip, {}).get('threat_type', 'Suspicious Activity')
)
critical_ips['country'] = critical_ips['ip_address'].apply(
    lambda ip: threat_feed.get(ip, {}).get('country', 'Unknown')
)
critical_ips['recommended_action'] = critical_ips['threat_category'].map({
    'Critical': 'BLOCK IMMEDIATELY',
    'High': 'Investigate & Monitor'
})

alert_table = critical_ips[[
    'ip_address', 'risk_score', 'threat_category',
    'threat_type', 'country', 'recommended_action'
]].head(15)

print("\n" + "=" * 75)
print("SOC PRIORITY ALERT TABLE — IPs Requiring Immediate Attention")
print("=" * 75)
print(alert_table.to_string(index=False))
print("=" * 75)
print(f"\nTotal IPs flagged       : {len(critical_ips)}")
print(f"Critical (Block Now)    : {len(critical_ips[critical_ips['threat_category'] == 'Critical'])}")
print(f"High (Investigate)      : {len(critical_ips[critical_ips['threat_category'] == 'High'])}")

# Save outputs
alert_table.to_csv('dashboards/soc_priority_alerts.csv', index=False)
df_logs.to_csv('dashboards/full_scored_log.csv', index=False)
print("\nAlert table saved  : dashboards/soc_priority_alerts.csv")
print("Full log saved     : dashboards/full_scored_log.csv")
print("\nSOC Dashboard Complete.")
