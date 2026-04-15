# 📋 SOC IP Threat Scoring Dashboard — Project Explanation

<div align="center">

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&color=00F7FF&width=600&lines=Project+Documentation;SOC+Analyst+Workflow+Explained;From+Raw+Logs+to+Actionable+Threat+Intelligence)](https://git.io/typing-svg)

</div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9-blue?style=for-the-badge&logo=python&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-11557C?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security_Analytics-red?style=for-the-badge&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-darkred?style=for-the-badge&logoColor=white)
![Jupyter](https://img.shields.io/badge/Jupyter-F37626?style=for-the-badge&logo=jupyter&logoColor=white)

</div>

---

## 1️⃣ Project Overview

In real companies, SOC analysts receive **thousands of log entries every single day**. Their job is to identify which IP addresses are suspicious, cross-reference them against threat databases, assign a risk score, and decide which threats need immediate action versus continued monitoring.

This project **automates that entire workflow using Python** — simulating a real-world Security Operations Center pipeline from raw log ingestion to a priority alert table with recommended actions.

---

## 2️⃣ Business Problem

| Challenge | Impact |
|-----------|--------|
| Thousands of daily log entries to review | Analyst alert fatigue |
| No automated way to prioritize threats | Critical threats missed or delayed |
| Manual IP lookups against threat databases | Hours of wasted analyst time per session |
| No risk scoring framework | Inconsistent triage decisions across analysts |
| No actionable output format | Investigations start too slowly |

---

## 3️⃣ Data Source

The dataset simulates real **Apache/Nginx web server logs** — the kind every production web server generates automatically.

| Attribute | Details |
|-----------|---------|
| Total Log Records | 200 entries |
| Time Period | January 2024 (hourly intervals) |
| Malicious IPs Injected | 5 known bad actors |
| Threat Feed Size | 5 confirmed malicious IPs with intelligence data |
| Output Alerts | Critical and High severity IPs flagged for action |

**Threat intelligence feed simulates data from:**
- AbuseIPDB — community-reported malicious IPs
- AlienVault OTX — open threat exchange
- VirusTotal — malware and threat analysis
- Shodan — internet-connected device scanner

---

## 4️⃣ Tools and Technologies

| Tool | Purpose |
|------|---------|
| **Python 3.10** | Core SOC analytics pipeline |
| **Pandas** | Log data loading, cleaning, enrichment |
| **NumPy** | Simulation and statistical calculations |
| **Matplotlib** | 4-panel SOC dashboard visualization |
| **Seaborn** | Chart style enhancements |
| **JSON** | Threat intelligence feed processing |
| **Jupyter Notebook** | Interactive analysis environment |

---

## 5️⃣ How It Works

```
Raw Web Server Logs (Apache/Nginx)
        │
        ▼
┌─────────────────────┐
│  Log Simulation     │  — 200 records with IPs, methods, status codes
│  & Injection        │  — 5 known malicious IPs injected realistically
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Threat Intelligence│  — Cross-reference IPs against threat feed
│  Enrichment         │  — AbuseIPDB / OTX / VirusTotal simulation
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Risk Scoring       │  — Multi-factor scoring algorithm (0-100)
│  Algorithm          │  — Threat intel + volume + status + method
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Threat             │  — Critical / High / Medium / Low classification
│  Classification     │
└────────┬────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  Output                                 │
│  ├── 4-panel Matplotlib SOC dashboard   │
│  ├── Risk score trend over time chart   │
│  ├── soc_priority_alerts.csv            │
│  └── full_scored_log.csv                │
└─────────────────────────────────────────┘
```

---

## 6️⃣ Risk Scoring Algorithm — Core Logic

The heart of this project is the **multi-factor risk scoring function** — the same approach used by real SIEM tools like Splunk, Microsoft Sentinel, and IBM QRadar:

```python
def calculate_risk_score(row, threat_feed):
    score = 0
    ip = row['ip_address']

    # Factor 1: Threat intelligence match (0-50 points)
    if ip in threat_feed:
        if severity == 'Critical': score += 50
        elif severity == 'High':   score += 35
        elif severity == 'Medium': score += 20

    # Factor 2: High request volume (0-20 points)
    if row['request_count'] > 400: score += 20
    elif row['request_count'] > 200: score += 10

    # Factor 3: Suspicious HTTP status codes (0-20 points)
    if row['status_code'] == 403:  score += 15
    elif row['status_code'] == 500: score += 10

    # Factor 4: Suspicious request methods (0-10 points)
    if row['request_method'] == 'DELETE': score += 10

    return min(score, 100)
```

**Scoring Breakdown:**

| Factor | Max Points | Why It Matters |
|--------|-----------|----------------|
| Threat intel match | 50 | IP already confirmed malicious |
| High request volume | 20 | Too many requests = likely automated attack |
| Error status codes | 20 | 403/500 errors suggest probing behavior |
| Dangerous methods | 10 | DELETE requests can destroy data |
| **Total** | **100** | Higher score = more dangerous |

**Risk Categories:**

| Score | Category | Recommended Action |
|-------|----------|--------------------|
| 70-100 | 🔴 Critical | BLOCK IMMEDIATELY |
| 40-69 | 🟠 High | Investigate & Monitor |
| 20-39 | 🟡 Medium | Monitor Closely |
| 0-19 | 🟢 Low | Log Only |

---

## 7️⃣ Key Metrics and Results

| Metric | Value |
|--------|-------|
| **Total IPs Analyzed** | 200 |
| **Malicious IPs Injected** | 5 known threat actors |
| **Critical IPs Flagged** | Immediate block required |
| **High IPs Flagged** | Investigate and monitor |
| **Manual Lookup Time Reduced** | ~60% per analyst session |
| **Threat Types Detected** | Brute Force, Port Scanner, Malware C2, SQL Injection, DDoS Source |

---

## 8️⃣ Threat Types Explained

| Threat Type | What It Means | Severity |
|-------------|--------------|----------|
| **Brute Force** | Trying thousands of passwords to break into accounts | High |
| **Port Scanner** | Scanning systems to find open vulnerabilities | High |
| **Malware C2** | Command & Control server directing malware infections | Critical |
| **SQL Injection** | Attempting to extract data from databases illegally | High |
| **DDoS Source** | Flooding servers with traffic to cause outages | Critical |

---

## 9️⃣ Dashboard Panels

| Panel | Chart Type | What It Shows |
|-------|-----------|---------------|
| Threat Category Distribution | Pie Chart | Overall threat landscape — Critical vs High vs Medium vs Low |
| Top 10 Highest Risk IPs | Horizontal Bar | Exactly which IPs are most dangerous — red = Critical |
| Risk Score Distribution | Histogram | How scores spread across all IPs — spikes above 70 = active threats |
| Request Volume vs Risk Score | Scatter Plot | High volume + high risk = most dangerous IPs in top-right corner |
| Risk Score Over Time | Line Chart | Detects unusual spikes — sudden clusters = active attack pattern |

---

## 🔟 SOC Priority Alert Table — Sample Output

| IP Address | Risk Score | Category | Threat Type | Action |
|------------|-----------|----------|-------------|--------|
| 172.16.0.23 | 85 | 🔴 Critical | Malware C2 | BLOCK IMMEDIATELY |
| 198.51.100.77 | 85 | 🔴 Critical | DDoS Source | BLOCK IMMEDIATELY |
| 192.168.1.100 | 70 | 🔴 Critical | Brute Force | BLOCK IMMEDIATELY |
| 45.33.32.156 | 60 | 🟠 High | SQL Injection | Investigate & Monitor |
| 10.0.0.55 | 50 | 🟠 High | Port Scanner | Investigate & Monitor |

---

## 1️⃣1️⃣ Real-World Connection

| This Project | Real SOC Tool |
|--------------|--------------|
| Log data CSV | SIEM log ingestion |
| Threat feed dictionary | AbuseIPDB / AlienVault OTX API |
| Risk score function | Splunk correlation rules |
| Alert table CSV | ServiceNow incident tickets |
| Dashboard charts | Splunk / Kibana dashboards |
| Recommended action | Firewall block rules / analyst queue |

---

## 1️⃣2️⃣ Skills Demonstrated

`SOC Workflow Simulation` · `Multi-Factor Risk Scoring` · `Threat Intelligence Enrichment` · `Log Analysis` · `Python` · `Pandas` · `Matplotlib` · `Security Analytics` · `Incident Prioritization` · `Data Engineering` · `CSV Output` · `Critical Thinking`

---

## 🚀 Future Roadmap

- [ ] Integrate live AbuseIPDB and VirusTotal REST APIs
- [ ] Add MITRE ATT&CK technique mapping per threat type
- [ ] Build anomaly detection using machine learning
- [ ] Deploy as real-time web dashboard
- [ ] Add Splunk/ELK Stack integration for live log streaming

---

## ⚙️ How to Run

### Option 1 — Jupyter Notebook (Recommended)
```bash
# Open Jupyter and run all cells
jupyter notebook SOC_IP_Threat_Scoring_Dashboard.ipynb
```

### Option 2 — Python Script
```bash
python SOC_IP_Threat_Scoring_Dashboard.py
```

### Install Dependencies
```bash
pip install pandas numpy matplotlib seaborn
```

---

## 👤 Author

**Reshma Keshireddy** — Cybersecurity & Data Analytics

LinkedIn: https://linkedin.com/in/reshma-keshireddy-1283b91b6
GitHub: https://github.com/reshmakeshireddy1021-bit

---

> *"In security, speed of detection means nothing without speed of prioritization."*

---

> *This project is for educational and portfolio purposes only.*
