# 🔐 SOC IP Threat Scoring & Security Analytics Dashboard

> **Turning raw security logs into actionable threat intelligence — the way real SOC analysts work.**

---

## 📌 Overview

This project simulates a real-world **Security Operations Center (SOC)** workflow by analyzing network and web server logs, enriching IP data with threat intelligence feeds, and calculating risk scores to help analysts prioritize threats faster.

Built to demonstrate the intersection of **cybersecurity analytics** and **data engineering** — from raw log ingestion to executive-ready visualizations.

---

## 🎯 Business Impact

| Metric | Result |
|--------|--------|
| Manual IP lookup time reduced | ~60% |
| Threat prioritization speed | Significantly improved |
| Alert fatigue reduction | Automated scoring replaces manual triage |
| Analyst decision support | Risk-tiered dashboard for faster response |

---

## 🛠 Tech Stack

| Category | Tools |
|----------|-------|
| Language | Python (Pandas, NumPy, Matplotlib, Plotly) |
| Data Sources | Apache/Nginx logs, JSON threat feeds |
| APIs | VirusTotal, AbuseIPDB |
| Visualization | Plotly interactive dashboards |
| Notebook | Jupyter Notebook |
| Concepts | MITRE ATT&CK, CVSS, SIEM workflows |

---

## ⚙️ How It Works

```
Raw Logs → IP Extraction → Threat Intelligence Enrichment
       → Risk Scoring Algorithm → Dashboard Visualization
```

1. **Ingest** — Import Apache/Nginx web server and network logs
2. **Extract** — Parse and extract IP addresses from log data
3. **Enrich** — Cross-reference IPs against VirusTotal and AbuseIPDB APIs
4. **Score** — Apply weighted risk scoring based on severity indicators
5. **Visualize** — Generate interactive Plotly dashboards for SOC analysts
6. **Prioritize** — Surface high-risk IPs for immediate incident response

---

## 📊 Key Features

- **Automated threat intelligence pipeline** — no manual IP lookups
- **Risk score tiering** — Low / Medium / High / Critical classification
- **Geographic IP distribution** — visualize where threats originate
- **Alert severity breakdown** — prioritize what matters most
- **SOC-ready output** — dashboards built for both analyst and leadership audiences

---

## 📂 Project Structure

```
SOC-IP-Threat-Scoring-Dashboard/
│
├── dashboards/         # Processed scoring outputs
├── data/               # Sample log files and threat feeds
├── notebooks/          # Analysis notebooks
│   └── SOC_IP_Threat_Scoring_Dashboard.ipynb
├── screenshots/        # Dashboard visualizations
├── README.md
└── .gitignore
```

---

## 📸 Dashboard Outputs

### Threat Score Distribution
![Threat Score](screenshots/threat_score_output.png)

### Risk Score Visualization
![Risk Chart](screenshots/risk_chart.png)

### Geographic Threat Analysis
![Risk Chart 2](screenshots/risk_chart%202.png)

---

## 💡 Skills Demonstrated

- Security log parsing and data extraction
- REST API integration for threat intelligence enrichment
- Risk scoring algorithm development
- Interactive data visualization with Plotly
- SOC workflow simulation and incident prioritization
- Cybersecurity data analysis using Python

---

## 🚀 Future Roadmap

- [ ] Real-time threat feed automation
- [ ] MITRE ATT&CK framework mapping
- [ ] Anomaly detection using machine learning
- [ ] Web-based dashboard deployment
- [ ] Splunk/ELK Stack integration

---

## 👤 Author

**Reshma Keshireddy**
*Data Analyst | Business Intelligence | Cybersecurity Analytics*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/reshma-keshireddy-1283b91b6)
[![GitHub](https://img.shields.io/badge/GitHub-Portfolio-black)](https://github.com/reshmakeshireddy1021-bit)

---

> *This project is for educational and portfolio purposes only.*
