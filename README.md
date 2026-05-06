
# 🛡️ AI SOC Analyst Assistant

**Log Analysis · Threat Detection · SOC Automation · LLM-Powered**

---

## 📌 Overview

AI SOC Analyst Assistant is an **enterprise-style cybersecurity platform** that analyzes raw logs, detects threats, correlates attacks, enriches with Threat Intelligence, and visualizes everything in an interactive dashboard.

It simulates a real **SOC (Security Operations Center)** workflow using a combination of:

* Rule-based detection
* LLM-powered analysis (Llama3 / Ollama)
* Threat Intelligence enrichment
* SOAR automation
* Analyst feedback loop

---

## ⚙️ Features

### 🔍 Detection Engine

* Rule-based detection for:

  * XSS, SQL Injection, Brute Force
  * LFI, RCE, Scanning attacks
* LLM-powered alert generation
* Risk scoring + confidence estimation

### 🔗 Correlation Engine

* Multi-log attack correlation
* Campaign detection (multi-step attacks)
* Correlation risk scoring

### 🔍 Threat Intelligence (TI)

* IP reputation enrichment
* Malicious / Suspicious classification
* External validation to reduce false positives

### ⚙️ SOAR (Automation)

* Automated response playbooks
* Ticket generation simulation
* Escalation to SOC Level 2

### 🗺️ MITRE ATT&CK Mapping

* Tactics & techniques mapping
* Heatmap visualization

### 📊 Dashboard (Streamlit)

* Interactive SOC dashboard
* Alert investigation panel
* Campaign visualization
* Risk & severity analytics
* Threat Intel panel
* SOAR tracking

### 📈 Evaluation & AI Quality

* Alert quality scoring
* True Positive / False Positive tracking
* Hallucination detection for LLM outputs

### 💬 Feedback Loop

* Analyst TP/FP override
* Calibration of false positive scoring
* Continuous improvement mechanism

---

## 🏗️ Architecture

```bash
Logs → Rule Engine → LLM Analysis → Alert Generation
     → Correlation Engine → Threat Intel → SOAR
     → Dashboard → Feedback Loop
```

---

## 📂 Project Structure

```bash
soc_project/
│
├── dashboard_soc.py          # Streamlit dashboard
├── feedback_loop.py          # Analyst feedback system
├── threat_intel.py           # TI enrichment module
├── rule_engine.py            # Detection rules
├── correlation_engine.py     # Attack correlation
├── evaluateur_complet.py     # Evaluation system
│
├── data/
│   ├── results_docker.json
│   ├── evaluation_report.json
│
├── requirements.txt
└── README.md
```

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/soc_project.git
cd soc_project
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Run with Docker

```bash
docker-compose up -d --build
```

---

## ▶️ Usage

### Run the pipeline (generate alerts)

```bash
python pipeline.py
```

### Launch the dashboard

```bash
streamlit run dashboard_soc.py
```

---

## 📊 Example Output

* Alerts with severity (Critical / High / Medium / Low)
* Attack types (SQLi, XSS, Brute Force…)
* Campaign detection
* MITRE mapping
* Threat Intel enrichment
* SOAR actions

---

## 🧠 Technologies Used

* Python
* Streamlit
* Pandas
* Plotly
* Ollama (Llama3)
* Docker
* JSON-based pipeline

---

## 🔐 Use Cases

* SOC Analyst training
* Cybersecurity research projects
* SIEM/SOAR simulation
* Log analysis automation
* AI-powered threat detection

---

## ⚠️ Limitations

* Uses simulated or offline Threat Intelligence (no live feeds by default)
* JSON-based storage (not scalable like SIEM tools)
* LLM output may require validation (hallucination handling included)

---

## 🔮 Future Improvements

* Real-time log streaming (Kafka)
* Integration with SIEM tools (Splunk / ELK)
* API backend (FastAPI)
* Database support (PostgreSQL / Elasticsearch)
* Live Threat Intelligence APIs

---

## 👩‍💻 Author

**Asmaa Bensair**
Cybersecurity Student | SOC Analyst Enthusiast


