# DFIR AI Assistant
### Autonomous Digital Forensics & Incident Response Analysis Platform

An automated **DFIR analysis platform** that ingests Windows security logs, detects malicious activity using **rule-based detection engineering**, maps events to **MITRE ATT&CK techniques**, scores incident severity, and generates **investigation-ready case reports and timelines**.

The system simulates how a **Security Operations Center (SOC)** triages incidents — transforming raw telemetry into actionable intelligence.

This project demonstrates the integration of:

- Detection engineering
- Threat hunting automation
- Security data pipelines
- Incident response tooling
- Security-focused backend engineering

---

# Overview

Modern SOC teams are overwhelmed by security alerts and log data. Analysts often spend hours manually:

- parsing logs
- correlating events
- identifying attacker techniques
- building investigation timelines
- writing incident reports

The **DFIR AI Assistant** automates this workflow.

Instead of manually analyzing raw log data, analysts can ingest logs and receive a **fully analyzed incident report with MITRE ATT&CK mapping and timeline reconstruction.**

---

# Key Features

## Automated Log Analysis

Parses Windows Security and Sysmon style events and normalizes them into a structured investigation dataset.

---

## Detection Engine

Applies rule-based detections to identify malicious patterns including:

- brute force attacks
- lateral movement
- suspicious PowerShell activity
- persistence mechanisms
- phishing macro execution chains

---

## MITRE ATT&CK Mapping

Each detection is mapped to its corresponding MITRE technique.

| Detection | MITRE Technique |
|---|---|
| Brute Force Logons | T1110 |
| Remote Service Logon | T1021 |
| Encoded PowerShell | T1059.001 |
| Service Persistence | T1543.003 |

---

## Incident Risk Scoring

Events are scored based on severity and behavioral context to determine overall **case risk level**.

Example outputs:
`
Low
Medium
High
Critical
`

---

## Automatic Incident Narrative

The system automatically generates a human-readable summary describing:

- what happened
- how the attacker moved
- what techniques were used
- recommended remediation steps

---

## Investigation Timeline

All suspicious events are reconstructed into a **chronological incident timeline**, allowing investigators to understand attacker progression.

---

## Web Dashboard

A lightweight SOC-style dashboard allows analysts to:

- browse incidents
- filter by severity
- search events
- view detailed case reports

---

# Screenshots

## SOC Dashboard

Shows detected cases, risk scores, and summary of findings.

<img width="1212" alt="dashboard" src="https://github.com/user-attachments/assets/2bf43972-8da6-47a9-898c-8f7824fca153" />



---

## Incident Case View

Displays the generated case report including MITRE mapping, detections, and investigation summary.

<img width="1212" alt="case-report" src="https://github.com/user-attachments/assets/23bbd450-2e7b-441a-9806-c05b52426562" />




---

## Investigation Timeline

Visual timeline reconstruction of attacker activity.

<img width="1002" height="603" alt="timeline" src="https://github.com/user-attachments/assets/b9b44d04-f5ac-4a55-88b8-4e71c966341d" />


---

## Rule Detection Output

Example detection for suspicious PowerShell execution.

<img width="962" height="427" alt="detections" src="https://github.com/user-attachments/assets/77b8890a-eb68-4eeb-b742-f29b73c9c79f" />

---

## API Interface (Swagger)

The platform exposes a REST API that allows analysts or security automation pipelines to ingest logs and trigger investigations programmatically.  
The Swagger UI provides interactive documentation and testing for endpoints such as log ingestion and case analysis.

<img width="1212" alt="api" src="https://github.com/user-attachments/assets/b8b909c3-912d-4737-948b-7ea2ba5e82e9" />


---

# Architecture
            +----------------------+
            |  Log Ingestion API   |
            |  (FastAPI endpoint)  |
            +----------+-----------+
                       |
                       v
            +----------------------+
            |  Log Normalization   |
            +----------+-----------+
                       |
                       v
            +----------------------+
            |  Detection Engine    |
            |  (rules + heuristics)|
            +----------+-----------+
                       |
                       v
            +----------------------+
            | MITRE ATT&CK Mapper  |
            +----------+-----------+
                       |
                       v
            +----------------------+
            |  Risk Scoring Engine |
            +----------+-----------+
                       |
                       v
            +----------------------+
            | Case Report Builder  |
            +----------+-----------+
                       |
                       v
            +----------------------+
            |  Web UI Dashboard    |
            +----------------------+ 

---

# Technologies Used

## Backend

- **Python**
- **FastAPI** — API framework
- **SQLAlchemy** — database ORM
- **SQLite** — lightweight storage
- **Pydantic** — data validation

---

## Security Engineering

- **MITRE ATT&CK Framework**
- **Detection-as-Code rule engine**
- **Windows Event Log analysis**
- **Sysmon telemetry parsing**

---

## Frontend

- **Jinja2 Templates**
- **HTML / CSS**
- **Lightweight SOC-style dashboard**

---

## Data Processing

- JSONL log ingestion
- timeline reconstruction
- IOC extraction
- behavioral correlation

---

# Example Attack Scenario

Example attack the platform detects automatically:

1. Attacker attempts password brute force
2. Account successfully authenticates
3. Attacker pivots to another system (lateral movement)
4. Malicious PowerShell payload executed
5. Persistence installed via Windows service

The system identifies:
`
Brute Force Attempt
→ Valid Account Login
→ Lateral Movement
→ PowerShell Execution
→ Persistence Mechanism
`
and generates a **complete investigation report automatically.**

---

# Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/dfir-ai-assistant.git
cd dfir-ai-assistant
```
Create virtual environment:
```bash
python -m venv venv
```
Activate environment:
Windows
```bash
venv\Scripts\activate
```
Mac/Linux
```
source venv/bin/activate
```
Install dependencies:
```
pip install fastapi uvicorn sqlalchemy jinja2 pydantic python-multipart pyyaml
```
# Running the Platform

Start the server:
```
uvicorn app.main:app --reload
```
Access the interfaces:
## API Documentation
`
http://127.0.0.1:8000/docs
`
## SOC Dashboard
`
http://127.0.0.1:8000/ui
`

---

# Using the DFIR Assistant

## Step 1 — Upload Logs

Upload Windows event logs through the API.

Supported format:
`
JSONL (one event per line)
`
Example File:
`
samples/mixed_security_sysmon.jsonl
`
Upload through Swagger UI: 
`
POST /ingest
`
## Step 2 — Run Detection Engine
Run the detection pipeline:
`
POST /cases/analyze
`
This will:
-run rule engine
-map MITRE techniques
-compute risk score
-generate investigation summary

## Step 3 — View Case Report
Navigate to the dashboard:
`
/ui
`
Click on a case to view:
-detections
-MITRE mapping
-IOC summary
-investigation timeline
-remediation recommendations
# Detection Rules 
Rules are defined using Detection-as-Code YAML rules.
```bash
name: Encoded PowerShell Execution
description: Detects PowerShell commands using encoded payloads
mitre:
  technique: T1059.001
severity: high
condition:
  command_line_contains:
    - "-enc"
    - "FromBase64String"
```
Rules can be added to:
`
rules/
`
and automatically loaded by the detection engine. 

---
# Example Output
Example generated report summary:
```bash
Case risk is CRITICAL (100/100)

Indicators suggest a brute force attack against user "employee".
The same account later authenticated successfully and accessed
multiple hosts indicating possible lateral movement.

Subsequent activity shows execution of encoded PowerShell
commands downloading external content.

A Windows service was created on server-1 indicating
potential persistence installation.
```

# Project structure
```bash
dfir-ai-assistant
│
├── app
│   ├── api
│   ├── core
│   │   ├── detections.py
│   │   ├── scoring.py
│   │   ├── timeline.py
│   │   ├── mitre.py
│   │   └── summary.py
│   ├── db
│   └── main.py
│
├── rules
│   └── detection rules
│
├── samples
│   └── sample Windows logs
│
├── ui
│   ├── templates
│   └── static
│
└── README.md
```
# Why this Project Matters
This project demonstrates practical skills used by:
-SOC Analysts
-Detection Engineers
-Threat Hunters
-DFIR Investigators
-Security Automation Engineers

Including:
-security log analysis
-threat detection engineering
-MITRE ATT&CK mapping
-automated incident triage
-SOC tooling development

# Future Improvements
-Future Improvements
-Planned enhancements include:
-Elastic / SIEM integration
-automated threat intelligence enrichment
-ML-based anomaly detection
-graph-based attack path visualization
-containerized deployment (Docker)
-cloud deployment (AWS)

# License

MIT License

Copyright (c) 2026 Benjamin Anderson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.



