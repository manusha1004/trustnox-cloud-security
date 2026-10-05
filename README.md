# TRUSTNOX — Detecting Excessive Cloud Permissions
> **Tagline:** Finding over-privileged cloud identities before attackers do.

---

## 🛡️ Executive Summary

**TRUSTNOX** is a next-generation Cloud Infrastructure Entitlement Management (CIEM) and Cloud Security Posture Management (CSPM) prototype. It analyzes simulated multi-account cloud IAM environments (AWS / GCP / Azure) to detect excessive permissions, wildcard risks, and latent privilege escalation paths before adversaries can exploit them.

### What TRUSTNOX Solves
Cloud breaches rarely start with zero-day exploits; they start with over-privileged service accounts, forgotten dormant access keys, and subtle permission-chaining vectors such as `iam:PassRole` and `sts:AssumeRole`. 

TRUSTNOX ingests cloud IAM telemetry, constructs a directed privilege escalation graph using **NetworkX**, scores risks across every identity, and provides 1-click automated least-privilege remediation.

---

## 🚀 Quick Start Guide

### Option 1: One-Click Local Prototype Launch
Run with the Python launcher to start the local prototype server and automatically open the application in your default web browser:

```bash
cd C:\Users\Hp\.gemini\antigravity\scratch\trustnox-cloud-security
py start_server.py
```
> **URL:** [http://localhost:8080/index.html](http://localhost:8080/index.html)

### Option 2: Direct Browser Launch
You can also directly open `index.html` in Microsoft Edge, Google Chrome, or any modern web browser:
```powershell
Start-Process "C:\Users\Hp\.gemini\antigravity\scratch\trustnox-cloud-security\index.html"
```

### Option 3: Python Backend Analysis Engine (CLI)
Run the backend analysis engine to generate an ASCII security audit report directly in your terminal:
```bash
py trustnox_engine.py
```

### Option 4: Docker Container Deployment
```bash
docker build -t trustnox-cloud-security .
docker run -p 8080:8080 trustnox-cloud-security
```

---

## 🎯 Summit Demo Walkthrough Script

Follow this sequence for an executive or project summit demonstration:

```
Login Screen
  ↓
Main Security Dashboard
  ↓
Identity Overview Table
  ↓
Permission Analyzer
  ↓
Visual Risk Scoring
  ↓
Privilege Escalation Graph
  ↓
Unused Account Finder
  ↓
Recommended Fixes (1-Click Remediation)
  ↓
Risk Reports & PDF Export
```

### Step 1: Login Page
* Point out the dark cybersecurity theme and cybersecurity lock badge.
* Click **"Demo Login"** to automatically populate credentials and authenticate with a smooth transition.

### Step 2: Main Security Dashboard
* Point out the exact KPI cards matching cloud security benchmarks:
  * **Total Identities:** 25
  * **High Risk:** 6 (Critical pulse badge)
  * **Medium Risk:** 9 (Warning badge)
  * **Low Risk:** 10 (Least Privilege badge)
  * **Unused Accounts:** 4 (>90 Days badge)
  * **Escalation Paths:** 3 (Attack Chain badge)
* Showcase the interactive native canvas Donut Chart (40% Low, 36% Medium, 24% High) and the Top High-Risk Identities bar chart.
* Click **"Run IAM Security Scan"** to watch the animated 7-stage scanning pipeline execute in real-time.

### Step 3: Identity Overview
* Review the catalog of cloud users, roles, and service accounts.
* Demonstrate dynamic search and filtering by risk level (`High`, `Medium`, `Low`) and identity type (`User`, `Role`).
* Note key sample records: `developer-user`, `data-analyst`, `deploy-role`, and `old-admin`.
* Click **"View Details"** on `developer-user` to transition directly to the Permission Analyzer.

### Step 4 & 5: Permission Analyzer & Visual Risk Scoring
* **Target Identity:** `developer-user`
* **Flagged Actions:**
  * `iam:PassRole` ⚠️ *(Critical privilege escalation vector)*
  * `sts:AssumeRole` ⚠️ *(Cross-account role escalation)*
  * `s3:GetObject`
  * `ec2:StartInstances`
* **Risk Level:** `HIGH`
* **Reason:** *"Permissions exceed the expected access required for this identity."*
* **Visual Gauge:** Risk Score **87/100 — HIGH** with animated radial meter and contributing factor breakdown.
* Inspect the syntax-highlighted **Simulated IAM Policy JSON** with annotated danger comments.

### Step 6: Privilege Escalation Graph
* View the interactive network graph titled **"Privilege Escalation Path"**.
* Trace the critical chain highlighted in pulsing neon red:
  $$\text{Developer User} \xrightarrow{\text{iam:PassRole}} \text{Deploy Role} \xrightarrow{\text{sts:AssumeRole}} \text{Admin Role} \xrightarrow{\text{Full Control}} \text{Root Access (*)}$$
* Call attention to the warning: **"Privilege escalation detected"**.
* Point to the key recommendation: **"Remove iam:PassRole from the developer-user."**
* Click nodes to view metadata in the live Node Inspector drawer.
* Switch between alternative escalation scenarios (Scenario 2: CloudFormation Role Injection; Scenario 3: Lambda Execution Pivot).

### Step 7: Unused Account Finder
* Inspect dormant identities inactive for >90 days:
  * `old-developer` (120 days ago) — High Risk
  * `test-user` (90 days ago) — Medium Risk
  * `inactive-admin` (180 days ago) — High Risk
  * `old-admin` (120 days ago) — High Risk
* Call out the key security reality: **"Inactive identities still have active permissions."**
* Click **"Disable Account"** to immediately revoke credentials, update the status to *Disabled*, reduce the risk score to 15, and update the dashboard KPI metrics in real time!

### Step 8: Recommended Fixes (Least-Privilege Recommendations)
* For every detected vulnerability, view problem statements and synthesized fixes:
  * **developer-user:** Remove `iam:PassRole` unless specifically required.
  * **old-admin:** Disable the account and remove unnecessary permissions.
  * **wildcard-role:** Replace wildcard (`*`) permissions with specific required actions.
* Click **"Apply Fix"** to review the Before/After policy diff and enforce least-privilege policies.
* Observe the real-time state change: the identity turns green (*Remediated*), and high-risk dashboard counts decrement!

### Step 9: Risk Reports & Executive Summary
* Review the ranked list of risky identities from score 98 down to score 12.
* Filter between All, High, Medium, and Low.
* Click **"Generate Report"** to open the Executive Risk Report modal, view CIS benchmark compliance status, export data to JSON/CSV, or trigger print-to-PDF.

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Analysis Engine** | **Python 3.12** | Core AST policy parser, heuristic risk calculator, and remediation generator |
| **Simulated Cloud Data** | **JSON IAM Policies** | Realistic AWS IAM policies modeling users, roles, and trust relationships |
| **Permission Graph** | **NetworkX / DiGraph** | Directed graph modeling of privilege escalation reachability paths |
| **Risk Dashboard** | **Streamlit / Web UI (HTML5/CSS3/JS)** | Dark SOC cyber theme, interactive charts, and live policy diff viewer |
| **Deployment** | **Docker** | Containerized deployment with minimal footprint |

---

## 🔒 Security Best Practices & Governance Alignment

TRUSTNOX aligns with key industry benchmarks:
- **CIS AWS Foundations Benchmark 1.16:** Deny root and wildcard (`*`) permissions.
- **AWS Well-Architected Security Pillar:** Principle of Least Privilege (PoLP).
- **MITRE ATT&CK for Cloud:**
  - *T1078.004:* Valid Accounts (Cloud Accounts)
  - *T1548.005:* Abuse Elevation Control Mechanism (IAM Role Passing)
  - *T1098:* Account Manipulation (AssumeRole pivots)

---

## 📂 Project Directory Structure

```
trustnox-cloud-security/
├── index.html                 # Complete, self-contained interactive web prototype
├── styles.css                 # Cybersecurity dark SOC styling with responsive layout
├── app.js                     # Core application logic, routing, live state management
├── trustnox_engine.py         # Python Analysis Engine utilizing NetworkX & directed graphs
├── sample_iam_data.json       # Realistic simulated cloud IAM dataset (25 identities)
├── start_server.py            # Local HTTP server launcher with auto-browser opening
├── requirements.txt           # Python package dependencies
├── Dockerfile                 # Docker container specification
└── README.md                  # Comprehensive summit guide and architecture documentation
```
