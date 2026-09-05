# 🛡️ AI-SHIELD

## Adaptive Security Header Detection, Risk Intelligence & Automated Remediation

> **An intelligent defensive cybersecurity framework that combines HTTP security analysis, machine learning, risk intelligence, CWE-based threat mapping, and automated server hardening.**

AI-SHIELD is a Python-based cybersecurity framework designed to analyze the security posture of web applications through their HTTP response headers.

Unlike traditional header scanners that simply report whether a security header exists, AI-SHIELD converts HTTP responses into **54 structured security features**, analyzes them using a **Random Forest machine learning model**, calculates an adaptive **0–100 risk score**, identifies specific security weaknesses, maps them to relevant **CWE references**, and generates platform-specific remediation configurations.

The complete pipeline transforms raw HTTP headers into actionable security intelligence:

```text id="ixcs5u"
Website
   ↓
HTTP Response Headers
   ↓
Security Feature Extraction
   ↓
54-Dimensional Feature Vector
   ↓
Machine Learning Risk Engine
   ↓
Risk Classification + Confidence
   ↓
Vulnerability & Threat Analysis
   ↓
CWE Mapping
   ↓
Automated Remediation
```

---

# 🚀 Core Features

## 🔍 1. Live Website Security Scanning

AI-SHIELD can inspect the HTTP response headers returned by a live website.

```bash id="wftc0m"
python run_ai_shield.py --scan https://example.com
```

The scanner retrieves the target's HTTP response headers and passes them through the complete security analysis pipeline.

The final report includes:

* Security risk classification
* ML confidence score
* Continuous risk score
* Detected vulnerabilities
* Affected HTTP headers
* Threat impact
* CWE references
* Recommended fixes
* Generated server-hardening configuration

---

# 🧠 2. Machine Learning Risk Intelligence

AI-SHIELD uses a **Random Forest ensemble classifier** to determine the security posture of the analyzed HTTP header configuration.

The model evaluates the extracted security features and classifies the target into one of four categories:

| Class | Risk Level     |
| ----- | -------------- |
| `0`   | 🟢 Secure      |
| `1`   | 🟡 Low Risk    |
| `2`   | 🟠 Medium Risk |
| `3`   | 🔴 High Risk   |

Instead of returning only a class label, AI-SHIELD also calculates:

* Prediction confidence
* Probability for every risk class
* Vulnerability status
* Continuous risk score from `0–100`

Example conceptual result:

```text id="flh8ij"
Risk Tier:          HIGH RISK
ML Confidence:      96.40%
Risk Score:         91.75 / 100
Vulnerable Status:  YES
Issues Detected:    7
```

---

# 🧬 3. 54-Feature Security Analysis

Raw HTTP response headers are converted into **54 numerical security attributes** before ML inference.

The feature space covers several important web-security areas.

### 🔐 Transport Security

Analyzes:

```text id="ibpjtn"
HTTPS
Strict-Transport-Security
HSTS max-age
includeSubDomains
HSTS preload
HSTS validity
```

### 🛡️ Content Security Policy

Detects:

```text id="3xqshf"
Content-Security-Policy presence
unsafe-inline
unsafe-eval
wildcard sources
data: permissions
CSP directive count
```

### 🖼️ Clickjacking Protection

Analyzes:

```text id="p5o4fx"
X-Frame-Options
DENY
SAMEORIGIN
ALLOW-FROM
```

### 📦 MIME-Type Protection

Checks:

```text id="fvacq8"
X-Content-Type-Options
nosniff
```

### 🔗 Referrer Security

Analyzes:

```text id="yk3x46"
Referrer-Policy
no-referrer
same-origin
strict-origin
unsafe-url
```

### 🌐 Cross-Origin Security

Evaluates:

```text id="z1dr6w"
CORS
Access-Control-Allow-Origin
Access-Control-Allow-Credentials
Wildcard origins
COOP
COEP
CORP
```

### 🍪 Cookie Security

Checks whether cookies use:

```text id="bgsb0j"
Secure
HttpOnly
SameSite
```

### 🕵️ Information Leakage

Detects exposure through headers such as:

```text id="1ky71i"
Server
X-Powered-By
X-AspNet-Version
X-PHP-Version
Framework/version headers
```

---

# ⚠️ 4. Vulnerability Detection

AI-SHIELD does more than classify a target.

A rule-based security analysis layer identifies specific security weaknesses from the extracted feature representation.

Examples include:

| Vulnerability               | Potential Impact                        |
| --------------------------- | --------------------------------------- |
| Missing HSTS                | SSL downgrade / cleartext interception  |
| Missing CSP                 | Increased XSS exposure                  |
| `unsafe-inline` CSP         | Weakened script execution protection    |
| `unsafe-eval` CSP           | Dynamic code execution exposure         |
| CSP wildcard                | Untrusted resource loading              |
| Missing X-Frame-Options     | Clickjacking                            |
| Missing `nosniff`           | MIME sniffing                           |
| Unsafe Referrer-Policy      | Sensitive URL information leakage       |
| Wildcard CORS + credentials | Unauthorized cross-origin data exposure |
| Server version disclosure   | Technology fingerprinting               |
| Insecure cookies            | Session/cookie exposure                 |

---

# 🧾 5. CWE-Based Threat Intelligence

Detected weaknesses are associated with relevant **Common Weakness Enumeration (CWE)** references.

Examples used by AI-SHIELD include:

```text id="xhn5c5"
CWE-79    → Cross-Site Scripting related weaknesses
CWE-200   → Information Exposure
CWE-319   → Cleartext Transmission
CWE-942   → Permissive Cross-Origin Policy
CWE-1021  → Improper Frame Restriction
CWE-614   → Sensitive Cookie without Secure Attribute
CWE-1004  → Sensitive Cookie without HttpOnly
```

This makes the scanner output easier to understand and connects findings with standardized security terminology.

---

# 📊 6. Adaptive Risk Score

AI-SHIELD converts the ML probability distribution into a normalized security risk score.

```text id="sd9pqi"
0 ------------------------------------------ 100
│                                              │
Secure                                      High Risk
```

The score provides a more granular security assessment than a simple vulnerable/not-vulnerable result.

A target may therefore receive results such as:

```text id="hvlh2k"
Predicted Class : Medium Risk
Risk Score      : 64.35 / 100
Confidence      : 89.72%
```

---

# 🛠️ 7. Automated Security Remediation

One of the main features of AI-SHIELD is automated remediation generation.

After analyzing the target, the framework generates hardening configurations for multiple web platforms.

### Supported Platforms

| Platform            | Generated Remediation            |
| ------------------- | -------------------------------- |
| Nginx               | `add_header` security directives |
| Apache              | `mod_headers` configuration      |
| Caddy               | Security `header` blocks         |
| Node.js / Express   | Helmet configuration             |
| FastAPI / Starlette | Security middleware              |
| Cloudflare          | Response Header Transform Rules  |

This transforms AI-SHIELD from a detection-only scanner into a:

```text id="uvlbn3"
DETECT
   ↓
ANALYZE
   ↓
ASSESS RISK
   ↓
EXPLAIN
   ↓
REMEDIATE
```

security workflow.

---

# 🏗️ System Architecture

```text id="94j0lo"
                    ┌─────────────────────┐
                    │    Target Website   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ HTTP Response       │
                    │ Header Collection   │
                    └──────────┬──────────┘
                               │
                               ▼
                 ┌───────────────────────────┐
                 │ Header Feature Extractor  │
                 │       54 Features         │
                 └─────────────┬─────────────┘
                               │
                               ▼
                 ┌───────────────────────────┐
                 │ ML Risk Intelligence      │
                 │ Random Forest Classifier  │
                 └─────────────┬─────────────┘
                               │
                  ┌────────────┴────────────┐
                  ▼                         ▼
        ┌──────────────────┐      ┌──────────────────┐
        │ Risk Assessment  │      │ Vulnerability    │
        │ + Confidence     │      │ Analysis         │
        └────────┬─────────┘      └────────┬─────────┘
                 │                         │
                 └────────────┬────────────┘
                              ▼
                   ┌──────────────────────┐
                   │ CWE / Threat Mapping │
                   └──────────┬───────────┘
                              │
                              ▼
                  ┌────────────────────────┐
                  │ Automated Remediation  │
                  └────────────────────────┘
```

---

# 📁 Project Structure

```text id="w6p1pf"
AI-SHIELD/
│
├── config.py
│   ├── Feature definitions
│   ├── Class labels
│   ├── Dataset configuration
│   └── Threat vector mappings
│
├── extractor.py
│   └── Converts HTTP headers into 54 security features
│
├── model.py
│   ├── Random Forest training
│   ├── Model evaluation
│   ├── Feature importance
│   ├── Model persistence
│   └── Risk prediction
│
├── scanner.py
│   ├── Live HTTP scanning
│   ├── Header auditing
│   ├── ML inference
│   └── Dataset batch auditing
│
├── remediation.py
│   ├── Vulnerability identification
│   ├── CWE mapping
│   └── Platform-specific remediation
│
├── run_ai_shield.py
│   └── Main command-line interface
│
└── saved_models/
    └── Trained .joblib model artifacts
```

---

# 📊 Model Training

The model uses a Random Forest classifier configured with:

```text id="r93g3t"
Estimators        : 150
Maximum Depth     : 18
Minimum Split     : 3
Class Weight      : Balanced
Random State      : 42
Parallel Training : Enabled
```

The dataset is divided using a stratified train/test split to preserve class distributions.

---

# 📈 Current Benchmark Results

The current project benchmark reports:

| Metric           |     Result |
| ---------------- | ---------: |
| 🎯 Test Accuracy | **98.30%** |
| Precision        | **0.9831** |
| Recall           | **0.9830** |
| F1-Score         | **0.9830** |
| Test Records     |  **1,000** |

### Per-Class Results

| Risk Class  | Precision | Recall |     F1 |
| ----------- | --------: | -----: | -----: |
| Secure      |    0.9709 | 1.0000 | 0.9852 |
| Low Risk    |    0.9700 | 0.9700 | 0.9700 |
| Medium Risk |    0.9885 | 0.9800 | 0.9842 |
| High Risk   |    0.9960 | 0.9840 | 0.9899 |

---

# 💻 Installation

## 1. Clone the repository

```bash id="c3rvw6"
git clone <your-repository-url>
cd AI-SHIELD
```

## 2. Create a virtual environment

### Windows

```bash id="8h4d8c"
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash id="wgyk6h"
python3 -m venv venv
source venv/bin/activate
```

## 3. Install dependencies

```bash id="x4o6sm"
pip install pandas numpy scikit-learn joblib requests
```

---

# 🚀 Running AI-SHIELD

## Full Demonstration

```bash id="zdv2g9"
python run_ai_shield.py --demo
```

Runs the model-training pipeline followed by a simulated vulnerable endpoint audit.

---

## Train the Model

```bash id="i90aw7"
python run_ai_shield.py --train
```

Displays:

```text id="oxm2v1"
Accuracy
Precision
Recall
F1-Score
Test Sample Size
Feature Importance
Per-Class Classification Report
```

---

## Scan a Live Website

```bash id="fsb30a"
python run_ai_shield.py --scan https://example.com
```

---

## Run Dataset Batch Audit

```bash id="3kt8xc"
python run_ai_shield.py --audit-dataset 100
```

This evaluates a sample of dataset records and reports prediction agreement and risk distribution.

---

# 🔄 Complete Processing Workflow

```text id="b71mh8"
                    START
                      │
                      ▼
               Enter Target URL
                      │
                      ▼
              HTTP GET Request
                      │
                      ▼
           Collect Response Headers
                      │
                      ▼
           Normalize Header Names
                      │
                      ▼
          Extract 54 Security Features
                      │
                      ▼
             Build Feature Vector
                      │
                      ▼
          Random Forest Prediction
                      │
          ┌───────────┼────────────┐
          ▼           ▼            ▼
       Class       Confidence    Probability
          │
          ▼
      Risk Score
          │
          ▼
   Vulnerability Analysis
          │
          ▼
      CWE Mapping
          │
          ▼
   Recommended Fixes
          │
          ▼
 Generate Platform Configurations
          │
          ▼
        REPORT
```

---

# 🔬 Technologies Used

### Programming

* Python

### Machine Learning

* Scikit-learn
* Random Forest Classifier

### Data Processing

* Pandas
* NumPy

### Model Persistence

* Joblib

### Networking

* Python Requests

### Cybersecurity

* HTTP Security Headers
* Content Security Policy
* HSTS
* CORS
* Cookie Security
* Cross-Origin Isolation
* CWE Mapping
* Security Misconfiguration Detection

---

# 💡 What Makes AI-SHIELD Different?

Traditional HTTP security scanners often follow:

```text id="dpkjyv"
Header Missing
      ↓
Display Warning
```

AI-SHIELD follows a broader workflow:

```text id="gq18pa"
HTTP Headers
      ↓
54 Security Features
      ↓
Machine Learning
      ↓
Risk Classification
      ↓
Probability Analysis
      ↓
Continuous Risk Score
      ↓
Specific Vulnerability Detection
      ↓
CWE Threat Mapping
      ↓
Impact Explanation
      ↓
Recommended Fix
      ↓
Platform-Specific Remediation
```

The project therefore combines **detection, risk intelligence, explainability and remediation** in one defensive pipeline.

---

# 🎯 Project Objectives

AI-SHIELD was developed with the following objectives:

1. Automate HTTP security-header analysis.
2. Convert security configurations into ML-compatible structured data.
3. Classify web security posture using machine learning.
4. Produce understandable risk scores rather than only binary results.
5. Identify specific security weaknesses.
6. Connect findings with CWE references.
7. Explain the security impact of detected weaknesses.
8. Recommend appropriate fixes.
9. Generate deployable hardening configurations for popular web platforms.
10. Provide a unified defensive security auditing workflow.

---

# 🔮 Future Enhancements

Potential future development includes:

* 🌐 Web-based security dashboard
* 📊 Interactive vulnerability visualizations
* 📄 PDF security audit reports
* 🔄 Continuous website monitoring
* 🔔 Security alerts
* 🧠 Additional ML models
* 📈 Model comparison dashboard
* 🗃️ Scan history
* 👥 Multi-user authentication
* 🔌 REST API
* 🐳 Docker deployment
* ☁️ Cloud deployment
* 🔗 CI/CD security scanning
* 📉 Security posture trend analysis
* 🧪 Automated regression testing
* 🔐 Authentication and authorization analysis
* 📦 Browser extension integration

---

# ⚠️ Limitations

AI-SHIELD primarily evaluates security posture based on **HTTP response headers and the features represented in its training dataset**.

It is not intended to replace:

* Full penetration testing
* Source-code security review
* SAST
* DAST
* Dependency vulnerability scanning
* Network vulnerability assessment
* Professional security audits

A secure header configuration alone does not guarantee that an application is free from vulnerabilities.

---

# 🔒 Ethical & Responsible Use

AI-SHIELD is intended exclusively for:

* Defensive cybersecurity
* Security education
* Academic research
* Authorized vulnerability assessment
* Security configuration auditing
* Testing systems you own or have permission to assess

## 🛡️ AI-SHIELD

### Detect. Assess. Explain. Remediate.

**Turning HTTP security headers into actionable security intelligence.**

