# AI-SHIELD: Adaptive Security Header Detection, Risk Intelligence & Automated Remediation

**AI-SHIELD** is an enterprise-grade defensive security intelligence framework that detects HTTP security header vulnerabilities, calculates adaptive risk scores using machine learning trained on 5,000 security header benchmarks, and automatically synthesizes platform-tailored server hardening configurations.

---

## Architecture Overview

```
C:\Users\csath\ai_shield\
├── config.py             # Constants, dataset path, threat vectors (CWE mappings) & 54 features
├── extractor.py          # Feature extractor mapping raw HTTP headers to the 54 dataset features
├── model.py              # ML risk engine (Random Forest ensemble) with multiclass inference
├── remediation.py        # Automated remediation synthesizer (Nginx, Apache, Caddy, Node, FastAPI)
├── scanner.py            # Unified scanner for live endpoints, raw header dicts & batch dataset audits
├── run_ai_shield.py      # CLI entry point supporting training, live scanning, and dataset audits
└── saved_models/         # Persisted model artifacts (.joblib)
```

---

## Dataset Integration

The system directly utilizes the 5,000-sample dataset extracted from:
`C:\Users\csath\Downloads\http_header_vuln_detection (3)\http_header_vuln_detection\training_dataset.csv`

### Feature Representation (54 Attributes)
- **Transport Security:** `has_strict_transport_security`, `hsts_max_age`, `hsts_include_subdomains`, `hsts_preload`, `hsts_valid`, `https`
- **Content Security:** `csp_present`, `csp_unsafe_inline`, `csp_unsafe_eval`, `csp_wildcard`, `csp_allow_data`, `csp_directive_count`
- **Framing & MIME Protection:** `xfo_deny`, `xfo_sameorigin`, `xfo_allowfrom`, `xcto_nosniff`
- **Referrer & Sensor Controls:** `rp_same_origin`, `rp_strict_origin`, `rp_unsafe_url`, `has_permissions_policy`
- **Process Isolation:** `has_coep`, `has_coop`, `has_corp`
- **CORS & Cookies:** `cors_wildcard`, `cors_cred_wildcard`, `cookie_secure`, `cookie_httponly`, `cookie_samesite`
- **Information Leaks:** `info_leak_count`, `server_version_exposed`, `x_powered_by_present`

### Target Classes
- **Class 0:** `Secure`
- **Class 1:** `Low Risk`
- **Class 2:** `Medium Risk`
- **Class 3:** `High Risk`

---

## Performance Benchmark

Trained with a balanced Random Forest ensemble on 4,000 records and evaluated against a stratified holdout test set of 1,000 records:

| Metric | Score |
|---|---|
| **Test Accuracy** | **98.30%** |
| **Weighted Precision** | **0.9831** |
| **Weighted Recall** | **0.9830** |
| **Weighted F1-Score** | **0.9830** |

### Per-Class Evaluation
| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **Secure** | 0.9709 | 1.0000 | 0.9852 | 200 |
| **Low Risk** | 0.9700 | 0.9700 | 0.9700 | 200 |
| **Medium Risk** | 0.9885 | 0.9800 | 0.9842 | 350 |
| **High Risk** | 0.9960 | 0.9840 | 0.9899 | 250 |

---

## Command Line Usage

### 1. Run Complete End-to-End Demo
```bash
python run_ai_shield.py --demo
```

### 2. Retrain ML Model & Display Evaluation
```bash
python run_ai_shield.py --train
```

### 3. Scan a Live Target Endpoint
```bash
python run_ai_shield.py --scan https://example.com
```

### 4. Run Batch Audit on Dataset Records
```bash
python run_ai_shield.py --audit-dataset 100
```

---

## Automated Multi-Platform Remediation

AI-SHIELD generates instant, copy-paste hardening configurations:
- **Nginx:** `add_header` directives + `server_tokens off;`
- **Apache:** `mod_headers` configuration with banner unsetting
- **Caddy:** Modern `header` blocks
- **Node.js Express:** Standardized `helmet` initialization
- **Python FastAPI / Starlette:** Asynchronous `BaseHTTPMiddleware`
- **Cloudflare:** HTTP Response Header Transform Rules
