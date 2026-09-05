"""
Configuration and constants for AI-SHIELD.
Defines dataset paths, model parameters, feature columns, and threat vector mappings.
"""

import os

# Base directory for AI-SHIELD
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAVED_MODELS_DIR = os.path.join(BASE_DIR, "saved_models")
os.makedirs(SAVED_MODELS_DIR, exist_ok=True)

# Default path to the extracted public dataset
DEFAULT_DATASET_PATH = os.path.normpath(
    r"C:\Users\csath\Downloads\http_header_vuln_detection (3)\http_header_vuln_detection\training_dataset.csv"
)

# Target classes
CLASS_NAMES = {
    0: "Secure",
    1: "Low Risk",
    2: "Medium Risk",
    3: "High Risk"
}

CLASS_COLORS = {
    0: "\033[92m",  # Green
    1: "\033[93m",  # Yellow
    2: "\033[38;5;208m",  # Orange
    3: "\033[91m"   # Red
}
COLOR_RESET = "\033[0m"

# The exact 54 numeric features used in the dataset
FEATURE_COLS = [
    "https", "header_count",
    "has_strict_transport_security", "hsts_max_age", "hsts_include_subdomains",
    "hsts_preload", "hsts_valid",
    "has_content_security_policy", "csp_present", "csp_unsafe_inline",
    "csp_unsafe_eval", "csp_wildcard", "csp_allow_data", "csp_directive_count",
    "has_x_frame_options", "xfo_deny", "xfo_sameorigin", "xfo_allowfrom",
    "has_x_content_type_options", "xcto_nosniff",
    "has_x_xss_protection", "xxss_enabled", "xxss_block", "xxss_report_uri",
    "has_referrer_policy", "rp_no_referrer", "rp_same_origin", "rp_strict_origin",
    "rp_unsafe_url", "rp_no_restriction",
    "has_permissions_policy",
    "has_cache_control", "cc_no_store", "cc_no_cache", "cc_public_sensitive",
    "has_expect_ct",
    "has_cross_origin_embedder_policy", "has_coep",
    "has_cross_origin_opener_policy", "has_coop",
    "has_cross_origin_resource_policy", "has_corp",
    "has_access_control_allow_origin", "has_access_control_allow_credentials",
    "cors_wildcard", "cors_cred_wildcard", "cors_present",
    "cookie_present", "cookie_secure", "cookie_httponly", "cookie_samesite",
    "info_leak_count", "server_version_exposed", "x_powered_by_present"
]

# Threat vector mapping for missing/misconfigured headers
THREAT_VECTORS = {
    "hsts_missing": {
        "title": "Cleartext HTTP / SSL Downgrade (MitM)",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "impact": "Attackers on shared networks can intercept credentials or force unencrypted HTTP traffic.",
        "severity": "High"
    },
    "hsts_short_max_age": {
        "title": "Sub-optimal HSTS Cache Lifetime",
        "cwe": "CWE-319: Insufficient HSTS Protection Duration",
        "impact": "max-age < 1 year (31,536,000s) limits persistent transport-layer security guarantees.",
        "severity": "Low"
    },
    "csp_missing": {
        "title": "Cross-Site Scripting (XSS) & Unauthorized Script Execution",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "impact": "Vulnerable to malicious script injection, DOM manipulation, and credential harvesting.",
        "severity": "Critical"
    },
    "csp_unsafe_inline": {
        "title": "Permissive CSP ('unsafe-inline')",
        "cwe": "CWE-79: Bypass of Script Execution Controls",
        "impact": "Inline scripts are allowed, severely undermining Content-Security-Policy defenses against XSS.",
        "severity": "High"
    },
    "csp_unsafe_eval": {
        "title": "Permissive CSP ('unsafe-eval')",
        "cwe": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        "impact": "Permits eval() and Function constructors, enabling dynamic payload execution.",
        "severity": "Medium"
    },
    "csp_wildcard": {
        "title": "Overly Permissive CSP Wildcard (*)",
        "cwe": "CWE-284: Improper Access Control in Content Policy",
        "impact": "Allows script, connect, or object loading from arbitrary domains.",
        "severity": "High"
    },
    "xfo_missing": {
        "title": "Clickjacking / UI Redressing",
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        "impact": "Target page can be embedded in hidden iframes to deceive users into triggering actions.",
        "severity": "High"
    },
    "xcto_missing": {
        "title": "MIME-Type Sniffing Exploit",
        "cwe": "CWE-16: Configuration Vulnerability (Missing nosniff)",
        "impact": "Browsers may treat non-executable assets (images, text) as executable scripts.",
        "severity": "Medium"
    },
    "rp_unsafe": {
        "title": "Sensitive Information Leakage via Referer Header",
        "cwe": "CWE-200: Exposure of Sensitive Information to Unauthorized Actor",
        "impact": "URL parameters containing authentication tokens or session identifiers are leaked to external origins.",
        "severity": "Medium"
    },
    "cors_cred_wildcard": {
        "title": "Insecure CORS Policy with Wildcard & Credentials",
        "cwe": "CWE-942: Permissive Cross-Origin Resource Sharing Policy",
        "impact": "Permits unauthorized origins to read authenticated responses containing private user data.",
        "severity": "Critical"
    },
    "info_leak_server": {
        "title": "Server Version & Stack Disclosure",
        "cwe": "CWE-200: Information Disclosure via Software Fingerprinting",
        "impact": "Exposes precise software versions (e.g. Apache/2.4.41, PHP/7.4.3), aiding reconnaissance for known CVEs.",
        "severity": "Low"
    },
    "insecure_cookie": {
        "title": "Insecure Cookie Flags (Missing Secure/HttpOnly/SameSite)",
        "cwe": "CWE-614 / CWE-1004 / CWE-1275",
        "impact": "Cookies are exposed to JavaScript theft (XSS) or transmission across unencrypted connections.",
        "severity": "High"
    }
}
