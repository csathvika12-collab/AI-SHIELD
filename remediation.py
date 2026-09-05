"""
AI-SHIELD Automated Remediation Engine.
Generates multi-platform configuration directives to eliminate detected security header flaws.
"""

from typing import Any, Dict, List
from config import THREAT_VECTORS


class AutomatedRemediator:
    """Generates server hardening configurations and middleware snippets."""

    @staticmethod
    def analyze_vulnerabilities(features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identifies specific missing headers, directive weaknesses, and information disclosures."""
        issues = []

        # 1. HSTS
        if not features.get("has_strict_transport_security"):
            issues.append({
                "key": "hsts_missing",
                "header": "Strict-Transport-Security",
                "recommendation": "max-age=31536000; includeSubDomains; preload",
                **THREAT_VECTORS["hsts_missing"]
            })
        elif features.get("hsts_max_age", 0) < 31536000 or not features.get("hsts_include_subdomains"):
            issues.append({
                "key": "hsts_short_max_age",
                "header": "Strict-Transport-Security",
                "recommendation": "max-age=31536000; includeSubDomains; preload",
                **THREAT_VECTORS["hsts_short_max_age"]
            })

        # 2. CSP
        if not features.get("csp_present"):
            issues.append({
                "key": "csp_missing",
                "header": "Content-Security-Policy",
                "recommendation": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
                **THREAT_VECTORS["csp_missing"]
            })
        else:
            if features.get("csp_unsafe_inline"):
                issues.append({
                    "key": "csp_unsafe_inline",
                    "header": "Content-Security-Policy",
                    "recommendation": "Migrate inline scripts to cryptographic nonces ('nonce-...') or SHA-256 hashes.",
                    **THREAT_VECTORS["csp_unsafe_inline"]
                })
            if features.get("csp_unsafe_eval"):
                issues.append({
                    "key": "csp_unsafe_eval",
                    "header": "Content-Security-Policy",
                    "recommendation": "Refactor codebase to eliminate eval(), Function(), and setTimeout(string).",
                    **THREAT_VECTORS["csp_unsafe_eval"]
                })
            if features.get("csp_wildcard"):
                issues.append({
                    "key": "csp_wildcard",
                    "header": "Content-Security-Policy",
                    "recommendation": "Replace wildcard '*' with specific, trusted origin whitelists.",
                    **THREAT_VECTORS["csp_wildcard"]
                })

        # 3. X-Frame-Options
        if not features.get("has_x_frame_options"):
            issues.append({
                "key": "xfo_missing",
                "header": "X-Frame-Options",
                "recommendation": "DENY",
                **THREAT_VECTORS["xfo_missing"]
            })

        # 4. X-Content-Type-Options
        if not features.get("xcto_nosniff"):
            issues.append({
                "key": "xcto_missing",
                "header": "X-Content-Type-Options",
                "recommendation": "nosniff",
                **THREAT_VECTORS["xcto_missing"]
            })

        # 5. Referrer-Policy
        if not features.get("has_referrer_policy") or features.get("rp_unsafe_url") or features.get("rp_no_restriction"):
            issues.append({
                "key": "rp_unsafe",
                "header": "Referrer-Policy",
                "recommendation": "strict-origin-when-cross-origin",
                **THREAT_VECTORS["rp_unsafe"]
            })

        # 6. Permissions-Policy
        if not features.get("has_permissions_policy"):
            issues.append({
                "key": "permissions_policy_missing",
                "header": "Permissions-Policy",
                "recommendation": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
                "title": "Unrestricted Browser Sensor & Feature Access",
                "cwe": "CWE-250: Execution with Unnecessary Privileges",
                "impact": "Third-party embeds or scripts could attempt to invoke camera/mic or sensitive device APIs.",
                "severity": "Medium"
            })

        # 7. Cross-Origin Isolation (COEP, COOP, CORP)
        if not features.get("has_coep") or not features.get("has_coop"):
            issues.append({
                "key": "cross_origin_isolation_missing",
                "header": "Cross-Origin-Opener-Policy & COEP",
                "recommendation": "COOP: same-origin; COEP: require-corp; CORP: same-origin",
                "title": "Lack of Cross-Origin Process Isolation",
                "cwe": "CWE-200: Exposure of Memory via Spectre Side-Channel",
                "impact": "Browser process memory could be vulnerable to cross-origin speculative side-channel reads.",
                "severity": "Low"
            })

        # 8. CORS Credentials with Wildcard
        if features.get("cors_cred_wildcard"):
            issues.append({
                "key": "cors_cred_wildcard",
                "header": "Access-Control-Allow-Origin",
                "recommendation": "Disallow wildcard '*' origin when Access-Control-Allow-Credentials is true.",
                **THREAT_VECTORS["cors_cred_wildcard"]
            })

        # 9. Server Banner / X-Powered-By Exposure
        if features.get("server_version_exposed") or features.get("x_powered_by_present") or features.get("info_leak_count", 0) > 0:
            issues.append({
                "key": "info_leak_server",
                "header": "Server / X-Powered-By",
                "recommendation": "Suppress or strip server version and technology headers in production proxy.",
                **THREAT_VECTORS["info_leak_server"]
            })

        # 10. Cookie Flags
        if features.get("cookie_present") and (not features.get("cookie_secure") or not features.get("cookie_httponly") or not features.get("cookie_samesite")):
            issues.append({
                "key": "insecure_cookie",
                "header": "Set-Cookie",
                "recommendation": "Append '; Secure; HttpOnly; SameSite=Strict' to all sensitive session cookies.",
                **THREAT_VECTORS["insecure_cookie"]
            })

        return issues

    @classmethod
    def generate_configs(cls, features: Dict[str, Any]) -> Dict[str, str]:
        """Produces deployable configurations for all major web platforms."""
        return {
            "nginx": cls._nginx_snippet(features),
            "apache": cls._apache_snippet(features),
            "caddy": cls._caddy_snippet(features),
            "express_helmet": cls._express_snippet(features),
            "fastapi": cls._fastapi_snippet(features),
            "cloudflare": cls._cloudflare_snippet(features),
        }

    @staticmethod
    def _nginx_snippet(f: Dict[str, Any]) -> str:
        lines = [
            "# ========================================================",
            "# AI-SHIELD Automated Remediation for Nginx",
            "# Place in http {} or server {} block in /etc/nginx/nginx.conf",
            "# ========================================================",
            "server_tokens off;",
            "more_clear_headers 'Server' 'X-Powered-By';  # Optional: requires headers-more module",
            "",
            "# Core Defensive Security Headers"
        ]
        lines.append('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;')
        lines.append('add_header X-Frame-Options "DENY" always;')
        lines.append('add_header X-Content-Type-Options "nosniff" always;')
        lines.append('add_header Referrer-Policy "strict-origin-when-cross-origin" always;')
        lines.append('add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;')
        lines.append('add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';" always;')
        lines.append('add_header Cross-Origin-Opener-Policy "same-origin" always;')
        lines.append('add_header Cross-Origin-Embedder-Policy "require-corp" always;')
        lines.append('add_header Cross-Origin-Resource-Policy "same-origin" always;')
        return "\n".join(lines)

    @staticmethod
    def _apache_snippet(f: Dict[str, Any]) -> str:
        return "\n".join([
            "# ========================================================",
            "# AI-SHIELD Automated Remediation for Apache (.htaccess / httpd.conf)",
            "# Requires mod_headers enabled (a2enmod headers)",
            "# ========================================================",
            "<IfModule mod_headers.c>",
            "    # Suppress signature and banner info leaks",
            "    ServerSignature Off",
            "    Header unset X-Powered-By",
            "    Header unset Server",
            "",
            "    # Enforce Security Headers",
            '    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            '    Header always set X-Frame-Options "DENY"',
            '    Header always set X-Content-Type-Options "nosniff"',
            '    Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            '    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"',
            '    Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';"',
            '    Header always set Cross-Origin-Opener-Policy "same-origin"',
            '    Header always set Cross-Origin-Embedder-Policy "require-corp"',
            '    Header always set Cross-Origin-Resource-Policy "same-origin"',
            "</IfModule>"
        ])

    @staticmethod
    def _caddy_snippet(f: Dict[str, Any]) -> str:
        return "\n".join([
            "# ========================================================",
            "# AI-SHIELD Automated Remediation for Caddy (Caddyfile)",
            "# ========================================================",
            "example.com {",
            "    header {",
            '        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            '        X-Frame-Options "DENY"',
            '        X-Content-Type-Options "nosniff"',
            '        Referrer-Policy "strict-origin-when-cross-origin"',
            '        Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"',
            '        Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';"',
            '        Cross-Origin-Opener-Policy "same-origin"',
            '        Cross-Origin-Embedder-Policy "require-corp"',
            '        Cross-Origin-Resource-Policy "same-origin"',
            "        -Server",
            "        -X-Powered-By",
            "    }",
            "}"
        ])

    @staticmethod
    def _express_snippet(f: Dict[str, Any]) -> str:
        return "\n".join([
            "// ========================================================",
            "// AI-SHIELD Automated Remediation for Node.js Express (using helmet)",
            "// Install: npm install helmet",
            "// ========================================================",
            "const express = require('express');",
            "const helmet = require('helmet');",
            "const app = express();",
            "",
            "// Disable fingerprinting header",
            "app.disable('x-powered-by');",
            "",
            "// Apply Comprehensive Security Header Suite",
            "app.use(helmet({",
            "    contentSecurityPolicy: {",
            "        directives: {",
            "            defaultSrc: [\"'self'\"],",
            "            scriptSrc: [\"'self'\"],",
            "            objectSrc: [\"'none'\"],",
            "            frameAncestors: [\"'none'\"],",
            "            upgradeInsecureRequests: [],",
            "        },",
            "    },",
            "    hsts: {",
            "        maxAge: 31536000,",
            "        includeSubDomains: true,",
            "        preload: true,",
            "    },",
            "    frameguard: { action: 'deny' },",
            "    noSniff: true,",
            "    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },",
            "    crossOriginOpenerPolicy: { policy: 'same-origin' },",
            "    crossOriginEmbedderPolicy: { policy: 'require-corp' },",
            "    crossOriginResourcePolicy: { policy: 'same-origin' },",
            "});"
        ])

    @staticmethod
    def _fastapi_snippet(f: Dict[str, Any]) -> str:
        return "\n".join([
            "# ========================================================",
            "# AI-SHIELD Automated Remediation for Python (FastAPI / Starlette)",
            "# ========================================================",
            "from fastapi import FastAPI, Request",
            "from starlette.middleware.base import BaseHTTPMiddleware",
            "",
            "app = FastAPI()",
            "",
            "class AIShieldHeadersMiddleware(BaseHTTPMiddleware):",
            "    async def dispatch(self, request: Request, call_next):",
            "        response = await call_next(request)",
            "        # Inject standard security headers",
            "        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'",
            "        response.headers['X-Frame-Options'] = 'DENY'",
            "        response.headers['X-Content-Type-Options'] = 'nosniff'",
            "        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
            "        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()'",
            "        response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\"",
            "        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'",
            "        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'",
            "        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'",
            "        # Strip leak headers",
            "        response.headers.pop('server', None)",
            "        response.headers.pop('x-powered-by', None)",
            "        return response",
            "",
            "app.add_middleware(AIShieldHeadersMiddleware)"
        ])

    @staticmethod
    def _cloudflare_snippet(f: Dict[str, Any]) -> str:
        return "\n".join([
            "# ========================================================",
            "# AI-SHIELD Cloudflare Transform Rule (HTTP Response Header Modification)",
            "# In Cloudflare Dashboard -> Rules -> Transform Rules -> Modify Response Header",
            "# ========================================================",
            "Expression: (http.request.uri.path matches \".*\")",
            "",
            "Actions (Set Static):",
            "  1. Set 'Strict-Transport-Security' = 'max-age=31536000; includeSubDomains; preload'",
            "  2. Set 'X-Frame-Options' = 'DENY'",
            "  3. Set 'X-Content-Type-Options' = 'nosniff'",
            "  4. Set 'Referrer-Policy' = 'strict-origin-when-cross-origin'",
            "  5. Set 'Permissions-Policy' = 'geolocation=(), microphone=(), camera=(), payment=()'",
            "  6. Set 'Cross-Origin-Opener-Policy' = 'same-origin'",
            "  7. Remove 'x-powered-by'",
        ])
