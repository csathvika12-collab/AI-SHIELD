"""
AI-SHIELD Feature Extractor.
Extracts 54 structured security attributes from raw HTTP response headers,
matching the training schema of the HTTP header vulnerability dataset.
"""

import re
from typing import Any, Dict, Optional
from config import FEATURE_COLS

LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-wordpress-cache", "x-runtime",
    "x-version", "x-backend-server", "x-php-version", "x-framework",
    "via", "x-forwarded-server"
]


class HeaderFeatureExtractor:
    """Extracts lexical, directive, and policy features from HTTP headers."""

    @staticmethod
    def extract_features(headers: Dict[str, str], url: str = "https://target.local", status: int = 200) -> Dict[str, Any]:
        """
        Parses raw header dictionary and converts it into the 54-feature dictionary
        aligned with the AI-SHIELD training dataset.
        """
        # Normalize header keys to lowercase
        h = {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}
        f: Dict[str, Any] = {}

        # Meta attributes
        is_https = int(url.lower().startswith("https://") or h.get("upgrade-insecure-requests") == "1")
        f["https"] = is_https
        f["header_count"] = len([k for k in h if not k.startswith("_")])

        # Strict-Transport-Security (HSTS)
        hsts = h.get("strict-transport-security", "")
        f["has_strict_transport_security"] = int(bool(hsts))
        m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        f["hsts_max_age"] = int(m.group(1)) if m else 0
        f["hsts_include_subdomains"] = int("includesubdomains" in hsts.lower())
        f["hsts_preload"] = int("preload" in hsts.lower())
        f["hsts_valid"] = int(f["hsts_max_age"] >= 31536000)

        # Content-Security-Policy (CSP)
        csp = h.get("content-security-policy", "")
        f["has_content_security_policy"] = int(bool(csp))
        f["csp_present"] = int(bool(csp))
        cv = csp.lower()
        f["csp_unsafe_inline"] = int("'unsafe-inline'" in cv)
        f["csp_unsafe_eval"] = int("'unsafe-eval'" in cv)
        f["csp_wildcard"] = int(" * " in cv or cv.startswith("*") or "default-src *" in cv or "script-src *" in cv)
        f["csp_allow_data"] = int("data:" in cv)
        f["csp_directive_count"] = len([d for d in csp.split(";") if d.strip()]) if csp else 0

        # X-Frame-Options (XFO)
        xfo = h.get("x-frame-options", "").upper()
        f["has_x_frame_options"] = int(bool(xfo))
        f["xfo_deny"] = int("DENY" in xfo)
        f["xfo_sameorigin"] = int("SAMEORIGIN" in xfo)
        f["xfo_allowfrom"] = int("ALLOW-FROM" in xfo)

        # X-Content-Type-Options (XCTO)
        xcto = h.get("x-content-type-options", "")
        f["has_x_content_type_options"] = int(bool(xcto))
        f["xcto_nosniff"] = int("nosniff" in xcto.lower())

        # X-XSS-Protection (Legacy)
        xxss = h.get("x-xss-protection", "")
        f["has_x_xss_protection"] = int(bool(xxss))
        f["xxss_enabled"] = int("1" in xxss)
        f["xxss_block"] = int("mode=block" in xxss.lower())
        f["xxss_report_uri"] = int("report=" in xxss.lower())

        # Referrer-Policy
        rp = h.get("referrer-policy", "").lower()
        f["has_referrer_policy"] = int(bool(rp))
        f["rp_no_referrer"] = int("no-referrer" in rp and "when" not in rp)
        f["rp_same_origin"] = int("same-origin" in rp)
        f["rp_strict_origin"] = int("strict-origin" in rp)
        f["rp_unsafe_url"] = int("unsafe-url" in rp)
        f["rp_no_restriction"] = int(not rp or rp == "no-referrer-when-downgrade")

        # Permissions-Policy
        f["has_permissions_policy"] = int("permissions-policy" in h or "feature-policy" in h)

        # Cache-Control
        cc = h.get("cache-control", "").lower()
        f["has_cache_control"] = int(bool(cc))
        f["cc_no_store"] = int("no-store" in cc)
        f["cc_no_cache"] = int("no-cache" in cc)
        f["cc_public_sensitive"] = int("public" in cc)

        # Expect-CT
        f["has_expect_ct"] = int("expect-ct" in h)

        # Modern Cross-Origin Isolation (COEP, COOP, CORP)
        f["has_cross_origin_embedder_policy"] = int("cross-origin-embedder-policy" in h)
        f["has_coep"] = f["has_cross_origin_embedder_policy"]

        f["has_cross_origin_opener_policy"] = int("cross-origin-opener-policy" in h)
        f["has_coop"] = f["has_cross_origin_opener_policy"]

        f["has_cross_origin_resource_policy"] = int("cross-origin-resource-policy" in h)
        f["has_corp"] = f["has_cross_origin_resource_policy"]

        # Cross-Origin Resource Sharing (CORS)
        acao = h.get("access-control-allow-origin", "")
        f["has_access_control_allow_origin"] = int(bool(acao))
        f["has_access_control_allow_credentials"] = int("access-control-allow-credentials" in h)
        f["cors_present"] = int(bool(acao))
        f["cors_wildcard"] = int(acao.strip() == "*")
        f["cors_cred_wildcard"] = int(
            acao.strip() == "*" and h.get("access-control-allow-credentials", "").lower() == "true"
        )

        # Cookie Security Attributes
        sc = h.get("set-cookie", "").lower()
        f["cookie_present"] = int("set-cookie" in h)
        f["cookie_secure"] = int("secure" in sc) if f["cookie_present"] else 0
        f["cookie_httponly"] = int("httponly" in sc) if f["cookie_present"] else 0
        f["cookie_samesite"] = int("samesite" in sc) if f["cookie_present"] else 0

        # Information Leakage & Exposure
        f["info_leak_count"] = sum(1 for lh in LEAK_HEADERS if lh in h)
        srv = h.get("server", "")
        f["server_version_exposed"] = int(bool(re.search(r"[0-9]+\.[0-9]+", srv)))
        f["x_powered_by_present"] = int("x-powered-by" in h)

        return f

    @staticmethod
    def get_feature_vector(features: Dict[str, Any]) -> list:
        """Returns ordered feature list matching FEATURE_COLS for ML model input."""
        return [float(features.get(col, 0)) for col in FEATURE_COLS]
