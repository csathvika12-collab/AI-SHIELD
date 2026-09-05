"""
AI-SHIELD Unified Scanner.
Coordinates feature extraction, adaptive risk scoring, threat vector mapping, and remediation generation.
"""

from typing import Any, Dict, List, Optional
import requests
import pandas as pd
from extractor import HeaderFeatureExtractor
from model import AdaptiveRiskIntelligence
from remediation import AutomatedRemediator
from config import DEFAULT_DATASET_PATH, CLASS_NAMES


class AIShieldScanner:
    """Unified scanning and intelligence orchestrator."""

    def __init__(self, risk_engine: Optional[AdaptiveRiskIntelligence] = None):
        self.risk_engine = risk_engine or AdaptiveRiskIntelligence()
        if not self.risk_engine.is_trained:
            self.risk_engine.train()

    def scan_url(self, url: str, timeout: int = 8) -> Dict[str, Any]:
        """Performs live HTTP inspection and security posture assessment."""
        target_url = url if url.startswith("http://") or url.startswith("https://") else f"https://{url}"
        headers_found = {}
        status_code = 0

        try:
            resp = requests.get(
                target_url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "AI-SHIELD-Auditor/2.0 (Defensive Security Scanner)"}
            )
            headers_found = dict(resp.headers)
            status_code = resp.status_code
            effective_url = resp.url
        except requests.RequestException as e:
            effective_url = target_url
            headers_found = {"_error": str(e)}

        return self.audit_headers(headers_found, target=effective_url, status=status_code)

    def audit_headers(self, headers: Dict[str, str], target: str = "custom-target", status: int = 200) -> Dict[str, Any]:
        """Analyzes header dictionary, computes ML risk, and compiles remediation package."""
        # 1. Extract 54 attributes
        features = HeaderFeatureExtractor.extract_features(headers, url=target, status=status)

        # 2. ML Adaptive Risk Inference
        ml_result = self.risk_engine.predict(features)

        # 3. Threat Vector & Misconfiguration Analysis
        vulnerabilities = AutomatedRemediator.analyze_vulnerabilities(features)

        # 4. Generate Multi-Platform Remediations
        remediations = AutomatedRemediator.generate_configs(features)

        return {
            "target": target,
            "status_code": status,
            "ml_risk_assessment": ml_result,
            "detected_flaws_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "extracted_features": features,
            "remediation_configs": remediations,
            "raw_headers_analyzed": {k: v for k, v in headers.items() if not k.startswith("_")}
        }

    def audit_dataset_batch(self, dataset_path: str = DEFAULT_DATASET_PATH, sample_size: int = 50) -> Dict[str, Any]:
        """Runs audit over dataset samples to compute benchmark risk distribution."""
        df = pd.read_csv(dataset_path)
        sample = df.sample(min(sample_size, len(df)), random_state=42)

        results = []
        for _, row in sample.iterrows():
            url = row.get("url", "unknown")
            # Build feature dictionary from dataset row
            row_features = {c: row[c] for c in df.columns if c in HeaderFeatureExtractor.extract_features({}, "").keys()}
            ml_result = self.risk_engine.predict(row_features)
            vulns = AutomatedRemediator.analyze_vulnerabilities(row_features)

            results.append({
                "url": url,
                "ground_truth_label": row.get("vuln_label"),
                "ground_truth_class": row.get("vuln_class"),
                "predicted_label": ml_result["risk_label"],
                "confidence": ml_result["confidence"],
                "risk_score": ml_result["continuous_risk_score"],
                "flaws_detected": len(vulns)
            })

        summary_df = pd.DataFrame(results)
        accuracy = (summary_df["ground_truth_label"] == summary_df["predicted_label"]).mean()

        return {
            "batch_size": len(results),
            "batch_accuracy": float(accuracy),
            "distribution": summary_df["predicted_label"].value_counts().to_dict(),
            "samples": results[:10]
        }
