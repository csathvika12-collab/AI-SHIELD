"""
AI-SHIELD Main CLI Entry Point.
Adaptive Security Header Detection, Risk Intelligence & Automated Remediation.
"""

import argparse
import json
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from config import DEFAULT_DATASET_PATH
from model import AdaptiveRiskIntelligence
from scanner import AIShieldScanner


def print_banner():
    print(r"""
========================================================================
     _    ___       ____  _   _ ___ _____ _     ____  
    / \  |_ _|     / ___|| | | |_ _| ____| |   |  _ \ 
   / _ \  | | _____\___ \| |_| || ||  _| | |   | | | |
  / ___ \ | ||_____|___) |  _  || || |___| |___| |_| |
 /_/   \_\___|     |____/|_| |_|___|_____|_____|____/ 
 
 Adaptive Security Header Detection & Automated Remediation System
 Powered by Machine Learning trained on 5,000 Security Header Samples
========================================================================
""")


def format_risk_badge(label: str) -> str:
    badges = {
        "Secure": "[ SECURE ]",
        "Low Risk": "[ LOW RISK ]",
        "Medium Risk": "[ MEDIUM RISK ]",
        "High Risk": "[ HIGH RISK ]"
    }
    return badges.get(label, f"[{label}]")


def run_training():
    print("\n[*] Initializing AI-SHIELD Model Training Pipeline...")
    engine = AdaptiveRiskIntelligence()
    metrics = engine.train(DEFAULT_DATASET_PATH)

    print("\n" + "=" * 70)
    print("           MODEL TRAINING & EVALUATION REPORT")
    print("=" * 70)
    print(f"Test Accuracy:          {metrics['accuracy'] * 100:.2f}%")
    print(f"Weighted Precision:     {metrics['precision']:.4f}")
    print(f"Weighted Recall:        {metrics['recall']:.4f}")
    print(f"Weighted F1-Score:      {metrics['f1_score']:.4f}")
    print(f"Test Sample Size:       {metrics['test_samples']} records")

    print("\n--- Top 10 Most Influential Security Features ---")
    for rank, (feat, score) in enumerate(metrics["top_10_features"].items(), 1):
        bar = "#" * int(score * 80)
        print(f"{rank:2d}. {feat:<34} {score:.4f} {bar}")

    print("\n--- Per-Class Classification Report ---")
    rep = metrics["classification_report"]
    print(f"{'Class':<15} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support'}")
    print("-" * 65)
    for c in ["Secure", "Low Risk", "Medium Risk", "High Risk"]:
        if c in rep:
            r = rep[c]
            print(f"{c:<15} | {r['precision']:<10.4f} | {r['recall']:<10.4f} | {r['f1-score']:<10.4f} | {r['support']}")


def display_audit_result(res: dict):
    ml = res["ml_risk_assessment"]
    print("\n" + "=" * 70)
    print(f" TARGET AUDIT REPORT: {res['target']}")
    print("=" * 70)
    print(f"Risk Tier:          {format_risk_badge(ml['risk_label'])}")
    print(f"ML Confidence:      {ml['confidence'] * 100:.2f}%")
    print(f"Risk Score (0-100): {ml['continuous_risk_score']}/100")
    print(f"Vulnerable Status:  {'YES (Threats Detected)' if ml['is_vulnerable'] else 'NO (Hardened)'}")
    print(f"Issues Detected:    {res['detected_flaws_count']} specific flaws/weaknesses")

    print("\n--- Class Probability Distribution ---")
    for cls_name, prob in ml["class_probabilities"].items():
        bar = "=" * int(prob * 30)
        print(f"  {cls_name:<12}: {prob*100:5.1f}% | {bar}")

    if res["vulnerabilities"]:
        print("\n--- Detected Vulnerabilities & Threat Vectors ---")
        for idx, v in enumerate(res["vulnerabilities"], 1):
            print(f"\n[{idx}] {v['title']} (Severity: {v['severity']})")
            print(f"    CWE / Ref:       {v['cwe']}")
            print(f"    Header Affected: {v['header']}")
            print(f"    Threat Impact:   {v['impact']}")
            print(f"    Recommended Fix: {v['recommendation']}")

    print("\n" + "=" * 70)
    print(" AUTOMATED REMEDIATION: NGINX CONFIGURATION SNIPPET")
    print("=" * 70)
    print(res["remediation_configs"]["nginx"])

    print("\n" + "=" * 70)
    print(" AUTOMATED REMEDIATION: FASTAPI PYTHON MIDDLEWARE")
    print("=" * 70)
    print(res["remediation_configs"]["fastapi"])


def run_demo():
    print_banner()
    run_training()

    print("\n" + "=" * 70)
    print(" EXECUTING AUDIT ON SIMULATED VULNERABLE PRODUCTION ENDPOINT")
    print("=" * 70)

    # Simulated legacy enterprise app header response
    simulated_headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "Strict-Transport-Security": "max-age=3600",  # Short max-age, no subdomains
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline' *",  # Permissive
        "X-Frame-Options": "ALLOW-FROM https://partner.example.com",  # Deprecated
        "Set-Cookie": "session_id=987xyz; Path=/",  # Missing Secure & HttpOnly
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",  # Critical CORS flaw
        "Content-Type": "text/html; charset=UTF-8"
    }

    scanner = AIShieldScanner()
    audit_res = scanner.audit_headers(simulated_headers, target="https://legacy-banking.corp.internal")
    display_audit_result(audit_res)


def run_dataset_audit(count: int = 50):
    print(f"\n[*] Running batch audit on {count} samples from dataset: {DEFAULT_DATASET_PATH} ...")
    scanner = AIShieldScanner()
    batch_res = scanner.audit_dataset_batch(sample_size=count)

    print("\n" + "=" * 70)
    print("                 DATASET BATCH AUDIT RESULTS")
    print("=" * 70)
    print(f"Evaluated Samples:  {batch_res['batch_size']}")
    print(f"Agreement Accuracy: {batch_res['batch_accuracy'] * 100:.2f}%")
    print("\nPredicted Class Distribution:")
    for k, v in batch_res["distribution"].items():
        print(f"  {k:<15}: {v:3d} ({v/batch_res['batch_size']*100:.1f}%)")

    print("\nSample Audited Rows:")
    print(f"{'URL':<32} | {'Predicted':<12} | {'Conf':<6} | {'Risk':<5} | {'Flaws'}")
    print("-" * 70)
    for s in batch_res["samples"]:
        print(f"{s['url']:<32} | {s['predicted_label']:<12} | {s['confidence']*100:5.1f}% | {s['risk_score']:4.1f} | {s['flaws_detected']} flaws")


def main():
    parser = argparse.ArgumentParser(description="AI-SHIELD: Adaptive Security Header Detection & Automated Remediation")
    parser.add_argument("--train", action="store_true", help="Train ML model on dataset and print evaluation")
    parser.add_argument("--scan", type=str, help="Scan a live target URL (e.g. https://example.com)")
    parser.add_argument("--audit-dataset", type=int, nargs="?", const=50, help="Run batch audit on N records from dataset")
    parser.add_argument("--demo", action="store_true", help="Run full end-to-end demonstration")

    args = parser.parse_args()

    if args.demo or len(sys.argv) == 1:
        run_demo()
    elif args.train:
        print_banner()
        run_training()
    elif args.scan:
        print_banner()
        scanner = AIShieldScanner()
        res = scanner.scan_url(args.scan)
        display_audit_result(res)
    elif args.audit_dataset is not None:
        print_banner()
        run_dataset_audit(args.audit_dataset)


if __name__ == "__main__":
    main()
