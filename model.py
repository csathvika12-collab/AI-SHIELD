"""
Adaptive Risk Intelligence Engine.
Trains, evaluates, and applies Machine Learning models on the HTTP header vulnerability dataset.
"""

import os
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from config import CLASS_NAMES, DEFAULT_DATASET_PATH, FEATURE_COLS, SAVED_MODELS_DIR


class AdaptiveRiskIntelligence:
    """Adaptive risk scoring and tier prediction engine using ensemble learning."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.path.join(SAVED_MODELS_DIR, "ai_shield_rf.joblib")
        self.model: Optional[RandomForestClassifier] = None
        self.feature_importances: Dict[str, float] = {}
        self.is_trained = False

        if os.path.exists(self.model_path):
            self.load_model()

    def train(
        self, dataset_path: str = DEFAULT_DATASET_PATH, test_size: float = 0.2, random_state: int = 42
    ) -> Dict[str, Any]:
        """
        Trains the adaptive Random Forest classifier on the 5,000-record dataset.
        Returns comprehensive evaluation metrics and feature importances.
        """
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset not found at '{dataset_path}'.")

        print(f"[*] Loading dataset from {dataset_path} ...")
        df = pd.read_csv(dataset_path)
        print(f"[*] Loaded {len(df):,} samples with {len(df.columns)} raw columns.")

        X = df[FEATURE_COLS].fillna(0).values
        y = df["vuln_class"].values

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        print(f"[*] Training ensemble classifier on {len(X_train):,} training records...")
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=18,
            min_samples_split=3,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)

        # Evaluation on holdout test set
        preds = self.model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, average="weighted", zero_division=0)
        rec = recall_score(y_test, preds, average="weighted", zero_division=0)
        f1 = f1_score(y_test, preds, average="weighted", zero_division=0)
        report_dict = classification_report(
            y_test, preds, target_names=[CLASS_NAMES[i] for i in range(4)], output_dict=True
        )

        # Calculate feature importances
        raw_importances = self.model.feature_importances_
        sorted_indices = np.argsort(raw_importances)[::-1]
        self.feature_importances = {
            FEATURE_COLS[i]: float(raw_importances[i]) for i in sorted_indices
        }

        # Persist model artifact
        joblib.dump(self.model, self.model_path)
        self.is_trained = True

        metrics = {
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1_score": float(f1),
            "classification_report": report_dict,
            "top_10_features": dict(list(self.feature_importances.items())[:10]),
            "test_samples": len(X_test)
        }

        print(f"[+] Model successfully trained. Test Accuracy: {acc * 100:.2f}% | F1: {f1:.4f}")
        print(f"[+] Model artifact saved to: {self.model_path}")
        return metrics

    def load_model(self) -> None:
        """Loads trained model from disk."""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            self.is_trained = True
            raw_importances = self.model.feature_importances_
            sorted_indices = np.argsort(raw_importances)[::-1]
            self.feature_importances = {
                FEATURE_COLS[i]: float(raw_importances[i]) for i in sorted_indices
            }

    def predict(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes extracted 54-feature dictionary and performs adaptive risk inference.
        """
        if not self.is_trained or self.model is None:
            self.train()

        feature_vector = np.array([[float(feature_dict.get(c, 0)) for c in FEATURE_COLS]])
        pred_class = int(self.model.predict(feature_vector)[0])
        probabilities = self.model.predict_proba(feature_vector)[0]
        confidence = float(probabilities[pred_class])

        # Calculate continuous normalized risk score (0 to 100)
        # Weight class probabilities: 0 -> 0, 1 -> 33.3, 2 -> 66.6, 3 -> 100
        continuous_risk_score = (
            probabilities[0] * 5.0 +
            probabilities[1] * 35.0 +
            probabilities[2] * 70.0 +
            probabilities[3] * 95.0
        )
        continuous_risk_score = round(float(continuous_risk_score), 2)

        return {
            "predicted_class": pred_class,
            "risk_label": CLASS_NAMES[pred_class],
            "confidence": confidence,
            "is_vulnerable": bool(pred_class > 0),
            "continuous_risk_score": continuous_risk_score,
            "class_probabilities": {
                CLASS_NAMES[i]: float(probabilities[i]) for i in range(len(probabilities))
            }
        }
