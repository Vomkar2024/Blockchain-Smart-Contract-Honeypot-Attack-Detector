"""Machine Learning Honeypot Detector with resilient heuristic fallback when model artifacts are absent."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
import joblib
import pandas as pd

from src.config import settings, MODELS_DIR
from src.feature_extractor import FeatureExtractor, FEATURE_NAMES, get_default_features


@dataclass
class MLPredictionResult:
    """Standardized prediction outcome from machine learning honeypot classification."""
    is_honeypot: bool
    honeypot_probability: float
    confidence_score: float
    risk_label: str
    model_used: str
    model_available: bool
    feature_contributions: Dict[str, float] = field(default_factory=dict)
    feature_vector: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert ML result to serializable dictionary."""
        return {
            "is_honeypot": self.is_honeypot,
            "honeypot_probability": round(self.honeypot_probability, 4),
            "confidence_score": round(self.confidence_score, 4),
            "risk_label": self.risk_label,
            "model_used": self.model_used,
            "model_available": self.model_available,
            "feature_contributions": {
                k: round(v, 4) for k, v in self.feature_contributions.items()
            },
            "feature_vector": self.feature_vector,
            "timestamp": self.timestamp,
        }


class MLDetector:
    """
    Production-ready machine learning inference detector.
    Features:
    - Automatically loads Random Forest or Logistic Regression joblib artifacts.
    - Provides seamless, deterministic heuristic fallback if model artifacts are absent.
    - Extracts feature importance and individual sample contributions.
    """

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        scaler_path: Optional[Union[str, Path]] = None,
        prefer_model: str = "random_forest",
        feature_extractor: Optional[FeatureExtractor] = None,
    ):
        self.extractor = feature_extractor or FeatureExtractor()
        self.prefer_model = prefer_model.lower().strip()

        # Paths
        self.rf_path = Path(model_path or settings.random_forest_model_path)
        self.lr_path = Path(settings.logistic_regression_model_path)
        self.scaler_path = Path(scaler_path or settings.scaler_path)

        # Runtime model objects
        self.model: Any = None
        self.scaler: Any = None
        self.model_name: str = "None"
        self.model_available: bool = False

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Attempt to load trained model and scaler artifacts from disk."""
        # Try preferred model first
        if self.prefer_model == "logistic_regression" and self.lr_path.exists():
            try:
                self.model = joblib.load(self.lr_path)
                self.model_name = "LogisticRegression"
                self.model_available = True
            except Exception:
                self.model = None

        if not self.model:
            rf_candidates = [self.rf_path, MODELS_DIR / "honeypot_rf_model.joblib"]
            for candidate in rf_candidates:
                if candidate.exists():
                    try:
                        self.model = joblib.load(candidate)
                        self.model_name = "RandomForestClassifier"
                        self.model_available = True
                        break
                    except Exception:
                        self.model = None

        if not self.model and self.lr_path.exists():
            try:
                self.model = joblib.load(self.lr_path)
                self.model_name = "LogisticRegression"
                self.model_available = True
            except Exception:
                self.model = None

        # Load scaler if available
        if self.scaler_path.exists():
            try:
                self.scaler = joblib.load(self.scaler_path)
            except Exception:
                self.scaler = None

    def predict_features(
        self,
        features: Union[Dict[str, Any], List[float], pd.DataFrame],
    ) -> MLPredictionResult:
        """
        Execute inference on structured feature representation.
        If model artifacts are absent, executes heuristic fallback.
        """
        # Standardize features into dict and DataFrame row
        if isinstance(features, dict):
            feat_dict = {name: features.get(name, 0) for name in FEATURE_NAMES}
            df_row = pd.DataFrame([feat_dict])
        elif isinstance(features, list):
            feat_dict = {name: val for name, val in zip(FEATURE_NAMES, features)}
            df_row = pd.DataFrame([feat_dict])
        elif isinstance(features, pd.DataFrame):
            df_row = features[FEATURE_NAMES].iloc[[0]].copy()
            feat_dict = df_row.iloc[0].to_dict()
        else:
            feat_dict = get_default_features()
            df_row = pd.DataFrame([feat_dict])

        # If no model is available, route to heuristic fallback
        if not self.model_available or self.model is None:
            return self._heuristic_fallback_predict(feat_dict)

        try:
            # Predict using loaded model
            if self.model_name == "LogisticRegression" and self.scaler is not None:
                X_scaled = self.scaler.transform(df_row)
                prob = float(self.model.predict_proba(X_scaled)[0, 1])
                pred = bool(self.model.predict(X_scaled)[0])
                contributions = self._compute_logistic_contributions(df_row.iloc[0])
            else:
                prob = float(self.model.predict_proba(df_row)[0, 1])
                pred = bool(self.model.predict(df_row)[0])
                contributions = self._compute_tree_contributions(df_row.iloc[0])

            conf = float(abs(prob - 0.5) * 2.0)
            risk_label = self._determine_risk_label(prob)

            return MLPredictionResult(
                is_honeypot=pred,
                honeypot_probability=prob,
                confidence_score=conf,
                risk_label=risk_label,
                model_used=self.model_name,
                model_available=True,
                feature_contributions=contributions,
                feature_vector=feat_dict,
            )

        except Exception:
            # Fall back defensively if runtime model inference encounters unexpected issue
            return self._heuristic_fallback_predict(feat_dict)

    def predict_source(self, solidity_source: Optional[str]) -> MLPredictionResult:
        """Extract features from Solidity source code and run prediction."""
        feat_dict = self.extractor.extract_features_from_source(solidity_source)
        return self.predict_features(feat_dict)

    def predict_contract(self, contract: Any) -> MLPredictionResult:
        """Extract features from a LoadedContract object and run prediction."""
        feat_dict = self.extractor.extract_from_contract(contract)
        return self.predict_features(feat_dict)

    def predict_batch(self, items: List[Any]) -> List[MLPredictionResult]:
        """Run batch inference on multiple source strings or LoadedContract objects."""
        return [
            self.predict_source(item) if isinstance(item, str) else self.predict_contract(item)
            for item in items
        ]

    def _determine_risk_label(self, probability: float) -> str:
        """Translate honeypot probability into descriptive label."""
        if probability >= 0.75:
            return "HONEYPOT"
        elif probability >= 0.35:
            return "SUSPICIOUS"
        return "BENIGN"

    def _compute_tree_contributions(self, row: pd.Series) -> Dict[str, float]:
        """Compute sample-level feature contributions from Random Forest importances."""
        if not hasattr(self.model, "feature_importances_"):
            return {}
        importances = self.model.feature_importances_
        contributions = {}
        for name, imp in zip(FEATURE_NAMES, importances):
            val = float(row.get(name, 0))
            if val > 0:
                contributions[name] = float(imp * val)
        # Return top 5 sorted contributions
        sorted_top = sorted(contributions.items(), key=lambda x: x[1], reverse=True)[:5]
        return dict(sorted_top)

    def _compute_logistic_contributions(self, row: pd.Series) -> Dict[str, float]:
        """Compute sample-level feature contributions from Logistic Regression coefficients."""
        if not hasattr(self.model, "coef_"):
            return {}
        coeffs = self.model.coef_[0]
        contributions = {}
        for name, coeff in zip(FEATURE_NAMES, coeffs):
            val = float(row.get(name, 0))
            if val != 0:
                contributions[name] = float(coeff * val)
        sorted_top = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        return dict(sorted_top)

    def _heuristic_fallback_predict(self, feat_dict: Dict[str, Any]) -> MLPredictionResult:
        """
        Deterministic, rule-based heuristic inference fallback executed when
        joblib model artifacts are absent, deleted, or unreadable.
        """
        score = 0.0
        contributions: Dict[str, float] = {}

        # Major threat flags
        critical_threats = [
            ("has_blacklist_mapping", 0.35),
            ("has_sell_restriction_logic", 0.35),
            ("has_excessive_fee", 0.30),
            ("has_unbounded_fee_setter", 0.25),
            ("has_cooldown_delay", 0.20),
            ("has_pausable_transfers", 0.20),
            ("has_max_tx_wallet_limit", 0.20),
            ("has_hidden_mint", 0.25),
            ("has_inline_assembly", 0.15),
            ("has_external_transfer_call", 0.20),
        ]

        for flag, weight in critical_threats:
            if feat_dict.get(flag, 0) == 1:
                score += weight
                contributions[flag] = weight

        # Findings multiplier
        findings_count = feat_dict.get("num_total_findings", 0)
        if findings_count > 0:
            finding_impact = min(0.40, findings_count * 0.10)
            score += finding_impact
            contributions["num_total_findings"] = finding_impact

        # Positive indicator deductions
        pos_count = feat_dict.get("num_positive_indicators", 0)
        if pos_count > 0:
            deduction = -min(0.50, pos_count * 0.15)
            score += deduction
            contributions["num_positive_indicators"] = deduction

        if feat_dict.get("has_openzeppelin_imports", 0) == 1:
            score -= 0.15
            contributions["has_openzeppelin_imports"] = -0.15

        if feat_dict.get("has_renounce_ownership", 0) == 1:
            score -= 0.15
            contributions["has_renounce_ownership"] = -0.15

        # Normalize probability to [0.0, 1.0]
        prob = max(0.0, min(1.0, score))
        is_honeypot = prob >= 0.50
        conf = float(abs(prob - 0.5) * 2.0)
        risk_label = self._determine_risk_label(prob)

        sorted_top = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)[:5]

        return MLPredictionResult(
            is_honeypot=is_honeypot,
            honeypot_probability=prob,
            confidence_score=conf,
            risk_label=risk_label,
            model_used="HeuristicFallback",
            model_available=False,
            feature_contributions=dict(sorted_top),
            feature_vector=feat_dict,
        )
