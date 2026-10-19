"""Model training pipeline for smart contract honeypot classification (Random Forest & Logistic Regression)."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

# Ensure project root is on sys.path for direct script execution
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate

from ml.preprocess import get_preprocessed_data, PreprocessedData, DEFAULT_DATASET_PATH
MODELS_DIR = BASE_DIR / "models"
DEFAULT_RF_PATH = MODELS_DIR / "random_forest_model.joblib"
DEFAULT_LR_PATH = MODELS_DIR / "logistic_regression_model.joblib"
DEFAULT_METADATA_PATH = MODELS_DIR / "model_metadata.json"


def train_random_forest(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    n_estimators: int = 100,
    random_state: int = 42,
    class_weight: str = "balanced",
) -> RandomForestClassifier:
    """
    Train a Random Forest classifier on tabular contract features.
    Tree-based models operate directly on unscaled features preserving interpretability.
    """
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        class_weight=class_weight,
    )
    rf.fit(X_train, y_train)
    return rf


def train_logistic_regression(
    X_train_scaled: np.ndarray,
    y_train: pd.Series,
    max_iter: int = 1000,
    random_state: int = 42,
    class_weight: str = "balanced",
    C: float = 1.0,
) -> LogisticRegression:
    """
    Train an L2-regularized Logistic Regression classifier on standardized feature vectors.
    """
    lr = LogisticRegression(
        max_iter=max_iter,
        random_state=random_state,
        class_weight=class_weight,
        C=C,
    )
    lr.fit(X_train_scaled, y_train)
    return lr


def evaluate_cross_validation(
    model: Any,
    X: Any,
    y: pd.Series,
    n_splits: int = 5,
    random_state: int = 42,
) -> Dict[str, float]:
    """
    Perform Stratified K-Fold cross validation and return mean scoring metrics.
    """
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    cv_results = cross_validate(model, X, y, cv=cv, scoring=scoring)

    return {
        "accuracy_mean": float(np.mean(cv_results["test_accuracy"])),
        "precision_mean": float(np.mean(cv_results["test_precision"])),
        "recall_mean": float(np.mean(cv_results["test_recall"])),
        "f1_mean": float(np.mean(cv_results["test_f1"])),
        "roc_auc_mean": float(np.mean(cv_results["test_roc_auc"])),
    }


def extract_feature_importances(
    rf_model: RandomForestClassifier,
    feature_names: List[str],
) -> Dict[str, float]:
    """Extract and sort feature importances from trained Random Forest."""
    importances = rf_model.feature_importances_
    sorted_pairs = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    return {name: float(imp) for name, imp in sorted_pairs}


def extract_logistic_coefficients(
    lr_model: LogisticRegression,
    feature_names: List[str],
) -> Dict[str, float]:
    """Extract and sort absolute coefficients from trained Logistic Regression."""
    coeffs = lr_model.coef_[0]
    sorted_pairs = sorted(zip(feature_names, coeffs), key=lambda x: abs(x[1]), reverse=True)
    return {name: float(coeff) for name, coeff in sorted_pairs}


def train_and_save_all_models(
    csv_path: Optional[Path] = None,
    rf_path: Optional[Path] = None,
    lr_path: Optional[Path] = None,
    metadata_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    End-to-end training orchestrator:
    1. Loads and preprocesses dataset
    2. Trains Random Forest and Logistic Regression
    3. Runs 5-fold cross-validation
    4. Saves serialized models (.joblib) and training metadata (.json)
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    rf_target_path = Path(rf_path or DEFAULT_RF_PATH)
    lr_target_path = Path(lr_path or DEFAULT_LR_PATH)
    meta_target_path = Path(metadata_path or DEFAULT_METADATA_PATH)

    # 1. Preprocessing
    data: PreprocessedData = get_preprocessed_data(csv_path=csv_path, save_scaler=True)

    # 2. Train Random Forest (unscaled features)
    rf_model = train_random_forest(data.X_train, data.y_train)
    rf_cv = evaluate_cross_validation(rf_model, data.X_train, data.y_train)
    rf_importances = extract_feature_importances(rf_model, data.feature_names)

    # 3. Train Logistic Regression (scaled features)
    lr_model = train_logistic_regression(data.X_train_scaled, data.y_train)
    lr_cv = evaluate_cross_validation(lr_model, data.X_train_scaled, data.y_train)
    lr_coeffs = extract_logistic_coefficients(lr_model, data.feature_names)

    # 4. Save joblib models
    joblib.dump(rf_model, rf_target_path)
    joblib.dump(lr_model, lr_target_path)
    # Also save honeypot_rf_model.joblib alias for requirement compatibility
    honeypot_rf_path = MODELS_DIR / "honeypot_rf_model.joblib"
    joblib.dump(rf_model, honeypot_rf_path)

    # 5. Determine recommended best model
    best_model_name = "RandomForestClassifier" if rf_cv["f1_mean"] >= lr_cv["f1_mean"] else "LogisticRegression"

    # 6. Build and save metadata
    metadata = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "path": str(csv_path or DEFAULT_DATASET_PATH),
            "total_samples": data.train_size + data.test_size,
            "train_samples": data.train_size,
            "test_samples": data.test_size,
            "features_count": len(data.feature_names),
            "feature_names": data.feature_names,
        },
        "models": {
            "random_forest": {
                "algorithm": "RandomForestClassifier",
                "artifact_path": str(rf_target_path),
                "n_estimators": rf_model.n_estimators,
                "cross_validation_5fold": rf_cv,
                "top_5_features": list(rf_importances.items())[:5],
            },
            "logistic_regression": {
                "algorithm": "LogisticRegression",
                "artifact_path": str(lr_target_path),
                "max_iter": lr_model.max_iter,
                "cross_validation_5fold": lr_cv,
                "top_5_coefficients": list(lr_coeffs.items())[:5],
            },
        },
        "recommended_model": best_model_name,
        "scaler_path": str(MODELS_DIR / "scaler.joblib"),
    }

    with open(meta_target_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


if __name__ == "__main__":
    print("=" * 60)
    print(" Smart Contract ML Model Training Pipeline ")
    print("=" * 60)
    results = train_and_save_all_models()
    print(f"Random Forest Saved: {results['models']['random_forest']['artifact_path']}")
    print(f"  5-Fold CV Accuracy: {results['models']['random_forest']['cross_validation_5fold']['accuracy_mean']:.4f}")
    print(f"  5-Fold CV F1 Score: {results['models']['random_forest']['cross_validation_5fold']['f1_mean']:.4f}")
    print(f"Logistic Regression Saved: {results['models']['logistic_regression']['artifact_path']}")
    print(f"  5-Fold CV Accuracy: {results['models']['logistic_regression']['cross_validation_5fold']['accuracy_mean']:.4f}")
    print(f"  5-Fold CV F1 Score: {results['models']['logistic_regression']['cross_validation_5fold']['f1_mean']:.4f}")
    print(f"Recommended Model: {results['recommended_model']}")
    print(f"Metadata Saved: {DEFAULT_METADATA_PATH}")
    print("Training completed successfully.")
