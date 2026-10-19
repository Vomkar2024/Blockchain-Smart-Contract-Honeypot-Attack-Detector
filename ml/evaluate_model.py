"""Evaluation module computing classification metrics, confusion matrices, and ROC curves."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

# Ensure project root is on sys.path for direct script execution
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive headless backend
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve,
    average_precision_score,
    precision_recall_curve,
)

from ml.preprocess import get_preprocessed_data, PreprocessedData
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

DEFAULT_RF_PATH = MODELS_DIR / "random_forest_model.joblib"
DEFAULT_LR_PATH = MODELS_DIR / "logistic_regression_model.joblib"
DEFAULT_EVAL_JSON = REPORTS_DIR / "ml_evaluation_report.json"
DEFAULT_EVAL_TXT = REPORTS_DIR / "ml_evaluation_summary.txt"


def evaluate_single_model(
    model: Any,
    X_test: Any,
    y_test: pd.Series,
    model_name: str,
) -> Dict[str, Any]:
    """
    Compute comprehensive classification metrics for a single model against test data.
    """
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    acc = float(accuracy_score(y_test, y_pred))
    bal_acc = float(balanced_accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob))
    avg_prec = float(average_precision_score(y_test, y_prob))

    # ROC curve points
    fpr, tpr, roc_thresh = roc_curve(y_test, y_prob)
    # PR curve points
    pr_prec, pr_rec, _ = precision_recall_curve(y_test, y_prob)

    report_dict = classification_report(
        y_test, y_pred, target_names=["Benign", "Honeypot"], output_dict=True
    )

    return {
        "model_name": model_name,
        "metrics": {
            "accuracy": acc,
            "balanced_accuracy": bal_acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "average_precision": avg_prec,
        },
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "total_samples": len(y_test),
        },
        "classification_report": report_dict,
        "roc_curve": {
            "fpr": [float(x) for x in fpr],
            "tpr": [float(x) for x in tpr],
        },
    }


def generate_evaluation_plots(
    eval_results: Dict[str, Any],
    output_dir: Optional[Path] = None,
) -> Dict[str, str]:
    """
    Plot and save confusion matrices and ROC curves for visual audit reports.
    """
    out_dir = Path(output_dir or REPORTS_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    plot_paths = {}

    rf_eval = eval_results.get("random_forest", {})
    lr_eval = eval_results.get("logistic_regression", {})

    # 1. Confusion Matrix Comparison Plot
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))

    for ax, (m_key, m_eval, title) in zip(
        axes,
        [
            ("rf", rf_eval, "Random Forest Confusion Matrix"),
            ("lr", lr_eval, "Logistic Regression Confusion Matrix"),
        ],
    ):
        cm_data = m_eval.get("confusion_matrix", {})
        tn = cm_data.get("true_negatives", 0)
        fp = cm_data.get("false_positives", 0)
        fn = cm_data.get("false_negatives", 0)
        tp = cm_data.get("true_positives", 0)
        matrix = np.array([[tn, fp], [fn, tp]])

        cax = ax.matshow(matrix, cmap=plt.cm.Blues, alpha=0.8)
        for i in range(2):
            for j in range(2):
                ax.text(
                    j,
                    i,
                    str(matrix[i, j]),
                    va="center",
                    ha="center",
                    fontsize=14,
                    fontweight="bold",
                    color="darkblue" if matrix[i, j] > 0 else "gray",
                )
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Benign", "Honeypot"])
        ax.set_yticklabels(["Benign", "Honeypot"])
        ax.set_xlabel("Predicted Label", fontweight="bold")
        ax.set_ylabel("True Label", fontweight="bold")
        ax.set_title(title, pad=15, fontweight="bold")

    plt.tight_layout()
    cm_path = out_dir / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=150)
    plt.close(fig)
    plot_paths["confusion_matrix"] = str(cm_path)

    # 2. ROC Curves Plot
    fig, ax = plt.subplots(figsize=(6.5, 5))
    ax.plot([0, 1], [0, 1], "k--", label="Random Chance (AUC = 0.50)")

    if "roc_curve" in rf_eval:
        rf_fpr = rf_eval["roc_curve"]["fpr"]
        rf_tpr = rf_eval["roc_curve"]["tpr"]
        rf_auc = rf_eval["metrics"]["roc_auc"]
        ax.plot(rf_fpr, rf_tpr, label=f"Random Forest (AUC = {rf_auc:.3f})", color="royalblue", lw=2)

    if "roc_curve" in lr_eval:
        lr_fpr = lr_eval["roc_curve"]["fpr"]
        lr_tpr = lr_eval["roc_curve"]["tpr"]
        lr_auc = lr_eval["metrics"]["roc_auc"]
        ax.plot(lr_fpr, lr_tpr, label=f"Logistic Regression (AUC = {lr_auc:.3f})", color="seagreen", lw=2, linestyle=":")

    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate (1 - Specificity)", fontweight="bold")
    ax.set_ylabel("True Positive Rate (Recall / Sensitivity)", fontweight="bold")
    ax.set_title("Honeypot Detector ROC Curve Comparison", fontweight="bold")
    ax.legend(loc="lower right")
    ax.grid(True, linestyle="--", alpha=0.5)

    plt.tight_layout()
    roc_path = out_dir / "roc_curve.png"
    plt.savefig(roc_path, dpi=150)
    plt.close(fig)
    plot_paths["roc_curve"] = str(roc_path)

    return plot_paths


def evaluate_models_and_save_reports(
    rf_path: Optional[Path] = None,
    lr_path: Optional[Path] = None,
    output_json: Optional[Path] = None,
    output_txt: Optional[Path] = None,
    generate_plots: bool = True,
) -> Dict[str, Any]:
    """
    Main evaluation pipeline:
    1. Loads trained models and test split
    2. Runs test set evaluation
    3. Writes structured evaluation reports (JSON, TXT) and plots (PNG)
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    rf_model_file = Path(rf_path or DEFAULT_RF_PATH)
    lr_model_file = Path(lr_path or DEFAULT_LR_PATH)
    out_json = Path(output_json or DEFAULT_EVAL_JSON)
    out_txt = Path(output_txt or DEFAULT_EVAL_TXT)

    if not rf_model_file.exists() or not lr_model_file.exists():
        raise FileNotFoundError(
            f"Model artifacts missing. Please run 'python -m ml.train_model' first.\n"
            f"Looked for: {rf_model_file} and {lr_model_file}"
        )

    rf_model = joblib.load(rf_model_file)
    lr_model = joblib.load(lr_model_file)

    data: PreprocessedData = get_preprocessed_data(save_scaler=False)

    rf_eval = evaluate_single_model(rf_model, data.X_test, data.y_test, "RandomForestClassifier")
    lr_eval = evaluate_single_model(lr_model, data.X_test_scaled, data.y_test, "LogisticRegression")

    all_results = {
        "evaluation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "test_dataset_size": len(data.y_test),
        "class_distribution": {
            "benign_count": int((data.y_test == 0).sum()),
            "honeypot_count": int((data.y_test == 1).sum()),
        },
        "random_forest": rf_eval,
        "logistic_regression": lr_eval,
    }

    if generate_plots:
        plot_paths = generate_evaluation_plots(all_results, REPORTS_DIR)
        all_results["saved_plots"] = plot_paths

    # Save JSON report
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    # Save text report summary
    txt_summary = f"""======================================================================
 SMART CONTRACT HONEYPOT DETECTOR - ML EVALUATION REPORT
======================================================================
Evaluated at: {all_results['evaluation_timestamp_utc']}
Test Samples: {all_results['test_dataset_size']} (Benign: {all_results['class_distribution']['benign_count']}, Honeypot: {all_results['class_distribution']['honeypot_count']})

--- RANDOM FOREST CLASSIFIER ---
Accuracy:          {rf_eval['metrics']['accuracy']:.4f}
Precision:         {rf_eval['metrics']['precision']:.4f}
Recall:            {rf_eval['metrics']['recall']:.4f}
F1-Score:          {rf_eval['metrics']['f1_score']:.4f}
ROC-AUC:           {rf_eval['metrics']['roc_auc']:.4f}
Average Precision: {rf_eval['metrics']['average_precision']:.4f}
Confusion Matrix:  TN={rf_eval['confusion_matrix']['true_negatives']}, FP={rf_eval['confusion_matrix']['false_positives']}, FN={rf_eval['confusion_matrix']['false_negatives']}, TP={rf_eval['confusion_matrix']['true_positives']}

--- LOGISTIC REGRESSION ---
Accuracy:          {lr_eval['metrics']['accuracy']:.4f}
Precision:         {lr_eval['metrics']['precision']:.4f}
Recall:            {lr_eval['metrics']['recall']:.4f}
F1-Score:          {lr_eval['metrics']['f1_score']:.4f}
ROC-AUC:           {lr_eval['metrics']['roc_auc']:.4f}
Average Precision: {lr_eval['metrics']['average_precision']:.4f}
Confusion Matrix:  TN={lr_eval['confusion_matrix']['true_negatives']}, FP={lr_eval['confusion_matrix']['false_positives']}, FN={lr_eval['confusion_matrix']['false_negatives']}, TP={lr_eval['confusion_matrix']['true_positives']}
======================================================================
"""
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(txt_summary)

    return all_results


if __name__ == "__main__":
    print("=" * 60)
    print(" Smart Contract ML Model Evaluation Pipeline ")
    print("=" * 60)
    report = evaluate_models_and_save_reports()
    rf = report["random_forest"]["metrics"]
    lr = report["logistic_regression"]["metrics"]
    print(f"Random Forest  -> Accuracy: {rf['accuracy']:.4f}, Precision: {rf['precision']:.4f}, Recall: {rf['recall']:.4f}, F1: {rf['f1_score']:.4f}, AUC: {rf['roc_auc']:.4f}")
    print(f"Logistic Regr  -> Accuracy: {lr['accuracy']:.4f}, Precision: {lr['precision']:.4f}, Recall: {lr['recall']:.4f}, F1: {lr['f1_score']:.4f}, AUC: {lr['roc_auc']:.4f}")
    print(f"Saved JSON report: {DEFAULT_EVAL_JSON}")
    print(f"Saved TXT summary: {DEFAULT_EVAL_TXT}")
    if "saved_plots" in report:
        print(f"Plots generated: {list(report['saved_plots'].values())}")
    print("Evaluation completed successfully.")
