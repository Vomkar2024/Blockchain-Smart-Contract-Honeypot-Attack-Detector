"""Comprehensive unit and integration test suite for Phase 4:
Machine Learning Module & Sample Dataset.

Covers:
- FeatureExtractor (Solidity code to 19-dim vectors, batch DataFrames, contract objects, error safety)
- Dataset Integrity (sample_contract_features.csv schema, 120 balanced records, value ranges)
- Preprocessing Pipeline (cleaning, validation, stratified splitting, StandardScaler persistence)
- Model Training (Random Forest & Logistic Regression, 5-fold CV, joblib serialization, metadata)
- Model Evaluation (classification report, confusion matrix, ROC-AUC, report exports)
- MLDetector (production inference with trained models, and resilient heuristic fallback when artifacts absent)
- ReportGenerator Integration (CompleteAuditReport with ml_prediction)
"""

import json
import tempfile
import unittest
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from src.feature_extractor import FeatureExtractor, FEATURE_NAMES, get_default_features
from src.contract_loader import ContractLoader, LoadedContract
from src.ml_detector import MLDetector, MLPredictionResult
from src.report_generator import CompleteAuditReport, ReportGenerator
from ml.preprocess import (
    load_and_validate_dataset,
    split_features_and_target,
    prepare_train_test_split,
    fit_and_save_scaler,
    load_scaler,
    scale_features,
    get_preprocessed_data,
    PreprocessedData,
    DEFAULT_DATASET_PATH,
)
from ml.train_model import (
    train_random_forest,
    train_logistic_regression,
    evaluate_cross_validation,
    extract_feature_importances,
    extract_logistic_coefficients,
    train_and_save_all_models,
)
from ml.evaluate_model import (
    evaluate_single_model,
    evaluate_models_and_save_reports,
)


class TestFeatureExtractor(unittest.TestCase):
    """Test feature extractor translating Solidity source code into numerical vectors."""

    def setUp(self):
        self.extractor = FeatureExtractor()
        self.samples_dir = Path(__file__).resolve().parent.parent / "samples"
        self.benign_sol = (self.samples_dir / "BenignToken.sol").read_text(encoding="utf-8")
        self.honeypot_sol = (self.samples_dir / "HoneypotToken.sol").read_text(encoding="utf-8")

    def test_feature_names_length_and_order(self):
        self.assertEqual(len(FEATURE_NAMES), 19)
        self.assertIn("lines_of_code", FEATURE_NAMES)
        self.assertIn("has_blacklist_mapping", FEATURE_NAMES)
        self.assertIn("has_excessive_fee", FEATURE_NAMES)
        self.assertIn("num_total_findings", FEATURE_NAMES)

    def test_extract_features_benign_token(self):
        feats = self.extractor.extract_features_from_source(self.benign_sol)
        self.assertIsInstance(feats, dict)
        self.assertEqual(len(feats), 19)
        self.assertGreater(feats["lines_of_code"], 0)
        self.assertEqual(feats["has_transfer_function"], 1)
        self.assertEqual(feats["has_blacklist_mapping"], 0)
        self.assertEqual(feats["has_excessive_fee"], 0)
        self.assertGreaterEqual(feats["num_positive_indicators"], 1)
        self.assertEqual(feats["num_total_findings"], 0)

    def test_extract_features_honeypot_token(self):
        feats = self.extractor.extract_features_from_source(self.honeypot_sol)
        self.assertIsInstance(feats, dict)
        self.assertEqual(feats["has_blacklist_mapping"], 1)
        self.assertEqual(feats["has_excessive_fee"], 1)
        self.assertEqual(feats["has_sell_restriction_logic"], 1)
        self.assertEqual(feats["has_unbounded_fee_setter"], 1)
        self.assertGreaterEqual(feats["num_total_findings"], 5)

    def test_extract_feature_vector_format(self):
        vector = self.extractor.extract_feature_vector(self.benign_sol)
        self.assertIsInstance(vector, list)
        self.assertEqual(len(vector), 19)
        for val in vector:
            self.assertIsInstance(val, float)

    def test_extract_empty_or_malformed_code(self):
        empty_feats = self.extractor.extract_features_from_source("")
        self.assertEqual(empty_feats, get_default_features())

        none_feats = self.extractor.extract_features_from_source(None)
        self.assertEqual(none_feats, get_default_features())

        malformed_feats = self.extractor.extract_features_from_source("invalid // $$ syntax }")
        self.assertIsInstance(malformed_feats, dict)
        self.assertEqual(len(malformed_feats), 19)

    def test_extract_from_contract_object(self):
        contract = LoadedContract(
            input_type="source_code",
            source_code=self.benign_sol,
            name="BenignToken",
            address="0x1111111111111111111111111111111111111111",
            network="ethereum",
            is_success=True,
        )
        feats = self.extractor.extract_from_contract(contract)
        self.assertEqual(feats["has_transfer_function"], 1)
        self.assertEqual(feats["has_blacklist_mapping"], 0)

    def test_extract_dataframe_batch(self):
        sources = [self.benign_sol, self.honeypot_sol, ""]
        df = self.extractor.extract_dataframe(sources, include_metadata=False)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 3)
        self.assertEqual(list(df.columns), FEATURE_NAMES)


class TestDatasetIntegrity(unittest.TestCase):
    """Test schema and balance of sample_contract_features.csv."""

    def setUp(self):
        self.csv_path = DEFAULT_DATASET_PATH

    def test_dataset_exists_and_record_count(self):
        self.assertTrue(self.csv_path.exists(), f"Dataset CSV should exist at {self.csv_path}")
        df = pd.read_csv(self.csv_path)
        self.assertGreaterEqual(len(df), 100, "Dataset must have at least 100 annotated profiles")
        self.assertEqual(len(df), 120, "Dataset should have 120 total records")

    def test_dataset_balanced_classes(self):
        df = pd.read_csv(self.csv_path)
        benign_count = (df["is_honeypot"] == 0).sum()
        honeypot_count = (df["is_honeypot"] == 1).sum()
        self.assertEqual(benign_count, 60, "Should contain exactly 60 benign contracts")
        self.assertEqual(honeypot_count, 60, "Should contain exactly 60 honeypot contracts")

    def test_schema_columns(self):
        df = pd.read_csv(self.csv_path)
        expected_cols = [
            "contract_id",
            "contract_name",
            "source_origin",
            *FEATURE_NAMES,
            "is_honeypot",
        ]
        self.assertEqual(list(df.columns), expected_cols)
        self.assertFalse(df[FEATURE_NAMES].isnull().any().any(), "No feature column should contain nulls")

    def test_feature_value_ranges(self):
        df = pd.read_csv(self.csv_path)
        binary_cols = [
            "has_transfer_function", "has_owner_control", "has_blacklist_mapping",
            "has_sell_restriction_logic", "has_excessive_fee", "has_unbounded_fee_setter",
            "has_cooldown_delay", "has_pausable_transfers", "has_max_tx_wallet_limit",
            "has_hidden_mint", "has_inline_assembly", "has_external_transfer_call",
            "has_openzeppelin_imports", "has_renounce_ownership", "is_honeypot"
        ]
        for col in binary_cols:
            unique_vals = set(df[col].unique())
            self.assertTrue(unique_vals.issubset({0, 1}), f"Column {col} should only contain 0 or 1")

        self.assertTrue((df["lines_of_code"] > 0).all())
        self.assertTrue((df["num_functions"] > 0).all())


class TestPreprocessingPipeline(unittest.TestCase):
    """Test data cleaning, validation, scaling, and train-test splitting."""

    def test_load_and_validate_dataset(self):
        df = load_and_validate_dataset(DEFAULT_DATASET_PATH)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 120)

    def test_load_missing_dataset_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            load_and_validate_dataset("nonexistent_path_to_data.csv")

    def test_split_features_and_target(self):
        df = load_and_validate_dataset(DEFAULT_DATASET_PATH)
        X, y, meta = split_features_and_target(df)
        self.assertEqual(list(X.columns), FEATURE_NAMES)
        self.assertEqual(len(y), 120)
        self.assertIn("contract_name", meta.columns)

    def test_prepare_train_test_split_stratification(self):
        df = load_and_validate_dataset(DEFAULT_DATASET_PATH)
        X, y, _ = split_features_and_target(df)
        X_train, X_test, y_train, y_test = prepare_train_test_split(X, y, test_size=0.2, random_state=42)

        self.assertEqual(len(X_train), 96)
        self.assertEqual(len(X_test), 24)
        # Stratified balance check
        self.assertEqual((y_train == 0).sum(), 48)
        self.assertEqual((y_train == 1).sum(), 48)
        self.assertEqual((y_test == 0).sum(), 12)
        self.assertEqual((y_test == 1).sum(), 12)

    def test_scaler_persistence_and_transform(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            scaler_path = Path(tmp_dir) / "test_scaler.joblib"
            df = load_and_validate_dataset(DEFAULT_DATASET_PATH)
            X, y, _ = split_features_and_target(df)

            scaler = fit_and_save_scaler(X, scaler_path)
            self.assertTrue(scaler_path.exists())

            loaded_scaler = load_scaler(scaler_path)
            self.assertIsNotNone(loaded_scaler)

            scaled = scale_features(loaded_scaler, X)
            self.assertEqual(scaled.shape, (120, 19))
            # Mean of scaled features should be close to 0
            np.testing.assert_allclose(scaled.mean(axis=0), 0.0, atol=1e-7)

    def test_get_preprocessed_data_container(self):
        data = get_preprocessed_data()
        self.assertIsInstance(data, PreprocessedData)
        self.assertEqual(data.train_size, 96)
        self.assertEqual(data.test_size, 24)
        self.assertEqual(data.X_train_scaled.shape, (96, 19))
        self.assertEqual(data.X_test_scaled.shape, (24, 19))


class TestModelTraining(unittest.TestCase):
    """Test model training algorithms, cross validation, and serialization."""

    def setUp(self):
        self.data = get_preprocessed_data(save_scaler=False)

    def test_train_random_forest(self):
        rf = train_random_forest(self.data.X_train, self.data.y_train)
        self.assertIsInstance(rf, RandomForestClassifier)
        preds = rf.predict(self.data.X_test)
        self.assertEqual(len(preds), 24)
        probs = rf.predict_proba(self.data.X_test)
        self.assertEqual(probs.shape, (24, 2))

    def test_train_logistic_regression(self):
        lr = train_logistic_regression(self.data.X_train_scaled, self.data.y_train)
        self.assertIsInstance(lr, LogisticRegression)
        preds = lr.predict(self.data.X_test_scaled)
        self.assertEqual(len(preds), 24)
        probs = lr.predict_proba(self.data.X_test_scaled)
        self.assertEqual(probs.shape, (24, 2))

    def test_evaluate_cross_validation(self):
        rf = RandomForestClassifier(n_estimators=50, random_state=42)
        metrics = evaluate_cross_validation(rf, self.data.X_train, self.data.y_train, n_splits=3)
        self.assertIn("accuracy_mean", metrics)
        self.assertIn("f1_mean", metrics)
        self.assertIn("roc_auc_mean", metrics)
        self.assertGreater(metrics["accuracy_mean"], 0.80)

    def test_feature_importance_extraction(self):
        rf = train_random_forest(self.data.X_train, self.data.y_train)
        importances = extract_feature_importances(rf, self.data.feature_names)
        self.assertEqual(len(importances), 19)
        self.assertAlmostEqual(sum(importances.values()), 1.0, places=4)

    def test_logistic_coefficients_extraction(self):
        lr = train_logistic_regression(self.data.X_train_scaled, self.data.y_train)
        coeffs = extract_logistic_coefficients(lr, self.data.feature_names)
        self.assertEqual(len(coeffs), 19)

    def test_train_and_save_all_models_flow(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            rf_file = tmp_path / "rf.joblib"
            lr_file = tmp_path / "lr.joblib"
            meta_file = tmp_path / "meta.json"

            meta = train_and_save_all_models(
                rf_path=rf_file,
                lr_path=lr_file,
                metadata_path=meta_file,
            )

            self.assertTrue(rf_file.exists())
            self.assertTrue(lr_file.exists())
            self.assertTrue(meta_file.exists())
            self.assertIn("recommended_model", meta)
            self.assertIn("random_forest", meta["models"])


class TestModelEvaluation(unittest.TestCase):
    """Test evaluation report generation and metric calculations."""

    def setUp(self):
        self.data = get_preprocessed_data(save_scaler=False)
        self.rf = train_random_forest(self.data.X_train, self.data.y_train)

    def test_evaluate_single_model(self):
        res = evaluate_single_model(self.rf, self.data.X_test, self.data.y_test, "RandomForestClassifier")
        self.assertEqual(res["model_name"], "RandomForestClassifier")
        self.assertIn("metrics", res)
        self.assertIn("confusion_matrix", res)
        self.assertEqual(res["confusion_matrix"]["total_samples"], 24)
        self.assertGreaterEqual(res["metrics"]["accuracy"], 0.90)
        self.assertGreaterEqual(res["metrics"]["roc_auc"], 0.90)

    def test_evaluate_models_and_save_reports(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            rf_file = tmp_path / "rf.joblib"
            lr_file = tmp_path / "lr.joblib"
            json_file = tmp_path / "eval.json"
            txt_file = tmp_path / "eval.txt"

            train_and_save_all_models(rf_path=rf_file, lr_path=lr_file)
            reports = evaluate_models_and_save_reports(
                rf_path=rf_file,
                lr_path=lr_file,
                output_json=json_file,
                output_txt=txt_file,
                generate_plots=False,
            )

            self.assertTrue(json_file.exists())
            self.assertTrue(txt_file.exists())
            self.assertIn("random_forest", reports)
            self.assertIn("logistic_regression", reports)


class TestMLDetector(unittest.TestCase):
    """Test MLDetector inference with saved models and heuristic fallback."""

    def setUp(self):
        self.samples_dir = Path(__file__).resolve().parent.parent / "samples"
        self.benign_sol = (self.samples_dir / "BenignToken.sol").read_text(encoding="utf-8")
        self.honeypot_sol = (self.samples_dir / "HoneypotToken.sol").read_text(encoding="utf-8")
        self.detector = MLDetector()

    def test_detector_with_active_model(self):
        self.assertTrue(self.detector.model_available, "Trained model should be available")
        self.assertIn(self.detector.model_name, ["RandomForestClassifier", "LogisticRegression"])

    def test_predict_benign_token(self):
        result = self.detector.predict_source(self.benign_sol)
        self.assertIsInstance(result, MLPredictionResult)
        self.assertFalse(result.is_honeypot)
        self.assertEqual(result.risk_label, "BENIGN")
        self.assertLess(result.honeypot_probability, 0.35)
        self.assertTrue(result.model_available)

    def test_predict_honeypot_token(self):
        result = self.detector.predict_source(self.honeypot_sol)
        self.assertIsInstance(result, MLPredictionResult)
        self.assertTrue(result.is_honeypot)
        self.assertEqual(result.risk_label, "HONEYPOT")
        self.assertGreaterEqual(result.honeypot_probability, 0.70)
        self.assertTrue(result.model_available)
        self.assertGreater(len(result.feature_contributions), 0)

    def test_predict_contract_object(self):
        contract = LoadedContract(
            input_type="source_code",
            source_code=self.honeypot_sol,
            name="HoneypotToken",
            address="0x2222222222222222222222222222222222222222",
            network="ethereum",
            is_success=True,
        )
        result = self.detector.predict_contract(contract)
        self.assertTrue(result.is_honeypot)

    def test_predict_batch(self):
        results = self.detector.predict_batch([self.benign_sol, self.honeypot_sol])
        self.assertEqual(len(results), 2)
        self.assertFalse(results[0].is_honeypot)
        self.assertTrue(results[1].is_honeypot)

    def test_heuristic_fallback_when_model_absent(self):
        # Force fallback by pointing to nonexistent path
        fallback_detector = MLDetector(
            model_path="nonexistent_model.joblib",
            prefer_model="nonexistent",
        )
        # Explicitly ensure model is None to test pure fallback
        fallback_detector.model = None
        fallback_detector.model_available = False
        fallback_detector.model_name = "None"

        # Test benign in fallback
        benign_res = fallback_detector.predict_source(self.benign_sol)
        self.assertFalse(benign_res.model_available)
        self.assertEqual(benign_res.model_used, "HeuristicFallback")
        self.assertFalse(benign_res.is_honeypot)
        self.assertEqual(benign_res.risk_label, "BENIGN")

        # Test honeypot in fallback
        honeypot_res = fallback_detector.predict_source(self.honeypot_sol)
        self.assertFalse(honeypot_res.model_available)
        self.assertEqual(honeypot_res.model_used, "HeuristicFallback")
        self.assertTrue(honeypot_res.is_honeypot)
        self.assertEqual(honeypot_res.risk_label, "HONEYPOT")
        self.assertGreater(len(honeypot_res.feature_contributions), 0)

    def test_result_to_dict_serialization(self):
        result = self.detector.predict_source(self.benign_sol)
        res_dict = result.to_dict()
        self.assertIsInstance(res_dict, dict)
        self.assertIn("is_honeypot", res_dict)
        self.assertIn("honeypot_probability", res_dict)
        self.assertIn("risk_label", res_dict)
        self.assertIn("model_used", res_dict)
        self.assertIn("feature_contributions", res_dict)

    def test_integration_with_complete_audit_report(self):
        contract = ContractLoader.load_from_source(self.honeypot_sol)
        ml_res = self.detector.predict_contract(contract)

        audit = CompleteAuditReport(
            contract=contract,
            ml_prediction=ml_res.to_dict(),
        )
        report_dict = audit.to_dict()
        self.assertIsNotNone(report_dict["machine_learning"])
        self.assertTrue(report_dict["machine_learning"]["is_honeypot"])
        self.assertEqual(report_dict["machine_learning"]["risk_label"], "HONEYPOT")


if __name__ == "__main__":
    unittest.main()
