"""Comprehensive Test Suite for Phase 5: Educational Solidity Sample Contracts.

Covers:
- File integrity and contract loading (sample_safe_token.sol, sample_honeypot_token.sol, sample_restricted_token.sol)
- Static analysis and detection rule triggering (SourceAnalyzer)
- Feature extraction and 19-dimensional vector representations (FeatureExtractor)
- Explainable risk score assessment (RiskScorer)
- Machine learning classification and feature attribution (MLDetector)
- Complete audit report generation and exports (CompleteAuditReport)
"""

import json
import unittest
from pathlib import Path

from src.contract_loader import ContractLoader
from src.source_analyzer import SourceAnalyzer
from src.feature_extractor import FeatureExtractor
from src.risk_scorer import RiskScorer, RiskLevel
from src.ml_detector import MLDetector
from src.report_generator import CompleteAuditReport


class TestSampleContractsIntegrity(unittest.TestCase):
    """Verifies that all three educational contracts exist, load cleanly, and parse basic metadata."""

    def setUp(self):
        self.samples_dir = Path(__file__).resolve().parent.parent / "samples"
        self.safe_path = self.samples_dir / "sample_safe_token.sol"
        self.honeypot_path = self.samples_dir / "sample_honeypot_token.sol"
        self.restricted_path = self.samples_dir / "sample_restricted_token.sol"

    def test_sample_files_exist(self):
        self.assertTrue(self.safe_path.exists(), f"Missing file: {self.safe_path}")
        self.assertTrue(self.honeypot_path.exists(), f"Missing file: {self.honeypot_path}")
        self.assertTrue(self.restricted_path.exists(), f"Missing file: {self.restricted_path}")

    def test_load_sample_safe_token(self):
        contract = ContractLoader.load_from_file(self.safe_path)
        self.assertTrue(contract.is_success)
        self.assertTrue(contract.has_source)
        self.assertEqual(contract.name, "SafeToken")
        self.assertEqual(contract.compiler_version, "^0.8.20")
        self.assertIn("MAX_FEE", contract.source_code)

    def test_load_sample_honeypot_token(self):
        contract = ContractLoader.load_from_file(self.honeypot_path)
        self.assertTrue(contract.is_success)
        self.assertTrue(contract.has_source)
        self.assertEqual(contract.name, "HoneypotToken")
        self.assertEqual(contract.compiler_version, "^0.8.20")
        self.assertIn("isBlacklisted", contract.source_code)
        self.assertIn("canSell", contract.source_code)

    def test_load_sample_restricted_token(self):
        contract = ContractLoader.load_from_file(self.restricted_path)
        self.assertTrue(contract.is_success)
        self.assertTrue(contract.has_source)
        self.assertEqual(contract.name, "RestrictedGovernanceToken")
        self.assertEqual(contract.compiler_version, "^0.8.20")
        self.assertIn("maxTxAmount", contract.source_code)
        self.assertIn("isWhitelisted", contract.source_code)


class TestSourceAnalyzerEvaluation(unittest.TestCase):
    """Tests static analysis rule evaluation and positive indicator discovery across samples."""

    def setUp(self):
        self.analyzer = SourceAnalyzer()
        samples_dir = Path(__file__).resolve().parent.parent / "samples"
        self.safe_src = (samples_dir / "sample_safe_token.sol").read_text(encoding="utf-8")
        self.honeypot_src = (samples_dir / "sample_honeypot_token.sol").read_text(encoding="utf-8")
        self.restricted_src = (samples_dir / "sample_restricted_token.sol").read_text(encoding="utf-8")

    def test_safe_token_analysis(self):
        result = self.analyzer.analyze(self.safe_src, "SafeToken")
        self.assertTrue(result.is_valid_solidity)
        self.assertEqual(result.contract_structure.name, "SafeToken")
        self.assertTrue(result.contract_structure.has_transfer_function)
        self.assertTrue(result.contract_structure.has_owner_control)

        # Benign token should have ZERO malicious findings
        self.assertEqual(len(result.findings), 0, f"Expected 0 findings, got: {[f.rule_id for f in result.findings]}")

        # Should exhibit multiple positive indicators
        indicator_ids = {p.indicator_id for p in result.positive_indicators}
        self.assertIn("POS_OPENZEPPELIN_STANDARD", indicator_ids)
        self.assertIn("POS_RENOUNCE_OWNERSHIP", indicator_ids)
        self.assertIn("POS_STANDARD_EVENTS", indicator_ids)
        self.assertGreaterEqual(len(result.positive_indicators), 3)

    def test_honeypot_token_analysis(self):
        result = self.analyzer.analyze(self.honeypot_src, "HoneypotToken")
        self.assertTrue(result.is_valid_solidity)
        self.assertEqual(result.contract_structure.name, "HoneypotToken")
        self.assertTrue(result.contract_structure.has_owner_control)

        rule_ids = {f.rule_id for f in result.findings}
        # Verify all primary honeypot rules triggered
        self.assertIn("HONEYPOT_BLACKLIST", rule_ids)
        self.assertIn("HONEYPOT_SELL_RESTRICTION", rule_ids)
        self.assertIn("HONEYPOT_UNLIMITED_OWNER_TAX", rule_ids)
        self.assertIn("HONEYPOT_EXCESSIVE_SELL_TAX", rule_ids)
        self.assertIn("HONEYPOT_HIDDEN_MINT", rule_ids)
        self.assertIn("HONEYPOT_SUSPICIOUS_ASSEMBLY", rule_ids)
        self.assertIn("HONEYPOT_EXTERNAL_RESTRICTION_CALL", rule_ids)

        self.assertGreaterEqual(len(result.findings), 5)
        # Honeypot must not earn benign positive indicators
        self.assertEqual(len(result.positive_indicators), 0)

    def test_restricted_token_analysis(self):
        result = self.analyzer.analyze(self.restricted_src, "RestrictedGovernanceToken")
        self.assertTrue(result.is_valid_solidity)
        self.assertEqual(result.contract_structure.name, "RestrictedGovernanceToken")

        rule_ids = {f.rule_id for f in result.findings}
        # Restricted governance features triggered
        self.assertIn("HONEYPOT_PAUSABLE_TRANSFERS", rule_ids)
        self.assertIn("HONEYPOT_MAX_WALLET_TX_LIMIT", rule_ids)

        # Must NOT trigger classic honeypot traps
        self.assertNotIn("HONEYPOT_BLACKLIST", rule_ids)
        self.assertNotIn("HONEYPOT_SELL_RESTRICTION", rule_ids)
        self.assertNotIn("HONEYPOT_EXCESSIVE_SELL_TAX", rule_ids)
        self.assertNotIn("HONEYPOT_UNLIMITED_OWNER_TAX", rule_ids)

        # Must retain standard positive indicators
        indicator_ids = {p.indicator_id for p in result.positive_indicators}
        self.assertIn("POS_OPENZEPPELIN_STANDARD", indicator_ids)
        self.assertIn("POS_RENOUNCE_OWNERSHIP", indicator_ids)


class TestFeatureExtraction(unittest.TestCase):
    """Tests 19-dimensional feature vector extraction across all sample contracts."""

    def setUp(self):
        self.extractor = FeatureExtractor()
        samples_dir = Path(__file__).resolve().parent.parent / "samples"
        self.safe_src = (samples_dir / "sample_safe_token.sol").read_text(encoding="utf-8")
        self.honeypot_src = (samples_dir / "sample_honeypot_token.sol").read_text(encoding="utf-8")
        self.restricted_src = (samples_dir / "sample_restricted_token.sol").read_text(encoding="utf-8")

    def test_safe_token_features(self):
        feats = self.extractor.extract_features_from_source(self.safe_src)
        self.assertEqual(len(feats), 19)
        self.assertEqual(feats["has_blacklist_mapping"], 0)
        self.assertEqual(feats["has_sell_restriction_logic"], 0)
        self.assertEqual(feats["has_excessive_fee"], 0)
        self.assertEqual(feats["has_unbounded_fee_setter"], 0)
        self.assertEqual(feats["has_pausable_transfers"], 0)
        self.assertEqual(feats["num_total_findings"], 0)
        self.assertGreaterEqual(feats["num_positive_indicators"], 3)
        self.assertEqual(feats["has_openzeppelin_imports"], 1)
        self.assertEqual(feats["has_renounce_ownership"], 1)

    def test_honeypot_token_features(self):
        feats = self.extractor.extract_features_from_source(self.honeypot_src)
        self.assertEqual(len(feats), 19)
        self.assertEqual(feats["has_blacklist_mapping"], 1)
        self.assertEqual(feats["has_sell_restriction_logic"], 1)
        self.assertEqual(feats["has_excessive_fee"], 1)
        self.assertEqual(feats["has_unbounded_fee_setter"], 1)
        self.assertEqual(feats["has_hidden_mint"], 1)
        self.assertEqual(feats["has_inline_assembly"], 1)
        self.assertEqual(feats["has_external_transfer_call"], 1)
        self.assertGreaterEqual(feats["num_total_findings"], 5)
        self.assertEqual(feats["num_positive_indicators"], 0)

    def test_restricted_token_features(self):
        feats = self.extractor.extract_features_from_source(self.restricted_src)
        self.assertEqual(len(feats), 19)
        self.assertEqual(feats["has_blacklist_mapping"], 0)
        self.assertEqual(feats["has_sell_restriction_logic"], 0)
        self.assertEqual(feats["has_pausable_transfers"], 1)
        self.assertEqual(feats["has_max_tx_wallet_limit"], 1)
        self.assertEqual(feats["has_openzeppelin_imports"], 1)
        self.assertEqual(feats["has_renounce_ownership"], 1)
        self.assertGreaterEqual(feats["num_positive_indicators"], 2)

    def test_feature_vector_dimensions_and_types(self):
        for src in [self.safe_src, self.honeypot_src, self.restricted_src]:
            vec = self.extractor.extract_feature_vector(src)
            self.assertEqual(len(vec), 19)
            self.assertTrue(all(isinstance(v, float) for v in vec))


class TestRiskScoringEngine(unittest.TestCase):
    """Tests explainable risk scoring across safe, honeypot, and restricted archetypes."""

    def setUp(self):
        self.analyzer = SourceAnalyzer()
        self.scorer = RiskScorer()
        samples_dir = Path(__file__).resolve().parent.parent / "samples"
        self.safe_src = (samples_dir / "sample_safe_token.sol").read_text(encoding="utf-8")
        self.honeypot_src = (samples_dir / "sample_honeypot_token.sol").read_text(encoding="utf-8")
        self.restricted_src = (samples_dir / "sample_restricted_token.sol").read_text(encoding="utf-8")

    def test_safe_token_risk_score(self):
        analysis = self.analyzer.analyze(self.safe_src)
        report = self.scorer.calculate_risk(analysis.findings, analysis.positive_indicators)
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(report.risk_level, RiskLevel.LOW)
        self.assertEqual(report.label, "LOW")
        self.assertEqual(len(report.primary_risk_factors), 0)
        self.assertGreaterEqual(len(report.mitigating_factors), 3)

    def test_honeypot_token_risk_score(self):
        analysis = self.analyzer.analyze(self.honeypot_src)
        report = self.scorer.calculate_risk(analysis.findings, analysis.positive_indicators)
        self.assertGreaterEqual(report.risk_score, 80)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(report.label, "CRITICAL")
        self.assertGreaterEqual(len(report.primary_risk_factors), 3)
        self.assertGreaterEqual(len(report.manual_verification_checklist), 1)

    def test_restricted_token_risk_score(self):
        analysis = self.analyzer.analyze(self.restricted_src)
        report = self.scorer.calculate_risk(analysis.findings, analysis.positive_indicators)
        # Medium findings offset by positive indicators
        self.assertIn(report.risk_level, [RiskLevel.LOW, RiskLevel.MODERATE])
        self.assertLess(report.risk_score, 50)
        self.assertGreaterEqual(len(report.mitigating_factors), 2)


class TestMLInferenceClassification(unittest.TestCase):
    """Tests ML inference pipeline predictions and feature attributions on sample contracts."""

    def setUp(self):
        self.detector = MLDetector()
        samples_dir = Path(__file__).resolve().parent.parent / "samples"
        self.safe_src = (samples_dir / "sample_safe_token.sol").read_text(encoding="utf-8")
        self.honeypot_src = (samples_dir / "sample_honeypot_token.sol").read_text(encoding="utf-8")
        self.restricted_src = (samples_dir / "sample_restricted_token.sol").read_text(encoding="utf-8")

    def test_safe_token_ml_prediction(self):
        pred = self.detector.predict_source(self.safe_src)
        self.assertFalse(pred.is_honeypot)
        self.assertEqual(pred.risk_label, "BENIGN")
        self.assertLessEqual(pred.honeypot_probability, 0.35)
        self.assertGreaterEqual(pred.confidence_score, 0.0)

    def test_honeypot_token_ml_prediction(self):
        pred = self.detector.predict_source(self.honeypot_src)
        self.assertTrue(pred.is_honeypot)
        self.assertEqual(pred.risk_label, "HONEYPOT")
        self.assertGreaterEqual(pred.honeypot_probability, 0.70)
        self.assertGreater(len(pred.feature_contributions), 0)

    def test_restricted_token_ml_prediction(self):
        pred = self.detector.predict_source(self.restricted_src)
        self.assertIsInstance(pred.is_honeypot, bool)
        self.assertIn(pred.risk_label, ["BENIGN", "SUSPICIOUS"])
        self.assertIsInstance(pred.feature_vector, dict)
        self.assertEqual(len(pred.feature_vector), 19)


class TestEndToEndAuditReports(unittest.TestCase):
    """Tests full end-to-end audit report assembly and serialization for all three contracts."""

    def setUp(self):
        self.analyzer = SourceAnalyzer()
        self.scorer = RiskScorer()
        self.detector = MLDetector()
        self.samples_dir = Path(__file__).resolve().parent.parent / "samples"

    def test_generate_complete_audit_report(self):
        for filename in ["sample_safe_token.sol", "sample_honeypot_token.sol", "sample_restricted_token.sol"]:
            filepath = self.samples_dir / filename
            contract = ContractLoader.load_from_file(filepath)
            static_res = self.analyzer.analyze(contract.source_code, contract.name)
            risk_res = self.scorer.calculate_risk(static_res.findings, static_res.positive_indicators)
            ml_res = self.detector.predict_source(contract.source_code).to_dict()

            report = CompleteAuditReport(
                contract=contract,
                static_analysis=static_res,
                risk_report=risk_res,
                ml_prediction=ml_res,
            )

            # Check JSON serialization
            json_str = report.to_json()
            self.assertIsInstance(json_str, str)
            parsed = json.loads(json_str)
            self.assertEqual(parsed["contract"]["name"], contract.name)
            self.assertIn("risk_assessment", parsed)
            self.assertIn("machine_learning", parsed)

            # Check CSV serialization
            csv_str = report.to_csv()
            self.assertIn("Contract Name", csv_str)
            self.assertIn(contract.name, csv_str)


if __name__ == "__main__":
    unittest.main()
