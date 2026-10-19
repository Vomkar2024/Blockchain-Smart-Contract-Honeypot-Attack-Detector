"""Tests for the enhanced multi-tier samples suite and API catalog."""

import unittest
from pathlib import Path
import app
from src.config import SAMPLES_DIR
from src.risk_scorer import RiskLevel


class TestEnhancedSamplesAndCatalog(unittest.TestCase):
    """Test suite validating multi-tier threat classification and sample catalog."""

    def test_sample_catalog_structure(self):
        """Verify that all 11 samples exist in the catalog with required metadata."""
        self.assertGreaterEqual(len(app.SAMPLE_CATALOG), 11)
        for key, entry in app.SAMPLE_CATALOG.items():
            self.assertIn("key", entry)
            self.assertIn("name", entry)
            self.assertIn("threatLevel", entry)
            self.assertIn(entry["threatLevel"], ["CRITICAL", "HIGH", "MODERATE", "BENIGN"])
            self.assertIn("file", entry)
            file_path = SAMPLES_DIR / entry["file"]
            self.assertTrue(file_path.exists(), f"Sample file {entry['file']} does not exist on disk!")
            self.assertGreater(file_path.stat().st_size, 0)
            self.assertIn("tags", entry)
            self.assertIsInstance(entry["tags"], list)
            self.assertIn("description", entry)

    def test_get_samples_dict_and_filtering(self):
        """Verify get_samples_dict loads code and supports threat level filtering."""
        all_samples = app.get_samples_dict()
        self.assertEqual(len(all_samples), len(app.SAMPLE_CATALOG))
        for key, data in all_samples.items():
            self.assertTrue(len(data.get("code", "")) > 0, f"Code for {key} should not be empty")

        # Test filtering by CRITICAL
        crit_samples = app.get_samples_dict(filter_level="CRITICAL")
        self.assertGreaterEqual(len(crit_samples), 3)
        for data in crit_samples.values():
            self.assertEqual(data["threatLevel"], "CRITICAL")

        # Test filtering by HIGH
        high_samples = app.get_samples_dict(filter_level="HIGH")
        self.assertGreaterEqual(len(high_samples), 2)
        for data in high_samples.values():
            self.assertEqual(data["threatLevel"], "HIGH")

        # Test filtering by MODERATE
        mod_samples = app.get_samples_dict(filter_level="MODERATE")
        self.assertGreaterEqual(len(mod_samples), 3)
        for data in mod_samples.values():
            self.assertEqual(data["threatLevel"], "MODERATE")

        # Test filtering by BENIGN
        benign_samples = app.get_samples_dict(filter_level="BENIGN")
        self.assertGreaterEqual(len(benign_samples), 3)
        for data in benign_samples.values():
            self.assertEqual(data["threatLevel"], "BENIGN")

    def test_get_rules_catalog(self):
        """Verify get_rules_catalog returns all 10 detection rules with descriptions."""
        rules = app.get_rules_catalog()
        self.assertEqual(len(rules), 10)
        rule_ids = {r["rule_id"] for r in rules}
        self.assertIn("HONEYPOT_BLACKLIST", rule_ids)
        self.assertIn("HONEYPOT_SELL_RESTRICTION", rule_ids)
        self.assertIn("HONEYPOT_EXCESSIVE_SELL_TAX", rule_ids)
        self.assertIn("HONEYPOT_UNLIMITED_OWNER_TAX", rule_ids)
        self.assertIn("HONEYPOT_SUSPICIOUS_ASSEMBLY", rule_ids)

    def test_audit_critical_tier_samples(self):
        """Verify Critical samples score in the CRITICAL threat tier (>= 75)."""
        critical_samples = [
            "samples/sample_honeypot_token.sol",
            "samples/sample_critical_dextrap.sol",
            "samples/sample_critical_delegatecall_backdoor.sol",
        ]
        for p in critical_samples:
            report = app.execute_contract_audit(contract_input=p, input_type="file")
            self.assertIsNotNone(report.risk_report)
            self.assertGreaterEqual(
                report.risk_report.risk_score, 75,
                f"Sample {p} scored {report.risk_report.risk_score}, expected >= 75"
            )
            self.assertEqual(report.risk_report.risk_level, RiskLevel.CRITICAL)

    def test_audit_high_tier_samples(self):
        """Verify High risk samples score in the HIGH threat tier (50-74)."""
        high_samples = [
            "samples/sample_high_unbounded_tax.sol",
            "samples/sample_high_hidden_blacklist.sol",
        ]
        for p in high_samples:
            report = app.execute_contract_audit(contract_input=p, input_type="file")
            self.assertIsNotNone(report.risk_report)
            score = report.risk_report.risk_score
            self.assertTrue(
                50 <= score < 75,
                f"Sample {p} scored {score}, expected 50 <= score < 75"
            )
            self.assertEqual(report.risk_report.risk_level, RiskLevel.HIGH)

    def test_audit_moderate_tier_samples(self):
        """Verify Moderate risk samples score in the MODERATE threat tier (25-49)."""
        moderate_samples = [
            "samples/sample_restricted_token.sol",
            "samples/sample_moderate_pausable_token.sol",
            "samples/sample_moderate_cooldown_token.sol",
        ]
        for p in moderate_samples:
            report = app.execute_contract_audit(contract_input=p, input_type="file")
            self.assertIsNotNone(report.risk_report)
            score = report.risk_report.risk_score
            self.assertTrue(
                25 <= score < 50,
                f"Sample {p} scored {score}, expected 25 <= score < 50"
            )
            self.assertEqual(report.risk_report.risk_level, RiskLevel.MODERATE)

    def test_audit_benign_tier_samples(self):
        """Verify Benign reference samples score in the BENIGN / LOW threat tier (< 25)."""
        benign_samples = [
            "samples/sample_safe_token.sol",
            "samples/sample_benign_defi_token.sol",
            "samples/sample_benign_charity_token.sol",
        ]
        for p in benign_samples:
            report = app.execute_contract_audit(contract_input=p, input_type="file")
            self.assertIsNotNone(report.risk_report)
            score = report.risk_report.risk_score
            self.assertLess(
                score, 25,
                f"Sample {p} scored {score}, expected < 25"
            )
            self.assertEqual(report.risk_report.risk_level, RiskLevel.LOW)

    def test_preset_input_execution(self):
        """Verify execute_contract_audit handles preset keys directly."""
        report = app.execute_contract_audit("CriticalDexTrapToken", input_type="preset")
        self.assertTrue(report.contract.is_success)
        self.assertEqual(report.risk_report.risk_level, RiskLevel.CRITICAL)

    def test_audit_onchain_sample_address_hard_threat(self):
        """Verify on-chain address lookup sample scores in the HIGH threat tier (50-74)."""
        sample_addr = "0x71c8dC0563b7c8449c25fBA0B991461FfFAe7748"
        report = app.execute_contract_audit(contract_input=sample_addr, input_type="address", simulate=True)
        self.assertTrue(report.contract.is_success)
        self.assertEqual(report.contract.address, sample_addr)
        self.assertIsNotNone(report.risk_report)
        score = report.risk_report.risk_score
        self.assertTrue(
            50 <= score < 75,
            f"Sample address {sample_addr} scored {score}, expected 50 <= score < 75"
        )
        self.assertEqual(report.risk_report.risk_level, RiskLevel.HIGH)
        # Check static findings
        rule_ids = {f.rule_id for f in report.static_analysis.findings}
        self.assertIn("HONEYPOT_UNLIMITED_OWNER_TAX", rule_ids)
        self.assertIn("HONEYPOT_HIDDEN_MINT", rule_ids)
        self.assertIn("HONEYPOT_SUSPICIOUS_ASSEMBLY", rule_ids)
        # Check simulation
        self.assertIsNotNone(report.simulation)
        self.assertTrue(report.simulation.is_available)
        self.assertIsNotNone(report.simulation.sell_tax_percent)


if __name__ == "__main__":
    unittest.main()
