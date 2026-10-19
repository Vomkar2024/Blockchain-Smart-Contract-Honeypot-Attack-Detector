"""Unit tests for CompleteAuditReport and ReportGenerator."""

import json
import unittest
from pathlib import Path
import tempfile
import shutil

from src.contract_loader import LoadedContract
from src.source_analyzer import SourceAnalysisResult, ContractStructure
from src.risk_scorer import RiskReport, RiskBreakdown, RiskLevel
from src.detection_rules import Finding, Severity, Confidence
from src.simulation_adapter import SimulationResult
from src.report_generator import CompleteAuditReport, ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Tests audit report compilation, serialization, and disk export."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.contract = LoadedContract(
            input_type="file",
            name="TestCoin",
            source_code="contract TestCoin {}",
            address="0x1234567890123456789012345678901234567890",
            network="ethereum",
            is_verified=True,
        )
        self.finding = Finding(
            rule_id="HONEYPOT_BLACKLIST",
            rule_name="Blacklist Mechanism",
            category="Access Control",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            line_number=12,
            evidence="require(!isBlacklisted[from]);",
            explanation="Blacklists prevent transfers.",
            suggested_verification="Check blacklist.",
        )
        self.struct = ContractStructure(name="TestCoin", pragma="0.8.20", lines_of_code=20)
        self.static_analysis = SourceAnalysisResult(
            source_name="TestCoin.sol",
            contract_structure=self.struct,
            findings=[self.finding],
            positive_indicators=[],
            timestamp="2026-10-14T12:00:00Z",
            is_valid_solidity=True,
        )
        self.risk_report = RiskReport(
            risk_score=65,
            risk_level=RiskLevel.HIGH,
            label="HIGH",
            confidence=Confidence.HIGH,
            breakdown=RiskBreakdown(
                gross_score=65,
                positive_deductions=0,
                net_score=65,
                critical_findings_count=0,
                high_findings_count=1,
                medium_findings_count=0,
                low_findings_count=0,
                positive_indicators_count=0,
            ),
            primary_risk_factors=["[HIGH] Blacklist Mechanism"],
            mitigating_factors=[],
            summary_explanation="High risk of honeypot behavior.",
            manual_verification_checklist=["Verify owner control."],
            disclaimer="Automated tool disclaimer.",
        )
        self.simulation = SimulationResult(
            is_available=True,
            provider="Tenderly",
            is_honeypot=True,
            buy_tax_percent=5.0,
            sell_tax_percent=99.0,
            honeypot_reason="Sell transfer reverted on DEX.",
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_report_to_dict(self):
        report = CompleteAuditReport(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
            ml_prediction={"prediction": 1, "probability": 0.89},
            simulation=self.simulation,
        )
        d = report.to_dict()
        self.assertIn("report_metadata", d)
        self.assertEqual(d["contract"]["name"], "TestCoin")
        self.assertEqual(d["risk_assessment"]["risk_score"], 65)
        self.assertEqual(d["machine_learning"]["prediction"], 1)
        self.assertTrue(d["simulation"]["is_honeypot"])

    def test_complete_report_to_json_and_save(self):
        report = CompleteAuditReport(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
        )
        json_str = report.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["contract"]["name"], "TestCoin")

        json_file = self.temp_dir / "audit.json"
        saved_path = report.save_json(json_file)
        self.assertTrue(saved_path.exists())
        self.assertGreater(saved_path.stat().st_size, 50)

    def test_to_csv_with_findings_and_save(self):
        report = CompleteAuditReport(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
        )
        csv_text = report.to_csv()
        self.assertIn("HONEYPOT_BLACKLIST", csv_text)
        self.assertIn("TestCoin", csv_text)

        csv_file = self.temp_dir / "audit.csv"
        saved_path = report.save_csv(csv_file)
        self.assertTrue(saved_path.exists())
        self.assertIn("HONEYPOT_BLACKLIST", saved_path.read_text(encoding="utf-8"))

    def test_to_csv_clean_contract_no_findings(self):
        clean_analysis = SourceAnalysisResult(
            source_name="Clean.sol",
            contract_structure=self.struct,
            findings=[],
            positive_indicators=[],
            timestamp="2026-10-14T12:00:00Z",
            is_valid_solidity=True,
        )
        report = CompleteAuditReport(
            contract=self.contract,
            static_analysis=clean_analysis,
            risk_report=None,
        )
        csv_text = report.to_csv()
        self.assertIn("NONE", csv_text)
        self.assertIn("No Suspicious Patterns Detected", csv_text)

    def test_to_markdown_formatting_and_save(self):
        report = CompleteAuditReport(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
            simulation=self.simulation,
        )
        md_text = report.to_markdown()
        self.assertIn("# Honeypot Audit Report: TestCoin", md_text)
        self.assertIn("Overall Risk Score**: **65/100**", md_text)
        self.assertIn("Transaction Simulation", md_text)
        self.assertIn("Sell Tax**: 99.0%", md_text)
        self.assertIn("Static Analysis Findings", md_text)
        self.assertIn("`HONEYPOT_BLACKLIST`", md_text)

        md_file = self.temp_dir / "audit.md"
        saved_path = report.save_markdown(md_file)
        self.assertTrue(saved_path.exists())

    def test_report_generator_build_report_and_batch_csv(self):
        report1 = ReportGenerator.build_report(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
        )
        report2 = ReportGenerator.build_report(
            contract=LoadedContract(input_type="file", name="Coin2"),
            static_analysis=None,
            risk_report=None,
        )

        batch_csv_file = self.temp_dir / "batch.csv"
        saved = ReportGenerator.save_batch_csv([report1, report2], batch_csv_file)
        self.assertTrue(saved.exists())
        content = saved.read_text(encoding="utf-8")
        self.assertIn("TestCoin", content)
        self.assertIn("Coin2", content)
        self.assertIn("HONEYPOT_BLACKLIST", content)


if __name__ == "__main__":
    unittest.main()
