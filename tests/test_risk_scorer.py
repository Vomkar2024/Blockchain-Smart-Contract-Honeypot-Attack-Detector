"""Unit tests for the explainable RiskScorer engine."""

import unittest

from src.config import RiskThresholds, SeverityWeights
from src.detection_rules import Finding, PositiveIndicator, Severity, Confidence
from src.risk_scorer import RiskScorer, RiskLevel, RiskReport


def make_finding(severity: Severity, confidence: Confidence = Confidence.HIGH, rule_id: str = "RULE_1") -> Finding:
    """Helper to construct dummy findings."""
    return Finding(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        category="Test",
        severity=severity,
        confidence=confidence,
        line_number=1,
        evidence="evidence",
        explanation="Test explanation",
        suggested_verification="Verify test",
    )


def make_indicator(indicator_id: str = "POS_1") -> PositiveIndicator:
    """Helper to construct dummy positive indicators."""
    return PositiveIndicator(
        indicator_id=indicator_id,
        name=f"Indicator {indicator_id}",
        evidence="evidence",
        explanation="Safe practice",
    )


class TestRiskScorerCalculations(unittest.TestCase):
    """Verifies weighted scoring, positive discounts, security guardrails, and risk thresholds."""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_zero_findings_low_risk(self):
        report = self.scorer.calculate_risk(findings=[], positive_indicators=[])
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(report.risk_level, RiskLevel.LOW)
        self.assertEqual(report.breakdown.gross_score, 0)
        self.assertEqual(report.breakdown.net_score, 0)
        self.assertEqual(report.breakdown.positive_deductions, 0)

    def test_low_severity_findings(self):
        findings = [make_finding(Severity.LOW)]
        report = self.scorer.calculate_risk(findings=findings)
        # 1 Low = 5 points
        self.assertEqual(report.risk_score, 5)
        self.assertEqual(report.risk_level, RiskLevel.LOW)

    def test_moderate_risk_threshold(self):
        # 1 Medium (15) + 2 Low (10) = 25 points -> MODERATE
        findings = [
            make_finding(Severity.MEDIUM, rule_id="M1"),
            make_finding(Severity.LOW, rule_id="L1"),
            make_finding(Severity.LOW, rule_id="L2"),
        ]
        report = self.scorer.calculate_risk(findings=findings)
        self.assertEqual(report.risk_score, 25)
        self.assertEqual(report.risk_level, RiskLevel.MODERATE)

    def test_high_risk_threshold(self):
        # 2 High findings = 2 * 25 = 50 points -> HIGH
        findings = [
            make_finding(Severity.HIGH, rule_id="H1"),
            make_finding(Severity.HIGH, rule_id="H2"),
        ]
        report = self.scorer.calculate_risk(findings=findings)
        self.assertEqual(report.risk_score, 50)
        self.assertEqual(report.risk_level, RiskLevel.HIGH)

    def test_critical_risk_threshold(self):
        # 2 Critical findings = 2 * 40 = 80 points -> CRITICAL
        findings = [
            make_finding(Severity.CRITICAL, rule_id="C1"),
            make_finding(Severity.CRITICAL, rule_id="C2"),
        ]
        report = self.scorer.calculate_risk(findings=findings)
        self.assertEqual(report.risk_score, 80)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)

    def test_positive_deductions_capped_at_15(self):
        # 2 High findings = 50 points
        findings = [
            make_finding(Severity.HIGH, rule_id="H1"),
            make_finding(Severity.HIGH, rule_id="H2"),
        ]
        # 4 positive indicators = 4 * 5 = 20, but capped at 15
        indicators = [make_indicator(f"POS_{i}") for i in range(4)]
        report = self.scorer.calculate_risk(findings=findings, positive_indicators=indicators)
        self.assertEqual(report.breakdown.positive_deductions, 15)
        self.assertEqual(report.risk_score, 35)  # 50 - 15 = 35 -> MODERATE
        self.assertEqual(report.risk_level, RiskLevel.MODERATE)

    def test_critical_guardrail_floor_at_50(self):
        # 1 Critical finding = 40 points
        # 4 positive indicators = 15 deduction -> net would be 25 without guardrail
        # But guardrail enforces floor of 50 whenever critical finding exists
        findings = [make_finding(Severity.CRITICAL, rule_id="C1")]
        indicators = [make_indicator(f"POS_{i}") for i in range(4)]
        report = self.scorer.calculate_risk(findings=findings, positive_indicators=indicators)
        self.assertEqual(report.risk_score, 50)
        self.assertEqual(report.risk_level, RiskLevel.HIGH)

    def test_score_clamped_to_100_maximum(self):
        # 4 Critical findings = 160 points -> must clamp to 100
        findings = [make_finding(Severity.CRITICAL, rule_id=f"C{i}") for i in range(4)]
        report = self.scorer.calculate_risk(findings=findings)
        self.assertEqual(report.risk_score, 100)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)

    def test_confidence_assessment(self):
        # 1 Critical finding -> Confidence.HIGH
        f_crit = [make_finding(Severity.CRITICAL)]
        self.assertEqual(self.scorer.calculate_risk(f_crit).confidence, Confidence.HIGH)

        # 2 High confidence findings -> Confidence.HIGH
        f_high = [
            make_finding(Severity.MEDIUM, Confidence.HIGH, rule_id="M1"),
            make_finding(Severity.MEDIUM, Confidence.HIGH, rule_id="M2"),
        ]
        self.assertEqual(self.scorer.calculate_risk(f_high).confidence, Confidence.HIGH)

        # 1 Low confidence finding -> Confidence.MEDIUM
        f_low = [make_finding(Severity.LOW, Confidence.LOW)]
        self.assertEqual(self.scorer.calculate_risk(f_low).confidence, Confidence.MEDIUM)

        # 0 findings, 2 positive indicators -> Confidence.HIGH
        p_two = [make_indicator("P1"), make_indicator("P2")]
        self.assertEqual(self.scorer.calculate_risk([], p_two).confidence, Confidence.HIGH)

    def test_custom_thresholds_and_weights(self):
        custom_weights = SeverityWeights(CRITICAL=50, HIGH=30, MEDIUM=10, LOW=2)
        custom_thresholds = RiskThresholds(moderate=20, high=40, critical=60)
        custom_scorer = RiskScorer(thresholds=custom_thresholds, weights=custom_weights)

        findings = [make_finding(Severity.HIGH)]
        report = custom_scorer.calculate_risk(findings)
        # 1 High with custom weight 30 >= 20 -> MODERATE
        self.assertEqual(report.risk_score, 30)
        self.assertEqual(report.risk_level, RiskLevel.MODERATE)


class TestRiskReportOutput(unittest.TestCase):
    """Tests RiskReport dataclass, checklist generation, and serialization."""

    def test_to_dict_serialization(self):
        scorer = RiskScorer()
        findings = [
            make_finding(Severity.CRITICAL, rule_id="HONEYPOT_BLACKLIST"),
            make_finding(Severity.HIGH, rule_id="HONEYPOT_EXCESSIVE_SELL_TAX"),
        ]
        indicators = [make_indicator("POS_OPENZEPPELIN_STANDARD")]

        report = scorer.calculate_risk(findings=findings, positive_indicators=indicators)
        d = report.to_dict()

        self.assertIn("risk_score", d)
        self.assertIn("risk_level", d)
        self.assertIn("breakdown", d)
        self.assertEqual(d["breakdown"]["critical_findings_count"], 1)
        self.assertEqual(d["breakdown"]["high_findings_count"], 1)
        self.assertEqual(d["breakdown"]["positive_indicators_count"], 1)
        self.assertGreater(len(d["primary_risk_factors"]), 0)
        self.assertGreater(len(d["mitigating_factors"]), 0)
        self.assertGreater(len(d["manual_verification_checklist"]), 0)
        self.assertIn("disclaimer", d)


if __name__ == "__main__":
    unittest.main()
