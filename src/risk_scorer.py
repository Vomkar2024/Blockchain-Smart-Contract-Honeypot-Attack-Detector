"""Explainable risk-scoring engine for smart contract honeypot evaluation."""

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Any, Optional

from src.config import settings, RiskThresholds, SeverityWeights
from src.detection_rules import Finding, PositiveIndicator, Severity, Confidence


class RiskLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskBreakdown:
    """Detailed components explaining how the score was computed."""
    gross_score: int
    positive_deductions: int
    net_score: int
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    low_findings_count: int
    positive_indicators_count: int


@dataclass
class RiskReport:
    """Full explainable risk assessment report."""
    risk_score: int
    risk_level: RiskLevel
    label: str
    confidence: Confidence
    breakdown: RiskBreakdown
    primary_risk_factors: List[str]
    mitigating_factors: List[str]
    summary_explanation: str
    manual_verification_checklist: List[str]
    disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "label": self.label,
            "confidence": self.confidence.value,
            "breakdown": {
                "gross_score": self.breakdown.gross_score,
                "positive_deductions": self.breakdown.positive_deductions,
                "net_score": self.breakdown.net_score,
                "critical_findings_count": self.breakdown.critical_findings_count,
                "high_findings_count": self.breakdown.high_findings_count,
                "medium_findings_count": self.breakdown.medium_findings_count,
                "low_findings_count": self.breakdown.low_findings_count,
                "positive_indicators_count": self.breakdown.positive_indicators_count,
            },
            "primary_risk_factors": self.primary_risk_factors,
            "mitigating_factors": self.mitigating_factors,
            "summary_explanation": self.summary_explanation,
            "manual_verification_checklist": self.manual_verification_checklist,
            "disclaimer": self.disclaimer,
        }


class RiskScorer:
    """
    Computes explainable risk scores from findings and positive security indicators.
    """

    def __init__(
        self,
        thresholds: Optional[RiskThresholds] = None,
        weights: Optional[SeverityWeights] = None,
    ):
        self.thresholds = thresholds or settings.risk_thresholds
        self.weights = weights or settings.severity_weights

    def calculate_risk(
        self,
        findings: List[Finding],
        positive_indicators: Optional[List[PositiveIndicator]] = None,
    ) -> RiskReport:
        """
        Calculates a normalized 0-100 risk score and generates an explainable breakdown.
        """
        positive_indicators = positive_indicators or []

        # Count findings by severity
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)

        # Gross points calculation
        gross_score = (
            crit_count * self.weights.CRITICAL
            + high_count * self.weights.HIGH
            + med_count * self.weights.MEDIUM
            + low_count * self.weights.LOW
        )

        # Positive factor deduction (each positive indicator discounts 5 points, max 15 points)
        # Security guardrail: If critical findings exist, score cannot drop below 50.
        positive_deduction = min(len(positive_indicators) * 5, 15)

        net_score = gross_score - positive_deduction
        if crit_count > 0:
            net_score = max(net_score, 50)
        net_score = min(100, max(0, net_score))

        # Determine Risk Level and label
        if net_score >= self.thresholds.critical:
            risk_level = RiskLevel.CRITICAL
        elif net_score >= self.thresholds.high:
            risk_level = RiskLevel.HIGH
        elif net_score >= self.thresholds.moderate:
            risk_level = RiskLevel.MODERATE
        else:
            risk_level = RiskLevel.LOW
        label = risk_level.value

        # Confidence assessment
        high_conf_findings = sum(1 for f in findings if f.confidence == Confidence.HIGH)
        if high_conf_findings >= 2 or crit_count >= 1:
            confidence = Confidence.HIGH
        elif len(findings) > 0:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.HIGH if len(positive_indicators) >= 2 else Confidence.MEDIUM

        # Primary risk factors
        primary_risk_factors = [
            f"[{f.severity.value}] {f.rule_name}: {f.explanation}"
            for f in findings[:5]
        ]

        # Mitigating factors
        mitigating_factors = [
            f"{p.name}: {p.explanation}"
            for p in positive_indicators
        ]

        # Explainable summary
        if net_score >= self.thresholds.critical:
            summary = (
                f"Analysis assigned a CRITICAL risk score of {net_score}/100 based on {crit_count} critical finding(s). "
                "The contract exhibits patterns designed to prevent or restrict token selling, matching honeypot architecture."
            )
        elif net_score >= self.thresholds.high:
            summary = (
                f"Analysis assigned a HIGH risk score of {net_score}/100 based on {high_count} high-severity finding(s). "
                "The contract includes centralized controls or fee mechanisms that can be manipulated to disadvantage sellers."
            )
        elif net_score >= self.thresholds.moderate:
            summary = (
                f"Analysis assigned a MODERATE risk score of {net_score}/100. "
                "The contract contains transfer limits, anti-bot mechanisms, or pausable features. While common in some projects, "
                "they introduce administrative counterparty risk."
            )
        else:
            summary = (
                f"Analysis assigned a LOW risk score of {net_score}/100. "
                "No overt honeypot or malicious sell restrictions were detected in the inspected source code."
            )

        # Verification checklist
        checklist = [
            "Check if contract ownership has been renounced or transferred to a verifiable multi-signature wallet.",
            "Verify that initial liquidity pool tokens (LP tokens) are locked in a recognized locker (e.g. Unicrypt, PinkLock).",
            "Test a small buy and sell transaction on a testnet fork or simulator before committing capital.",
            "Inspect compiler pragma and optimization settings to rule out compiler-level bugs.",
        ]
        if crit_count > 0 or high_count > 0:
            checklist.insert(0, "URGENT: Manually inspect the transfer() and _transfer() logic for sell-specific reverts.")

        disclaimer = (
            "NOTICE: This automated report is generated using static heuristic rules and machine learning indicators. "
            "It does NOT constitute financial advice or a comprehensive formal audit. Low scores do not guarantee safety, "
            "as malicious actors can employ unverified bytecode, external proxies, or off-chain oracle collusion."
        )

        breakdown = RiskBreakdown(
            gross_score=gross_score,
            positive_deductions=positive_deduction,
            net_score=net_score,
            critical_findings_count=crit_count,
            high_findings_count=high_count,
            medium_findings_count=med_count,
            low_findings_count=low_count,
            positive_indicators_count=len(positive_indicators),
        )

        return RiskReport(
            risk_score=net_score,
            risk_level=risk_level,
            label=label,
            confidence=confidence,
            breakdown=breakdown,
            primary_risk_factors=primary_risk_factors,
            mitigating_factors=mitigating_factors,
            summary_explanation=summary,
            manual_verification_checklist=checklist,
            disclaimer=disclaimer,
        )
