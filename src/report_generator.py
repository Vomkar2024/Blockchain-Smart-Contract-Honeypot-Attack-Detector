"""Report generation utilities for JSON, CSV, and Markdown audit representations."""

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

from src.contract_loader import LoadedContract
from src.source_analyzer import SourceAnalysisResult
from src.risk_scorer import RiskReport
from src.simulation_adapter import SimulationResult


@dataclass
class CompleteAuditReport:
    """Comprehensive analysis report aggregating all static, ML, and simulation findings."""
    contract: LoadedContract
    static_analysis: Optional[SourceAnalysisResult] = None
    risk_report: Optional[RiskReport] = None
    ml_prediction: Optional[Dict[str, Any]] = None
    simulation: Optional[SimulationResult] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_metadata": {
                "created_at": self.created_at,
                "version": "1.0.0",
                "system": "Blockchain Smart Contract Honeypot Attack Detector",
            },
            "contract": self.contract.to_dict() if self.contract else {},
            "static_analysis": self.static_analysis.to_dict() if self.static_analysis else None,
            "risk_assessment": self.risk_report.to_dict() if self.risk_report else None,
            "machine_learning": self.ml_prediction,
            "simulation": self.simulation.to_dict() if self.simulation else None,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize complete report to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, output_path: Union[str, Path]) -> Path:
        """Write JSON report to specified destination."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        return path

    def to_csv(self) -> str:
        """
        Generate CSV representation focusing on individual findings and contract risk summary.
        """
        output = StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow([
            "Contract Name",
            "Address",
            "Network",
            "Risk Score",
            "Risk Level",
            "Rule ID",
            "Rule Name",
            "Severity",
            "Confidence",
            "Line Number",
            "Evidence",
            "Explanation",
            "Suggested Verification",
        ])

        contract_name = self.contract.name if self.contract else "UnknownContract"
        address = (self.contract.address if self.contract else None) or "N/A"
        network = (self.contract.network if self.contract else None) or "N/A"
        risk_score = self.risk_report.risk_score if self.risk_report else "N/A"
        risk_level = self.risk_report.risk_level.value if (self.risk_report and hasattr(self.risk_report.risk_level, 'value')) else "N/A"

        findings = self.static_analysis.findings if self.static_analysis else []

        if not findings:
            writer.writerow([
                contract_name,
                address,
                network,
                risk_score,
                risk_level,
                "NONE",
                "No Suspicious Patterns Detected",
                "INFORMATIONAL",
                "HIGH",
                "",
                "Clean Source Code",
                "No known honeypot rules matched.",
                "Verify on-chain transactions and liquidity locks.",
            ])
        else:
            for f in findings:
                writer.writerow([
                    contract_name,
                    address,
                    network,
                    risk_score,
                    risk_level,
                    f.rule_id,
                    f.rule_name,
                    f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    f.confidence.value if hasattr(f.confidence, 'value') else str(f.confidence),
                    f.line_number or "",
                    f.evidence.replace("\n", " ") if f.evidence else "",
                    f.explanation or "",
                    f.suggested_verification or "",
                ])

        return output.getvalue()

    def save_csv(self, output_path: Union[str, Path]) -> Path:
        """Write CSV findings report to specified destination."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(self.to_csv())
        return path

    def to_markdown(self) -> str:
        """Generate a formatted Markdown audit report summary."""
        contract_name = self.contract.name if self.contract else "Unknown"
        addr = (self.contract.address if self.contract else None) or "N/A"
        net = (self.contract.network if self.contract else None) or "N/A"
        score = self.risk_report.risk_score if self.risk_report else 0
        level = self.risk_report.risk_level.value if (self.risk_report and hasattr(self.risk_report.risk_level, 'value')) else "UNKNOWN"

        lines = [
            f"# Honeypot Audit Report: {contract_name}",
            "",
            f"- **Address**: `{addr}`",
            f"- **Network**: `{net}`",
            f"- **Audit Timestamp**: `{self.created_at}`",
            f"- **Overall Risk Score**: **{score}/100** ({level})",
            "",
            "## Risk Assessment",
        ]

        if self.risk_report:
            verdict = getattr(self.risk_report, "summary_explanation", getattr(self.risk_report, "summary", "Risk assessment completed."))
            lines.append(f"> **Verdict**: {verdict}")
            recs = getattr(self.risk_report, "manual_verification_checklist", getattr(self.risk_report, "recommendations", []))
            if recs:
                lines.append("")
                lines.append("### Recommendations")
                for r in recs:
                    lines.append(f"- {r}")
        else:
            lines.append("No static risk assessment available.")

        # Simulation section
        if self.simulation and self.simulation.is_available:
            lines.append("")
            lines.append("## Transaction Simulation")
            lines.append(f"- **Provider**: {self.simulation.provider}")
            lines.append(f"- **Honeypot Flag**: {'⚠️ YES' if self.simulation.is_honeypot else '✅ NO'}")
            if self.simulation.buy_tax_percent is not None:
                lines.append(f"- **Buy Tax**: {self.simulation.buy_tax_percent:.1f}%")
            if self.simulation.sell_tax_percent is not None:
                lines.append(f"- **Sell Tax**: {self.simulation.sell_tax_percent:.1f}%")
            if self.simulation.honeypot_reason:
                lines.append(f"- **Simulation Reason**: {self.simulation.honeypot_reason}")

        # Static findings table
        findings = self.static_analysis.findings if self.static_analysis else []
        lines.append("")
        lines.append(f"## Static Analysis Findings ({len(findings)})")
        if findings:
            lines.append("| ID | Rule Name | Severity | Line | Explanation |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in findings:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                ln = f.line_number if f.line_number else "-"
                clean_exp = f.explanation.replace("|", "/")
                lines.append(f"| `{f.rule_id}` | {f.rule_name} | **{sev}** | {ln} | {clean_exp} |")
        else:
            lines.append("No suspicious honeypot patterns detected.")

        return "\n".join(lines)

    def save_markdown(self, output_path: Union[str, Path]) -> Path:
        """Save formatted markdown audit report to file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_markdown())
        return path


class ReportGenerator:
    """Factory and batch export helper for CompleteAuditReport instances."""

    @staticmethod
    def build_report(
        contract: LoadedContract,
        static_analysis: Optional[SourceAnalysisResult] = None,
        risk_report: Optional[RiskReport] = None,
        ml_prediction: Optional[Dict[str, Any]] = None,
        simulation: Optional[SimulationResult] = None,
    ) -> CompleteAuditReport:
        return CompleteAuditReport(
            contract=contract,
            static_analysis=static_analysis,
            risk_report=risk_report,
            ml_prediction=ml_prediction,
            simulation=simulation,
        )

    @staticmethod
    def save_batch_csv(reports: List[CompleteAuditReport], output_path: Union[str, Path]) -> Path:
        """
        Export a list of CompleteAuditReport objects into a single aggregated CSV spreadsheet.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Contract Name",
                "Address",
                "Network",
                "Risk Score",
                "Risk Level",
                "Rule ID",
                "Rule Name",
                "Severity",
                "Confidence",
                "Line Number",
                "Evidence",
                "Explanation",
                "Suggested Verification",
            ])

            for report in reports:
                contract_name = report.contract.name if report.contract else "Unknown"
                address = (report.contract.address if report.contract else None) or "N/A"
                network = (report.contract.network if report.contract else None) or "N/A"
                risk_score = report.risk_report.risk_score if report.risk_report else "N/A"
                risk_level = report.risk_report.risk_level.value if (report.risk_report and hasattr(report.risk_report.risk_level, 'value')) else "N/A"

                findings = report.static_analysis.findings if report.static_analysis else []
                if not findings:
                    writer.writerow([
                        contract_name,
                        address,
                        network,
                        risk_score,
                        risk_level,
                        "NONE",
                        "No Suspicious Patterns Detected",
                        "INFORMATIONAL",
                        "HIGH",
                        "",
                        "Clean Source Code",
                        "No known honeypot rules matched.",
                        "Verify on-chain transactions and liquidity locks.",
                    ])
                else:
                    for find in findings:
                        writer.writerow([
                            contract_name,
                            address,
                            network,
                            risk_score,
                            risk_level,
                            find.rule_id,
                            find.rule_name,
                            find.severity.value if hasattr(find.severity, 'value') else str(find.severity),
                            find.confidence.value if hasattr(find.confidence, 'value') else str(find.confidence),
                            find.line_number or "",
                            find.evidence.replace("\n", " ") if find.evidence else "",
                            find.explanation or "",
                            find.suggested_verification or "",
                        ])

        return path
