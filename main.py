#!/usr/bin/env python3
"""Main Command-Line Interface (CLI) for Blockchain Smart Contract Honeypot Attack Detector."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from src.config import settings, SUPPORTED_NETWORKS
from src.contract_loader import ContractLoader, LoadedContract
from src.source_analyzer import SourceAnalyzer, SourceAnalysisResult
from src.risk_scorer import RiskScorer, RiskReport, RiskLevel
from src.ml_detector import MLDetector, MLPredictionResult
from src.report_generator import CompleteAuditReport

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(highlight=False)


def parse_arguments(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="EVM Smart Contract Honeypot Attack Detector — Forensic Static & ML Analysis Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python main.py --file samples/sample_safe_token.sol
  python main.py --file samples/sample_honeypot_token.sol --output reports/honeypot.json --csv-output reports/honeypot.csv
  python main.py --address 0x1234567890123456789012345678901234567890 --network ethereum
  python main.py --code "pragma solidity ^0.8.20; contract Test { ... }"
  python main.py --train-ml
""",
    )

    # Ingestion arguments
    input_group = parser.add_argument_group("Contract Input Options")
    input_group.add_argument(
        "-f", "--file",
        type=str,
        help="Path to Solidity source file (.sol), raw bytecode, or contract artifact.",
    )
    input_group.add_argument(
        "-a", "--address",
        type=str,
        help="On-chain smart contract address (0x...) to fetch and audit.",
    )
    input_group.add_argument(
        "-c", "--code",
        type=str,
        help="Direct Solidity source code string to analyze.",
    )
    input_group.add_argument(
        "-n", "--network",
        type=str,
        default=settings.default_network,
        choices=list(SUPPORTED_NETWORKS.keys()),
        help=f"Target blockchain network for address lookups (default: {settings.default_network}).",
    )

    # Export arguments
    output_group = parser.add_argument_group("Output & Reporting Options")
    output_group.add_argument(
        "-o", "--output",
        type=str,
        help="File path to save the full JSON audit report.",
    )
    output_group.add_argument(
        "--csv-output",
        type=str,
        help="File path to save the tabular CSV findings summary.",
    )

    # Execution control
    exec_group = parser.add_argument_group("Execution & Machine Learning Options")
    exec_group.add_argument(
        "--train-ml",
        action="store_true",
        help="Retrain Random Forest and Logistic Regression classifiers on the dataset and save artifacts.",
    )
    exec_group.add_argument(
        "--simulate",
        action="store_true",
        help="Execute simulated honeypot trading test (buy/sell tax, liquidity check).",
    )
    exec_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output with detailed debugging information.",
    )

    return parser.parse_args(args)


def run_ml_training() -> int:
    """Retrain ML models and display training performance metrics."""
    console.print(Panel.fit("[bold cyan]Retraining Machine Learning Classifier Models...[/bold cyan]", border_style="cyan"))
    try:
        from ml.train_model import train_and_save_all_models
        summary = train_and_save_all_models()

        models_info = summary.get("models", {})
        rf_info = models_info.get("random_forest", {})
        rf_cv = rf_info.get("cross_validation_5fold", {})
        rf_acc = rf_cv.get("accuracy_mean", 0.0)
        rf_std = rf_cv.get("accuracy_std", 0.0)
        rf_f1 = rf_cv.get("f1_mean", 0.0)

        table = Table(title="Model Training Performance Summary", box=box.ROUNDED, header_style="bold magenta")
        table.add_column("Model Architecture", style="bold white")
        table.add_column("5-Fold CV Accuracy", justify="center")
        table.add_column("CV Accuracy Std", justify="center")
        table.add_column("5-Fold CV F1", justify="center")
        table.add_column("Artifact Status", justify="center")

        table.add_row(
            "Random Forest Classifier (100 Estimators)",
            f"{rf_acc:.2%}",
            f"+/-{rf_std:.4f}",
            f"{rf_f1:.2%}",
            "[green]Persisted[/green]",
        )

        lr_info = models_info.get("logistic_regression", {})
        lr_cv = lr_info.get("cross_validation_5fold", {})
        lr_acc = lr_cv.get("accuracy_mean", 0.0)
        lr_std = lr_cv.get("accuracy_std", 0.0)
        lr_f1 = lr_cv.get("f1_mean", 0.0)

        table.add_row(
            "Logistic Regression (Standard Scaler)",
            f"{lr_acc:.2%}",
            f"+/-{lr_std:.4f}",
            f"{lr_f1:.2%}",
            "[green]Persisted[/green]",
        )

        console.print(table)
        rec_model = summary.get("recommended_model", "random_forest")
        console.print(f"[bold green][+][/bold green] Recommended Model: [bold cyan]{rec_model}[/bold cyan]")
        console.print(f"[bold green][+][/bold green] Models successfully saved to: [dim]models/[/dim]")
        return 0
    except Exception as e:
        console.print(f"[bold red][!] Training Failed:[/bold red] {e}")
        return 2


def get_risk_style(level_str: str) -> str:
    """Return color style corresponding to risk level."""
    normalized = level_str.upper()
    if "CRITICAL" in normalized:
        return "bold red"
    elif "HIGH" in normalized:
        return "bold orange3"
    elif "MODERATE" in normalized:
        return "bold yellow"
    elif "LOW" in normalized:
        return "bold green"
    return "bold cyan"


def get_severity_badge(severity_str: str) -> Text:
    """Format a styled severity badge text."""
    sev = severity_str.upper()
    if sev == "CRITICAL":
        return Text("CRITICAL", style="bold white on red")
    elif sev == "HIGH":
        return Text("HIGH", style="bold white on dark_orange")
    elif sev == "MEDIUM":
        return Text("MEDIUM", style="bold black on yellow")
    elif sev == "LOW":
        return Text("LOW", style="bold white on blue")
    return Text(sev, style="dim white")


def render_terminal_report(report: CompleteAuditReport) -> None:
    """Render a comprehensive, colorized forensic audit report in the terminal."""
    contract = report.contract
    static_res = report.static_analysis
    risk = report.risk_report
    ml = report.ml_prediction or {}
    sim = report.simulation

    # 1. Header Banner
    console.print()
    banner = Text.assemble(
        ("  === SMART CONTRACT FORENSIC AUDIT REPORT ===\n", "bold cyan"),
        ("      Blockchain Honeypot Detection & Heuristic Engine", "dim white"),
    )
    console.print(Panel(banner, box=box.DOUBLE, border_style="cyan"))

    # 2. Metadata Table
    meta_table = Table(box=box.SIMPLE_HEAVY, show_header=False, expand=True)
    meta_table.add_column("Property", style="bold cyan", width=22)
    meta_table.add_column("Value", style="white")

    meta_table.add_row("Contract Name", f"[bold]{contract.name}[/bold]")
    meta_table.add_row("Input Mode", contract.input_type.upper())
    if contract.address:
        meta_table.add_row("On-Chain Address", f"[yellow]{contract.address}[/yellow]")
    if contract.network:
        meta_table.add_row("Target Network", contract.network.title())
    if contract.compiler_version:
        meta_table.add_row("Compiler Version", contract.compiler_version)
    if static_res and static_res.contract_structure:
        meta_table.add_row("Lines of Code", str(static_res.contract_structure.lines_of_code))
        meta_table.add_row("Declared Functions", str(len(static_res.contract_structure.functions)))

    console.print(Panel(meta_table, title="[bold]Contract Metadata[/bold]", border_style="blue"))

    # 3. Risk Assessment & Gauge Panel
    if risk:
        level_style = get_risk_style(risk.risk_level.value)
        risk_score_bar = "█" * int(risk.risk_score / 4) + "░" * (25 - int(risk.risk_score / 4))

        risk_text = Text()
        risk_text.append(f"\n  EXPLAINABLE RISK SCORE: ", style="bold white")
        risk_text.append(f"[{risk.risk_score} / 100]\n", style=level_style)
        risk_text.append(f"  RISK LEVEL:            ", style="bold white")
        risk_text.append(f"[{risk.risk_level.value}]\n", style=level_style)
        risk_text.append(f"  GAUGE:                 [{risk_score_bar}]\n\n", style=level_style)
        risk_text.append(f"  Summary: {risk.summary_explanation}\n", style="italic white")

        console.print(Panel(risk_text, title="[bold]Explainable Risk Assessment[/bold]", border_style=get_risk_style(risk.risk_level.value)))

    # 4. Machine Learning Inference Panel
    if ml:
        is_hp = ml.get("is_honeypot", False)
        prob = ml.get("honeypot_probability", 0.0)
        conf = ml.get("confidence_score", 0.0)
        model = ml.get("model_used", "Classifier")

        ml_style = "bold red" if is_hp else "bold green"
        ml_label = "HONEYPOT DETECTED" if is_hp else "BENIGN TOKEN"

        ml_table = Table(box=box.SIMPLE, show_header=False, expand=True)
        ml_table.add_column("Metric", style="bold cyan", width=22)
        ml_table.add_column("Value")

        ml_table.add_row("ML Classification", f"[{ml_style}]{ml_label}[/{ml_style}]")
        ml_table.add_row("Honeypot Probability", f"{prob:.2%}")
        ml_table.add_row("Prediction Confidence", f"{conf:.2%}")
        ml_table.add_row("Inference Model", model)

        # Feature contributions
        contributions = ml.get("feature_contributions", {})
        if contributions:
            contrib_str = ", ".join([f"{k}: {v:+.2f}" for k, v in list(contributions.items())[:4]])
            ml_table.add_row("Top Feature Factors", f"[dim]{contrib_str}[/dim]")

        console.print(Panel(ml_table, title="[bold]Machine Learning Inference[/bold]", border_style="magenta"))

    # 5. Static Analysis Findings Table
    if static_res and static_res.findings:
        find_table = Table(title="Suspicious Honeypot Patterns & Vulnerabilities", box=box.ROUNDED, expand=True)
        find_table.add_column("Severity", justify="center", width=12)
        find_table.add_column("Rule ID & Name", style="bold white", width=30)
        find_table.add_column("Line", justify="center", width=8)
        find_table.add_column("Evidence Snippet", style="dim cyan")
        find_table.add_column("Suggested Verification", style="italic white")

        for f in static_res.findings:
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            find_table.add_row(
                get_severity_badge(sev_str),
                f"{f.rule_name}\n[dim]({f.rule_id})[/dim]",
                str(f.line_number or "-"),
                (f.evidence[:60] + "...") if f.evidence and len(f.evidence) > 60 else (f.evidence or "-"),
                f.suggested_verification or "-",
            )
        console.print(find_table)
    else:
        console.print(Panel("[bold green][+] No suspicious honeypot patterns detected by static analysis rules.[/bold green]", border_style="green"))

    # 6. Positive Security Indicators
    if static_res and static_res.positive_indicators:
        pos_table = Table(title="Positive Security & Safety Indicators", box=box.ROUNDED, expand=True)
        pos_table.add_column("Indicator ID", style="bold green", width=26)
        pos_table.add_column("Feature Name", style="bold white", width=28)
        pos_table.add_column("Impact & Details", style="dim green")

        for pos in static_res.positive_indicators:
            pos_table.add_row(
                pos.indicator_id,
                pos.name,
                pos.explanation or pos.evidence or "Positive security pattern.",
            )
        console.print(pos_table)

    # 7. Simulation Results (if present)
    if sim and sim.is_available:
        sim_table = Table(title="Transaction Simulation Adapter Results", box=box.ROUNDED, expand=True)
        sim_table.add_column("Provider", style="bold white")
        sim_table.add_column("Simulation Honeypot?", justify="center")
        sim_table.add_column("Buy Tax %", justify="center")
        sim_table.add_column("Sell Tax %", justify="center")
        sim_table.add_column("Reason / Remarks", style="dim")

        sim_style = "bold red" if sim.is_honeypot else "bold green"
        sim_status = "HONEYPOT" if sim.is_honeypot else "SAFE / PASS"
        sim_table.add_row(
            sim.provider,
            f"[{sim_style}]{sim_status}[/{sim_style}]",
            f"{sim.buy_tax_percent:.1f}%" if sim.buy_tax_percent is not None else "N/A",
            f"{sim.sell_tax_percent:.1f}%" if sim.sell_tax_percent is not None else "N/A",
            sim.honeypot_reason or "Simulation completed cleanly.",
        )
        console.print(sim_table)

    console.print()


def run_pipeline(args: argparse.Namespace) -> int:
    """Execute the complete contract audit pipeline and render terminal and file outputs."""
    # 1. Ingest contract based on flags
    contract: Optional[LoadedContract] = None

    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            console.print(f"[bold red][!] File not found:[/bold red] {file_path}")
            return 2
        contract = ContractLoader.load_from_file(file_path)
    elif args.address:
        console.print(f"Fetching contract from [bold cyan]{args.network.title()}[/bold cyan] for address [yellow]{args.address}[/yellow]...")
        contract = ContractLoader.load_from_address(args.address, network_name=args.network)
    elif args.code:
        contract = ContractLoader.load_from_source(args.code, name="DirectInputContract")
    else:
        console.print("[bold red][!] Error:[/bold red] No contract input provided. Use `--file`, `--address`, `--code`, or `--train-ml`.")
        return 2

    # Check contract ingestion status
    if not contract or not contract.is_success:
        error_msg = contract.error_message if contract else "Unknown loading failure."
        console.print(Panel(f"[bold red]Contract Loading Failed:[/bold red]\n{error_msg}", border_style="red"))
        return 2

    # 2. Static Analysis
    static_res: Optional[SourceAnalysisResult] = None
    if contract.has_source:
        analyzer = SourceAnalyzer()
        static_res = analyzer.analyze(contract.source_code, contract.name)

    # 3. Risk Assessment
    risk_report: Optional[RiskReport] = None
    if static_res:
        scorer = RiskScorer()
        risk_report = scorer.calculate_risk(static_res.findings, static_res.positive_indicators)

    # 4. Machine Learning Inference
    ml_dict: Optional[Dict[str, Any]] = None
    ml_pred: Optional[MLPredictionResult] = None
    if contract.has_source:
        detector = MLDetector()
        ml_pred = detector.predict_source(contract.source_code)
        ml_dict = ml_pred.to_dict()

    # 5. Simulation (if requested or on-chain address provided)
    sim_res: Optional[SimulationResult] = None
    if args.simulate or contract.address:
        try:
            adapter = SimulationAdapter(provider="auto")
            sim_res = adapter.simulate(contract.address or contract.name, network=args.network)
        except Exception as e:
            if args.verbose:
                console.print(f"[dim]Simulation skipped or failed: {e}[/dim]")

    # 6. Assemble Complete Audit Report
    complete_report = CompleteAuditReport(
        contract=contract,
        static_analysis=static_res,
        risk_report=risk_report,
        ml_prediction=ml_dict,
        simulation=sim_res,
    )

    # 7. Render Rich Terminal UI
    render_terminal_report(complete_report)

    # 8. Export Outputs if flags passed
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(complete_report.to_json(), encoding="utf-8")
        console.print(f"[bold green][+][/bold green] Complete JSON audit report saved to: [bold cyan]{out_path}[/bold cyan]")

    if args.csv_output:
        csv_path = Path(args.csv_output)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.write_text(complete_report.to_csv(), encoding="utf-8")
        console.print(f"[bold green][+][/bold green] Tabular CSV findings saved to: [bold cyan]{csv_path}[/bold cyan]")

    # 9. Return Exit Code
    # Return 1 for High/Critical honeypot risk, 0 for Low/Moderate benign
    if risk_report and risk_report.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
        return 1
    if ml_pred and ml_pred.is_honeypot:
        return 1
    return 0


def main(args: Optional[List[str]] = None) -> int:
    """Entry point for the smart contract detector CLI."""
    parsed_args = parse_arguments(args)

    if parsed_args.train_ml:
        train_exit = run_ml_training()
        # If no contract was provided, finish after training
        if not (parsed_args.file or parsed_args.address or parsed_args.code):
            return train_exit

    if parsed_args.file or parsed_args.address or parsed_args.code:
        return run_pipeline(parsed_args)

    if not parsed_args.train_ml:
        console.print("[bold yellow]No action specified.[/bold yellow] Run [bold cyan]python main.py --help[/bold cyan] for usage instructions.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
