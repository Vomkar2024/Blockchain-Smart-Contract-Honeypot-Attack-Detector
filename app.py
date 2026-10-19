"""EVM Smart Contract Honeypot Attack Detector — Forensic Engine & API Bridge.

Provides core pipeline execution for MERN stack (Express/MongoDB) integration
and standalone Python REST API bridge server: `python app.py [port]`
"""

import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional, List

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from src.config import SUPPORTED_NETWORKS, SAMPLES_DIR
from src.contract_loader import ContractLoader
from src.source_analyzer import SourceAnalyzer, SourceAnalysisResult
from src.risk_scorer import RiskScorer, RiskReport
from src.ml_detector import MLDetector
from src.simulation_adapter import SimulationAdapter, SimulationResult
from src.report_generator import CompleteAuditReport


# ---------------------------------------------------------------------------
# Comprehensive Multi-Tier Educational Sample Catalog
# ---------------------------------------------------------------------------
SAMPLE_CATALOG: Dict[str, Dict[str, Any]] = {
    # 1. CRITICAL THREAT LEVEL (Score >= 75)
    "HoneypotToken": {
        "key": "HoneypotToken",
        "name": "Classic Honeypot Token",
        "threatLevel": "CRITICAL",
        "category": "Multi-Vector Trap",
        "file": "sample_honeypot_token.sol",
        "expectedScore": "100/100",
        "tags": ["Blacklist Trap", "Asymmetric Sell", "99% Tax", "Hidden Mint", "Assembly"],
        "description": "Multi-vector malicious honeypot with blacklist traps, asymmetric sell locks, 99% confiscatory tax, and hidden mint privileges.",
    },
    "CriticalDexTrapToken": {
        "key": "CriticalDexTrapToken",
        "name": "DEX Liquidity Siphon Trap",
        "threatLevel": "CRITICAL",
        "category": "Trading Restrictions",
        "file": "sample_critical_dextrap.sol",
        "expectedScore": "100/100",
        "tags": ["DEX Pair Revert", "99% Sell Tax", "External Oracle Trap", "Infinite Mint"],
        "description": "Permits seamless DEX buying but reverts sell transfers back to the Uniswap pair, siphoning liquidity into deployer wallet.",
    },
    "CriticalDelegatecallToken": {
        "key": "CriticalDelegatecallToken",
        "name": "Shadow Delegatecall Backdoor",
        "threatLevel": "CRITICAL",
        "category": "Low-Level Backdoors",
        "file": "sample_critical_delegatecall_backdoor.sol",
        "expectedScore": "100/100",
        "tags": ["Delegatecall", "Address Blacklist", "Unbounded Tax", "Arbitrary Execution"],
        "description": "Low-level EVM delegatecall backdoor disguised inside execution hooks, combined with administrative blacklist mappings.",
    },

    # 2. HIGH THREAT LEVEL (Score 50 - 74)
    "HighUnboundedTaxToken": {
        "key": "HighUnboundedTaxToken",
        "name": "Unbounded Tax & Mint Token",
        "threatLevel": "HIGH",
        "category": "Privileged Manipulation",
        "file": "sample_high_unbounded_tax.sol",
        "address": "0x71c8dC0563b7c8449c25fBA0B991461FfFAe7748",
        "network": "ethereum",
        "expectedScore": "65/100",
        "tags": ["Uncapped Fee Setter", "Unconstrained Mint", "Inline Assembly", "On-Chain Address"],
        "description": "Owner can hike transfer taxes arbitrarily without an immutable ceiling, alongside unconstrained token supply inflation.",
    },
    "HighHiddenBlacklistToken": {
        "key": "HighHiddenBlacklistToken",
        "name": "Blacklist Guard & Inflation Token",
        "threatLevel": "HIGH",
        "category": "Access Control",
        "file": "sample_high_hidden_blacklist.sol",
        "expectedScore": "50/100",
        "tags": ["Hidden Blacklist Check", "Privileged Minting", "Max Wallet Limit"],
        "description": "Enforces selective address blocking in transfer execution paths paired with privileged unconstrained token minting.",
    },

    # 3. MODERATE THREAT LEVEL (Score 25 - 49)
    "RestrictedGovernanceToken": {
        "key": "RestrictedGovernanceToken",
        "name": "Restricted Governance Token",
        "threatLevel": "MODERATE",
        "category": "Enterprise Governance",
        "file": "sample_restricted_token.sol",
        "expectedScore": "30/100",
        "tags": ["Pausable Transfers", "Max Wallet Cap", "Whitelist Exemption", "Cooldown Delay"],
        "description": "Enterprise compliance token with emergency pause switches, anti-whale transaction limits, and partner whitelist mechanisms.",
    },
    "ModeratePausableToken": {
        "key": "ModeratePausableToken",
        "name": "Enterprise Pausable Token",
        "threatLevel": "MODERATE",
        "category": "Pausable Controls",
        "file": "sample_moderate_pausable_token.sol",
        "expectedScore": "30/100",
        "tags": ["Emergency Pause", "Anti-Whale Limit", "Hard Fee Cap (<=3%)"],
        "description": "Legitimate enterprise token featuring owner-controlled emergency circuit-breakers, hardcoded fee ceilings, and OpenZeppelin base.",
    },
    "ModerateCooldownToken": {
        "key": "ModerateCooldownToken",
        "name": "Anti-Bot Cooldown Token",
        "threatLevel": "MODERATE",
        "category": "Anti-Bot Mechanics",
        "file": "sample_moderate_cooldown_token.sol",
        "expectedScore": "30/100",
        "tags": ["Transfer Cooldown Delay", "Trading Enable Switch", "Anti-Whale 2%"],
        "description": "DeFi launch token enforcing anti-bot transfer timestamp cooldowns and launch trading enablement toggles.",
    },

    # 4. BENIGN THREAT LEVEL (Score 0 - 24)
    "SafeToken": {
        "key": "SafeToken",
        "name": "Safe Reference Token",
        "threatLevel": "BENIGN",
        "category": "Audited Standard",
        "file": "sample_safe_token.sol",
        "expectedScore": "0/100",
        "tags": ["OpenZeppelin Standard", "Hard Fee Cap (5%)", "Renounced Ownership", "Transparent Events"],
        "description": "Fully audited standard ERC-20 reference token with immutable 5% fee ceiling, renounced ownership, and symmetric trading.",
    },
    "BenignDeFiToken": {
        "key": "BenignDeFiToken",
        "name": "DeFi Zero-Fee Fixed Token",
        "threatLevel": "BENIGN",
        "category": "Zero-Risk Protocol",
        "file": "sample_benign_defi_token.sol",
        "expectedScore": "0/100",
        "tags": ["Zero Fees", "Fixed Supply", "Renounced Ownership", "Audited Base"],
        "description": "Zero-risk DeFi standard ERC-20 token with 100% fixed supply minted at construction, zero fees, and full ownership renunciation.",
    },
    "BenignCharityToken": {
        "key": "BenignCharityToken",
        "name": "Capped Charity Token",
        "threatLevel": "BENIGN",
        "category": "Community & Charity",
        "file": "sample_benign_charity_token.sol",
        "expectedScore": "0/100",
        "tags": ["Hard Fee Cap (3%)", "Transparent Treasury", "Renounceable", "Standard Events"],
        "description": "Community token with hardcoded 3% fee ceiling, dedicated transparent public good charity treasury, and standard events.",
    },
}


def get_samples_dict(filter_level: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve all samples or filtered by threat level, populated with code content."""
    res = {}
    for key, item in SAMPLE_CATALOG.items():
        if filter_level and item.get("threatLevel", "").upper() != filter_level.upper():
            continue
        p = SAMPLES_DIR / item["file"]
        code_content = p.read_text(encoding="utf-8") if p.exists() else ""
        res[key] = {
            **item,
            "code": code_content,
        }
    return res


def get_rules_catalog() -> List[Dict[str, Any]]:
    """Retrieve all static detection rules metadata."""
    from src.detection_rules import ALL_DETECTION_RULES
    return [
        {
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "category": r.category,
            "severity": r.severity.value,
            "confidence": r.confidence.value,
            "description": (r.__doc__ or "").strip(),
        }
        for r in ALL_DETECTION_RULES
    ]


# ---------------------------------------------------------------------------
# Core Analysis Pipeline Helper (Used by MERN Backend and Python REST API)
# ---------------------------------------------------------------------------
def execute_contract_audit(
    contract_input: str,
    input_type: str = "auto",
    network_name: str = "ethereum",
    simulate: bool = False,
) -> CompleteAuditReport:
    if isinstance(contract_input, dict):
        contract_input = json.dumps(contract_input)

    if input_type == "preset" or (isinstance(contract_input, str) and contract_input in SAMPLE_CATALOG):
        preset_info = SAMPLE_CATALOG.get(contract_input) if isinstance(contract_input, str) else None
        if preset_info:
            p = SAMPLES_DIR / preset_info["file"]
            code = p.read_text(encoding="utf-8") if p.exists() else ""
            contract = ContractLoader.load_from_source(code, name=preset_info["name"])
        else:
            contract = ContractLoader.load_auto(contract_input, network_name=network_name)
    elif input_type == "file":
        contract = ContractLoader.load_from_file(contract_input)
    elif input_type == "address":
        contract = ContractLoader.load_from_address(contract_input, network_name=network_name)
    elif input_type == "source_code":
        contract = ContractLoader.load_from_source(contract_input, name="DirectInputContract")
    else:
        contract = ContractLoader.load_auto(contract_input, network_name=network_name)

    if not contract or not contract.is_success:
        return CompleteAuditReport(contract=contract)

    # Static Analysis
    static_res: Optional[SourceAnalysisResult] = None
    if contract.has_source:
        analyzer = SourceAnalyzer()
        static_res = analyzer.analyze(contract.source_code, contract.name)

    # Risk Scoring
    risk_res: Optional[RiskReport] = None
    if static_res:
        scorer = RiskScorer()
        risk_res = scorer.calculate_risk(static_res.findings, static_res.positive_indicators)

    # Machine Learning Inference
    ml_dict: Optional[Dict[str, Any]] = None
    if contract.has_source:
        detector = MLDetector()
        ml_res = detector.predict_source(contract.source_code)
        ml_dict = ml_res.to_dict()

    # Simulation
    sim_res: Optional[SimulationResult] = None
    if simulate or contract.address:
        try:
            adapter = SimulationAdapter(provider="auto")
            sim_res = adapter.simulate(contract.address or contract.name, network=network_name)
        except Exception:
            pass

    return CompleteAuditReport(
        contract=contract,
        static_analysis=static_res,
        risk_report=risk_res,
        ml_prediction=ml_dict,
        simulation=sim_res,
    )


# ---------------------------------------------------------------------------
# Lightweight Standalone REST API Server Mode
# ---------------------------------------------------------------------------
def run_rest_api_server(port: int = 5000):
    """Start standard library HTTP REST bridge for MERN stack integration."""
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class HoneypotAPIHandler(BaseHTTPRequestHandler):
        def _send_cors_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

        def do_OPTIONS(self):
            self.send_response(200)
            self._send_cors_headers()
            self.end_headers()

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            self._send_cors_headers()

            if parsed.path == "/api/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                res = {"status": "healthy", "service": "EVM Honeypot Detector Python API"}
                self.wfile.write(json.dumps(res).encode("utf-8"))
                return

            if parsed.path == "/api/networks":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                networks = {k: {"name": v.name, "chain_id": v.chain_id} for k, v in SUPPORTED_NETWORKS.items()}
                self.wfile.write(json.dumps(networks).encode("utf-8"))
                return

            if parsed.path == "/api/samples":
                query_params = urllib.parse.parse_qs(parsed.query)
                filter_level = query_params.get("level", [None])[0]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                samples = get_samples_dict(filter_level=filter_level)
                self.wfile.write(json.dumps(samples).encode("utf-8"))
                return

            if parsed.path == "/api/rules":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                rules = get_rules_catalog()
                self.wfile.write(json.dumps(rules).encode("utf-8"))
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            self._send_cors_headers()

            if parsed.path == "/api/analyze":
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8")
                try:
                    payload = json.loads(body) if body else {}
                except Exception:
                    payload = {}

                code = payload.get("code", "")
                address = payload.get("address", "")
                preset = payload.get("preset", "")
                network = payload.get("network", "ethereum")
                simulate = bool(payload.get("simulate", False))

                if preset and not code and preset in SAMPLE_CATALOG:
                    target_input = preset
                    mode = "preset"
                else:
                    target_input = address if address else code
                    mode = "address" if address else "source_code"

                report = execute_contract_audit(
                    contract_input=target_input,
                    input_type=mode,
                    network_name=network,
                    simulate=simulate,
                )

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(report.to_json().encode("utf-8"))
                return

            if parsed.path == "/api/train-ml":
                from ml.train_model import train_and_save_all_models
                res = train_and_save_all_models()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(res).encode("utf-8"))
                return

            self.send_response(404)
            self.end_headers()

    server = HTTPServer(("0.0.0.0", port), HoneypotAPIHandler)
    print(f"[+] Python API Bridge Server listening on http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[!] Stopping Python API server...")
        server.server_close()


if __name__ == "__main__":
    port = 5001
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
    print(f"[+] Starting EVM Honeypot Detector Python REST API bridge on http://localhost:{port}")
    run_rest_api_server(port=port)
