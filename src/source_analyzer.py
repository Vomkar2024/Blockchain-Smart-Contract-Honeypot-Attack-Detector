"""Solidity source code static analysis engine."""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from src.utils import sanitize_source_code, strip_comments
from src.detection_rules import (
    ALL_DETECTION_RULES,
    BaseRule,
    Finding,
    PositiveIndicator,
    check_positive_indicators,
)


@dataclass
class ContractStructure:
    """Extracted structural metadata from a Solidity contract."""
    name: str
    pragma: str
    inheritance: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
    has_transfer_function: bool = False
    has_owner_control: bool = False
    lines_of_code: int = 0


@dataclass
class SourceAnalysisResult:
    """Complete output of the source code static analysis."""
    source_name: str
    contract_structure: ContractStructure
    findings: List[Finding]
    positive_indicators: List[PositiveIndicator]
    timestamp: str
    is_valid_solidity: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "contract_name": self.contract_structure.name,
            "pragma": self.contract_structure.pragma,
            "lines_of_code": self.contract_structure.lines_of_code,
            "inheritance": self.contract_structure.inheritance,
            "has_transfer_function": self.contract_structure.has_transfer_function,
            "has_owner_control": self.contract_structure.has_owner_control,
            "functions": self.contract_structure.functions,
            "findings": [f.to_dict() for f in self.findings],
            "positive_indicators": [p.to_dict() for p in self.positive_indicators],
            "timestamp": self.timestamp,
            "is_valid_solidity": self.is_valid_solidity,
            "error_message": self.error_message,
        }


class SourceAnalyzer:
    """
    Static analyzer for Solidity source code that inspects contract structure
    and runs configurable honeypot detection rules.
    """

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self.rules = rules if rules is not None else ALL_DETECTION_RULES

    def extract_structure(self, clean_source: str, raw_source: str) -> ContractStructure:
        """Parse key architectural components of the contract."""
        lines = raw_source.splitlines()
        loc = len([line for line in lines if line.strip() and not line.strip().startswith("//")])

        # Pragma version
        pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", clean_source)
        pragma = pragma_match.group(1).strip() if pragma_match else "unknown"

        # Main contract name & inheritance
        # Look for the last contract definition (typically the deployed token implementation)
        contract_matches = list(re.finditer(
            r"\bcontract\s+([A-Za-z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{",
            clean_source
        ))

        contract_name = "UnknownContract"
        inheritance = []

        if contract_matches:
            last_match = contract_matches[-1]
            contract_name = last_match.group(1)
            if last_match.group(2):
                inheritance = [
                    parent.strip()
                    for parent in last_match.group(2).split(",")
                    if parent.strip()
                ]

        # Extract function names
        functions = re.findall(r"\bfunction\s+([A-Za-z0-9_]+)\s*\(", clean_source)
        modifiers = re.findall(r"\bmodifier\s+([A-Za-z0-9_]+)\s*\(", clean_source)

        # Check for transfer function
        has_transfer = any(
            fn in ("transfer", "_transfer", "transferFrom", "_transferFrom")
            for fn in functions
        )

        # Check for owner control (Ownable pattern, onlyOwner, _owner)
        has_owner = bool(
            "onlyOwner" in clean_source
            or "Ownable" in inheritance
            or re.search(r"\baddress\s+(?:private|public|internal)?\s*(?:_?owner)\b", clean_source)
        )

        # State variable names (heuristics)
        state_vars = re.findall(
            r"\b(?:uint256|uint|bool|address|string|mapping\([^)]+\))\s+(?:public|private|internal)?\s+([A-Za-z0-9_]+)\s*[;=]",
            clean_source
        )

        return ContractStructure(
            name=contract_name,
            pragma=pragma,
            inheritance=inheritance,
            functions=list(set(functions)),
            modifiers=list(set(modifiers)),
            state_variables=list(set(state_vars)),
            has_transfer_function=has_transfer,
            has_owner_control=has_owner,
            lines_of_code=loc,
        )

    def analyze(self, raw_source: str, source_name: str = "UnknownSource") -> SourceAnalysisResult:
        """
        Execute full static analysis on Solidity source code.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        if not raw_source or not raw_source.strip():
            return SourceAnalysisResult(
                source_name=source_name,
                contract_structure=ContractStructure(name="Empty", pragma="unknown"),
                findings=[],
                positive_indicators=[],
                timestamp=now_iso,
                is_valid_solidity=False,
                error_message="Source code is empty or contains only whitespace.",
            )

        sanitized_raw = sanitize_source_code(raw_source)
        clean_source = strip_comments(sanitized_raw)

        # Basic validity check: must contain 'contract' or 'pragma solidity' or 'interface'
        is_solidity = bool(
            re.search(r"\b(?:contract|library|interface|pragma\s+solidity)\b", clean_source)
        )
        if not is_solidity:
            return SourceAnalysisResult(
                source_name=source_name,
                contract_structure=ContractStructure(name="Invalid", pragma="unknown"),
                findings=[],
                positive_indicators=[],
                timestamp=now_iso,
                is_valid_solidity=False,
                error_message="Provided text does not appear to be valid Solidity code (missing contract/pragma/interface).",
            )

        structure = self.extract_structure(clean_source, sanitized_raw)

        # Evaluate all detection rules
        all_findings: List[Finding] = []
        for rule in self.rules:
            try:
                rule_findings = rule.evaluate(clean_source, sanitized_raw)
                all_findings.extend(rule_findings)
            except Exception as e:
                # Log error or add informational finding
                all_findings.append(Finding(
                    rule_id=f"{rule.rule_id}_ERROR",
                    rule_name=f"{rule.rule_name} (Evaluation Error)",
                    category="Engine Error",
                    severity=rule.severity,
                    confidence=rule.confidence,
                    line_number=None,
                    evidence=f"Error evaluating rule: {str(e)}",
                    explanation="Rule evaluation encountered an unexpected parsing exception.",
                    suggested_verification="Review rule parser.",
                ))

        # Check positive indicators
        positive_indicators = check_positive_indicators(clean_source)

        return SourceAnalysisResult(
            source_name=source_name,
            contract_structure=structure,
            findings=all_findings,
            positive_indicators=positive_indicators,
            timestamp=now_iso,
            is_valid_solidity=True,
            error_message=None,
        )
