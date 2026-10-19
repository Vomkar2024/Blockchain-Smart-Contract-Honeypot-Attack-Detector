"""Feature extraction module converting smart contract source code into machine learning feature vectors."""

import re
from typing import Dict, Any, List, Optional, Union
import pandas as pd

from src.source_analyzer import SourceAnalyzer


FEATURE_NAMES: List[str] = [
    "lines_of_code",
    "num_functions",
    "num_modifiers",
    "has_transfer_function",
    "has_owner_control",
    "has_blacklist_mapping",
    "has_sell_restriction_logic",
    "has_excessive_fee",
    "has_unbounded_fee_setter",
    "has_cooldown_delay",
    "has_pausable_transfers",
    "has_max_tx_wallet_limit",
    "has_hidden_mint",
    "has_inline_assembly",
    "has_external_transfer_call",
    "num_positive_indicators",
    "has_openzeppelin_imports",
    "has_renounce_ownership",
    "num_total_findings",
]

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "lines_of_code": "Total non-blank, non-comment lines of Solidity code",
    "num_functions": "Total parsed contract functions",
    "num_modifiers": "Total parsed custom function modifiers",
    "has_transfer_function": "Whether contract defines ERC-20 transfer/transferFrom logic (0/1)",
    "has_owner_control": "Whether contract uses administrative access control (0/1)",
    "has_blacklist_mapping": "Whether blacklist mapping or recipient filter is detected (0/1)",
    "has_sell_restriction_logic": "Whether asymmetric DEX sell restriction logic is detected (0/1)",
    "has_excessive_fee": "Whether excessive transfer/sell fee >= 25% is detected (0/1)",
    "has_unbounded_fee_setter": "Whether admin can set fee without upper ceiling constraint (0/1)",
    "has_cooldown_delay": "Whether trading cooldown or anti-bot lockup timers exist (0/1)",
    "has_pausable_transfers": "Whether token transfers can be halted or paused by owner (0/1)",
    "has_max_tx_wallet_limit": "Whether restrictive max transaction/wallet limits exist (0/1)",
    "has_hidden_mint": "Whether unconstrained minting capability exists outside constructor (0/1)",
    "has_inline_assembly": "Whether inline assembly blocks or delegatecalls are present (0/1)",
    "has_external_transfer_call": "Whether external contracts/oracles are called in transfer path (0/1)",
    "num_positive_indicators": "Total positive security indicators identified",
    "has_openzeppelin_imports": "Whether contract imports standard OpenZeppelin contracts (0/1)",
    "has_renounce_ownership": "Whether ownership renunciation capability is provided (0/1)",
    "num_total_findings": "Total suspicious static analysis findings detected",
}


def get_default_features() -> Dict[str, Union[int, float]]:
    """Return zero-initialized feature dictionary."""
    return {name: 0 for name in FEATURE_NAMES}


class FeatureExtractor:
    """
    Translates Solidity source code and parsed contract representations
    into normalized numeric feature vectors suitable for scikit-learn ML models.
    """

    def __init__(self, analyzer: Optional[SourceAnalyzer] = None):
        self.analyzer = analyzer or SourceAnalyzer()

    def extract_features_from_source(self, raw_source: Optional[str]) -> Dict[str, Union[int, float]]:
        """
        Extract a structured feature dictionary from raw Solidity source code.
        Safely handles empty, None, or unparseable source code by returning default features.
        """
        if not raw_source or not isinstance(raw_source, str) or not raw_source.strip():
            return get_default_features()

        try:
            analysis = self.analyzer.analyze(raw_source, source_name="FeatureExtraction")
            struct = analysis.contract_structure
            findings = analysis.findings
            positive = analysis.positive_indicators

            rule_ids = {f.rule_id for f in findings}

            features: Dict[str, Union[int, float]] = {
                "lines_of_code": int(struct.lines_of_code),
                "num_functions": int(len(struct.functions)),
                "num_modifiers": int(len(struct.modifiers)),
                "has_transfer_function": 1 if struct.has_transfer_function else 0,
                "has_owner_control": 1 if struct.has_owner_control else 0,
                "has_blacklist_mapping": 1 if "HONEYPOT_BLACKLIST" in rule_ids else 0,
                "has_sell_restriction_logic": 1 if "HONEYPOT_SELL_RESTRICTION" in rule_ids else 0,
                "has_excessive_fee": 1 if "HONEYPOT_EXCESSIVE_SELL_TAX" in rule_ids else 0,
                "has_unbounded_fee_setter": 1 if "HONEYPOT_UNLIMITED_OWNER_TAX" in rule_ids else 0,
                "has_cooldown_delay": 1 if "HONEYPOT_TRADING_COOLDOWN_DELAY" in rule_ids else 0,
                "has_pausable_transfers": 1 if "HONEYPOT_PAUSABLE_TRANSFERS" in rule_ids else 0,
                "has_max_tx_wallet_limit": 1 if "HONEYPOT_MAX_WALLET_TX_LIMIT" in rule_ids else 0,
                "has_hidden_mint": 1 if "HONEYPOT_HIDDEN_MINT" in rule_ids else 0,
                "has_inline_assembly": 1 if "HONEYPOT_SUSPICIOUS_ASSEMBLY" in rule_ids else 0,
                "has_external_transfer_call": 1 if "HONEYPOT_EXTERNAL_RESTRICTION_CALL" in rule_ids else 0,
                "num_positive_indicators": int(len(positive)),
                "has_openzeppelin_imports": 1 if any(p.indicator_id == "POS_OPENZEPPELIN_STANDARD" for p in positive) else 0,
                "has_renounce_ownership": 1 if any(p.indicator_id == "POS_RENOUNCE_OWNERSHIP" for p in positive) else 0,
                "num_total_findings": int(len(findings)),
            }

            return features

        except Exception:
            # Fallback defensively if AST parsing fails unexpectedly
            return get_default_features()

    def extract_feature_vector(self, raw_source: Optional[str]) -> List[float]:
        """Return numeric features in ordered list matching FEATURE_NAMES."""
        feat_dict = self.extract_features_from_source(raw_source)
        return [float(feat_dict.get(name, 0)) for name in FEATURE_NAMES]

    def extract_from_contract(self, contract: Any) -> Dict[str, Union[int, float]]:
        """
        Extract features from a LoadedContract instance (from src.contract_loader)
        or any object with a `source_code` attribute.
        """
        if hasattr(contract, "source_code") and contract.source_code:
            return self.extract_features_from_source(contract.source_code)

        # If only bytecode or metadata is available without source
        default_feats = get_default_features()
        if hasattr(contract, "bytecode") and contract.bytecode:
            clean_bc = contract.bytecode.replace("0x", "")
            default_feats["lines_of_code"] = max(1, len(clean_bc) // 100)
        return default_feats

    def extract_dataframe(
        self,
        sources_or_contracts: List[Any],
        include_metadata: bool = False,
    ) -> pd.DataFrame:
        """
        Extract features from a batch of source strings or contracts into a pandas DataFrame.
        Columns are guaranteed to match FEATURE_NAMES in exact order.
        """
        rows: List[Dict[str, Any]] = []
        for idx, item in enumerate(sources_or_contracts):
            if isinstance(item, str):
                feats = self.extract_features_from_source(item)
                if include_metadata:
                    feats = {"contract_index": idx, **feats}
            elif hasattr(item, "source_code"):
                feats = self.extract_from_contract(item)
                if include_metadata:
                    meta = {
                        "contract_index": idx,
                        "contract_name": getattr(item, "name", f"Contract_{idx}"),
                        "contract_address": getattr(item, "address", ""),
                    }
                    feats = {**meta, **feats}
            else:
                feats = get_default_features()
                if include_metadata:
                    feats = {"contract_index": idx, **feats}
            rows.append(feats)

        df = pd.DataFrame(rows)
        # Ensure column ordering
        if not include_metadata:
            df = df.reindex(columns=FEATURE_NAMES, fill_value=0)
        return df

    @staticmethod
    def get_feature_names() -> List[str]:
        """Return the canonical list of ML feature names."""
        return list(FEATURE_NAMES)
