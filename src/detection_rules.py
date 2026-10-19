"""Modular Honeypot Detection Rules and Security Indicators."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """Represents a suspicious security finding in the smart contract."""
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    confidence: Confidence
    line_number: Optional[int]
    evidence: str
    explanation: str
    suggested_verification: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "suggested_verification": self.suggested_verification,
        }


@dataclass
class PositiveIndicator:
    """Represents a benign or safety-enhancing characteristic in the contract."""
    indicator_id: str
    name: str
    evidence: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "name": self.name,
            "evidence": self.evidence,
            "explanation": self.explanation,
        }


class BaseRule:
    """Base interface for all honeypot detection rules."""
    rule_id: str = "BASE_RULE"
    rule_name: str = "Base Detection Rule"
    category: str = "General"
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        """
        Analyze the Solidity source code and return a list of findings.
        clean_source: source code with comments stripped (line numbers preserved)
        raw_source: original raw source code including comments and formatting
        """
        raise NotImplementedError("Subclasses must implement evaluate()")


# -------------------------------------------------------------------------
# Detection Rules
# -------------------------------------------------------------------------

class BlacklistLogicRule(BaseRule):
    """Detects address blacklisting logic, address checks, and modifier traps that can block token holders from transferring or selling."""
    rule_id = "HONEYPOT_BLACKLIST"
    rule_name = "Arbitrary Address Blacklist Mechanism"
    category = "Access Control & Transfer Restrictions"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        # 1. Blacklist mapping declarations
        blacklist_map_pattern = re.compile(
            r"mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*(?:private|public|internal)?\s*.*?(isBlacklist|blackList|isBot|bots|_isBlacklisted|_isBot|sniper|isBlocked)",
            re.IGNORECASE
        )

        # 2. Direct address check / revert statements
        address_check_pattern = re.compile(
            r"(?:require\s*\(\s*!(?:_?isBlacklisted|blackList|_?isBot|bots|isBlocked)\[(?:from|sender|to|account|recipient)\])|"
            r"(?:if\s*\(\s*(?:_?isBlacklisted|blackList|_?isBot|bots)\[(?:from|sender|to|account)\]\s*(?:==\s*true)?\s*\)\s*revert)",
            re.IGNORECASE
        )

        # 3. Modifier traps
        modifier_trap_pattern = re.compile(
            r"modifier\s+(?:notBlacklisted|onlyNonBlacklisted|notBot|isNotBlacklisted|checkBlacklist|antiBot)\b",
            re.IGNORECASE
        )

        # Check if there is an owner-settable function for blacklisting
        has_setter = bool(re.search(
            r"function\s+(?:setBlacklist|blacklist|setBot|addBot|setSniper|blockAddress|setBlacklistedAddress)",
            clean_source,
            re.IGNORECASE
        ))

        for idx, line in enumerate(lines, start=1):
            if blacklist_map_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    category=self.category,
                    severity=Severity.CRITICAL if has_setter else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Contract declares an address blacklist or bot mapping. "
                        "If controlled by the owner, buyers can be selectively trapped and prevented from selling."
                    ),
                    suggested_verification=(
                        "Verify whether addresses can be blacklisted arbitrarily post-launch and whether ownership is renounced."
                    ),
                ))
            elif address_check_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name="Blacklist Address Check Trap",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Direct address blacklist check detected in transfer execution path. "
                        "Transactions from flagged wallets will be reverted."
                    ),
                    suggested_verification="Audit which addresses are flagged and how the mapping is populated.",
                ))
            elif modifier_trap_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name="Blacklist Modifier Trap",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Modifier trap detected that gates execution on non-blacklisted status. "
                        "When attached to transfer functions, blacklisted users cannot execute transactions."
                    ),
                    suggested_verification="Check modifier implementation and who has authority to toggle blacklist status.",
                ))

        return findings


class AsymmetricSellRestrictionRule(BaseRule):
    """Detects transfer conditions that selectively restrict selling to DEX liquidity pools."""
    rule_id = "HONEYPOT_SELL_RESTRICTION"
    rule_name = "Asymmetric Sell / DEX Transfer Restriction"
    category = "Trading Restrictions"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        # Patterns checking if recipient is liquidity pair/router and applying restrictions
        sell_check_pattern = re.compile(
            r"(?:if\s*\(\s*(?:to|recipient)\s*==\s*(?:uniswapV2Pair|automatedMarketMakerPairs|dexPair|pair|pancakePair|router|_uniswapV2Pair))|"
            r"(?:automatedMarketMakerPairs\[(?:to|recipient)\])|"
            r"(?:require\s*\(\s*!(?:isSell|sellingRestricted|onlyBuy)\b)|"
            r"(?:require\s*\(\s*(?:isWhitelisted|canSell|allowedToSell)\[(?:sender|from)\])|"
            r"(?:if\s*\(\s*(?:isSell|to\s*==\s*pair).*(?:revert|require))",
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, start=1):
            if sell_check_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Detected conditional logic specifically targeting sell transactions (e.g. transfers to DEX pairs). "
                        "Honeypots use this pattern to allow token purchases while causing sell transactions to revert."
                    ),
                    suggested_verification=(
                        "Inspect the transfer logic to confirm if ordinary holders can transfer to Uniswap/PancakeSwap pairs, "
                        "or if only whitelisted/owner wallets are permitted to sell."
                    ),
                ))

        return findings


class ExcessiveSellTaxRule(BaseRule):
    """Detects hardcoded or dynamic tax rates that exceed normal trading levels (>= 25%)."""
    rule_id = "HONEYPOT_EXCESSIVE_SELL_TAX"
    rule_name = "Excessive or Confiscatory Sell Tax"
    category = "Fee Manipulation"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        # Check for hardcoded fees >= 25% or 99-100%
        fee_assign_pattern = re.compile(
            r"(?:_?sellFee|_?sellTax|_?totalSellFee|_?taxFee|_?liquidityFee|_?transferFee|_?fee|_?tax)\s*=\s*(\d+)\s*;",
            re.IGNORECASE
        )
        fee_math_pattern = re.compile(
            r"(?:\*\s*(\d{2,3})\s*\)?\s*\/\s*100|\*\s*(\d{4,5})\s*\)?\s*\/\s*10000)",
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, start=1):
            match = fee_assign_pattern.search(line)
            if match:
                fee_val = int(match.group(1))
                # Distinguish basis points (e.g. 2500 = 25%) vs percentage (e.g. 25 = 25%)
                is_excessive = (25 <= fee_val <= 100) or (2500 <= fee_val <= 10000)
                if is_excessive:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        category=self.category,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        line_number=idx,
                        evidence=line.strip(),
                        explanation=(
                            f"Hardcoded fee value ({fee_val}) is set to an excessive level (>= 25%), "
                            "effectively siphoning most or all funds during token transfers."
                        ),
                        suggested_verification=(
                            "Examine whether fees are calculated as percentage or basis points, "
                            "and whether tokens are burned or redirected to an owner wallet."
                        ),
                    ))
            else:
                math_match = fee_math_pattern.search(line)
                if math_match:
                    pct = int(math_match.group(1)) if math_match.group(1) else int(math_match.group(2)) // 100
                    if 25 <= pct <= 100 and ("fee" in line.lower() or "tax" in line.lower() or "amount" in line.lower()):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            category=self.category,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            line_number=idx,
                            evidence=line.strip(),
                            explanation=(
                                f"Direct fee computation applies excessive tax rate ({pct}%), "
                                "confiscating user funds during transfer or sell transactions."
                            ),
                            suggested_verification="Inspect how calculated tax amounts are distributed or burned.",
                        ))

        return findings


class UnlimitedOwnerTaxRule(BaseRule):
    """Detects fee setter functions without an upper bound limit check (sanity cap)."""
    rule_id = "HONEYPOT_UNLIMITED_OWNER_TAX"
    rule_name = "Unbounded Owner Fee Setter"
    category = "Fee Manipulation"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        fee_func_pattern = re.compile(
            r"function\s+(?:setSellTax|setBuyTax|setFees|setTaxFee|updateFees|setSellFee|setFee|setTax|changeFees|setTransactionFee)\s*\([^)]*\)",
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, start=1):
            if fee_func_pattern.search(line):
                # Look ahead up to 15 lines to see if there is a require(fee <= MAX)
                function_block = "\n".join(lines[idx - 1: min(idx + 15, len(lines))])
                has_cap = bool(re.search(
                    r"require\s*\(\s*.*?(?:(?:<=|<)\s*(?:[1-9]|[12][0-9]|30|MAX_FEE|MAX_TAX|MAX_SELL_TAX|\d{3,4})\b|(?:MAX_FEE|MAX_TAX)\s*(?:>=|>))",
                    function_block,
                    re.IGNORECASE
                ))

                if not has_cap:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        line_number=idx,
                        evidence=line.strip(),
                        explanation=(
                            "Owner has a function to alter buy/sell fees without a hardcoded maximum ceiling (e.g. require(fee <= 25)). "
                            "A malicious owner can raise fees to 100% after investors purchase tokens."
                        ),
                        suggested_verification=(
                            "Verify if the fee update function contains a sanity check ceiling or timelock."
                        ),
                    ))

        return findings


class TradingCooldownDelayRule(BaseRule):
    """Detects transfer delay timers or cooldown blocks that can freeze selling."""
    rule_id = "HONEYPOT_TRADING_COOLDOWN_DELAY"
    rule_name = "Transfer Delay or Trading Cooldown Lockup"
    category = "Trading Restrictions"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        cooldown_pattern = re.compile(
            r"(?:_holderLastTransferTimestamp|cooldownTimer|tradingDelay|transferDelayEnabled)",
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, start=1):
            if cooldown_pattern.search(line) and ("mapping" in line or "bool" in line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Contract enforces transfer timestamps or cooldown blocks between transactions. "
                        "While sometimes used for anti-bot protection, attackers can modify the delay to trap funds."
                    ),
                    suggested_verification=(
                        "Inspect whether the cooldown period has an immutable upper bound (e.g. max 1 minute)."
                    ),
                ))
                break

        return findings


class PausableTransfersRule(BaseRule):
    """Detects owner-controlled transfer pause mechanisms that can freeze liquidity."""
    rule_id = "HONEYPOT_PAUSABLE_TRANSFERS"
    rule_name = "Owner-Controlled Pausable Transfers"
    category = "Access Control & Transfer Restrictions"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        pause_pattern = re.compile(
            r"(?:function\s+(?:pause|setTradingEnabled|enableTrading|setPaused)\s*\([^)]*\))|"
            r"(?:bool\s+(?:public|private|internal)?\s*(?:tradingEnabled|paused)\s*;)",
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, start=1):
            if pause_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Contract implements a transfer pause toggle or trading-enable flag. "
                        "If the owner retains rights to pause transfers or turn off trading indefinitely, sellers can be locked out."
                    ),
                    suggested_verification=(
                        "Verify whether trading can only be enabled once and cannot be re-paused by the owner."
                    ),
                ))
                break

        return findings


class MaxWalletTxLimitRule(BaseRule):
    """Detects micro-limits on transaction or wallet amounts that prevent liquidating tokens."""
    rule_id = "HONEYPOT_MAX_WALLET_TX_LIMIT"
    rule_name = "Restrictive Transaction or Wallet Limit"
    category = "Trading Restrictions"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        limit_pattern = re.compile(
            r"(?:maxTxAmount|maxWalletAmount|_maxTxAmount|_maxWalletSize)\s*=",
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, start=1):
            if limit_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Contract configures maximum transaction or maximum wallet limits. "
                        "If configured to tiny amounts, users may be prevented from selling their full balance."
                    ),
                    suggested_verification=(
                        "Verify minimum limits (e.g. at least 0.5% or 1% of total supply) and whether the owner can lower them."
                    ),
                ))
                break

        return findings


class HiddenMintPrivilegeRule(BaseRule):
    """Detects hidden or unconstrained token minting capability outside constructor."""
    rule_id = "HONEYPOT_HIDDEN_MINT"
    rule_name = "Privileged Unconstrained Minting"
    category = "Supply Manipulation"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        mint_pattern = re.compile(
            r"function\s+(?:mint|_mintToken|generateToken)\s*\([^)]*\)\s*(?:external|public)",
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, start=1):
            if mint_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Contract exposes a public/external minting function. "
                        "An owner can arbitrarily mint tokens, diluting investor value to zero and dumping on DEX pools."
                    ),
                    suggested_verification=(
                        "Check if minting is capped by a maximum supply limit or if ownership is fully renounced."
                    ),
                ))

        return findings


class SuspiciousAssemblyRule(BaseRule):
    """Detects inline assembly blocks or delegatecalls within transfer paths."""
    rule_id = "HONEYPOT_SUSPICIOUS_ASSEMBLY"
    rule_name = "Inline Assembly or Delegatecall in Transfer Logic"
    category = "Code Obfuscation & Low-Level Calls"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        assembly_pattern = re.compile(r"\bassembly\s*\{", re.IGNORECASE)
        delegatecall_pattern = re.compile(r"\.delegatecall\s*\(", re.IGNORECASE)

        for idx, line in enumerate(lines, start=1):
            if assembly_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Inline assembly block detected. Malicious contracts frequently use assembly to obscure "
                        "storage manipulation, evade AST scanners, or bypass standard ERC-20 invariants."
                    ),
                    suggested_verification=(
                        "Audit the assembly instructions to verify memory/storage offsets and ensure no hidden state mutation."
                    ),
                ))
            elif delegatecall_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name="Unsafe Delegatecall Execution",
                    category=self.category,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Delegatecall detected. This permits an external contract to execute code in the context of the token contract, "
                        "allowing full takeover or fund drainage."
                    ),
                    suggested_verification=(
                        "Ensure the target address is strictly immutable and verified."
                    ),
                ))

        return findings


class ExternalRestrictionCallRule(BaseRule):
    """Detects external contract calls during transfer logic that can trigger reverts on sells."""
    rule_id = "HONEYPOT_EXTERNAL_RESTRICTION_CALL"
    rule_name = "External Oracle / Permission Call in Transfer"
    category = "External Dependencies"
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM

    def evaluate(self, clean_source: str, raw_source: str) -> List[Finding]:
        findings = []
        lines = clean_source.splitlines()

        external_call_pattern = re.compile(
            r"(?:I(?:TokenFilter|BotChecker|Whitelist|SecurityOracle|TradingService|AntiBot)\s*\([^)]*\)\s*\.\s*(?:canTransfer|isAllowed|verifyTransfer|checkTransfer|validateTransfer))|"
            r"(?:(?:filter|oracle|botChecker|securityContract|transferFilter)\s*\.\s*(?:canTransfer|isAllowed|verifyTransfer|checkTransfer|validateTransfer))|"
            r"(?:call\s*\(abi\.encodeWith(?:Signature|Selector)\s*\(\s*[\"'](?:check|verify|canTransfer|isAllowed|validate))",
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, start=1):
            if external_call_pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    line_number=idx,
                    evidence=line.strip(),
                    explanation=(
                        "Transfer logic delegates authorization to an external unverified contract or oracle. "
                        "The external contract can return false or revert on sell attempts while returning true for buys."
                    ),
                    suggested_verification=(
                        "Inspect the source code of the external authorization contract."
                    ),
                ))

        return findings


# -------------------------------------------------------------------------
# Positive Indicators
# -------------------------------------------------------------------------

def check_positive_indicators(clean_source: str) -> List[PositiveIndicator]:
    """Identifies standard security best-practices and transparency features."""
    indicators = []

    # 1. OpenZeppelin standard library usage
    if re.search(r"@openzeppelin/contracts|OpenZeppelin", clean_source, re.IGNORECASE):
        indicators.append(PositiveIndicator(
            indicator_id="POS_OPENZEPPELIN_STANDARD",
            name="OpenZeppelin Standard Implementation",
            evidence="Imports or implements audited OpenZeppelin ERC-20 base contracts.",
            explanation="Adheres to industry standard audited contracts, reducing probability of custom backdoors."
        ))

    # 2. Renounce ownership support
    if re.search(r"function\s+renounceOwnership\s*\(\s*\)", clean_source, re.IGNORECASE):
        indicators.append(PositiveIndicator(
            indicator_id="POS_RENOUNCE_OWNERSHIP",
            name="Ownership Renunciation Capability",
            evidence="Contract includes standard renounceOwnership() function.",
            explanation="Provides the ability for the deployer to relinquish administrative control permanently."
        ))

    # 3. Explicit fee ceilings
    if re.search(r"require\s*\(\s*(?:newSellFee|newTax|totalFee|fee)\s*<=\s*(?:10|15|20|25|1000|2500)", clean_source):
        indicators.append(PositiveIndicator(
            indicator_id="POS_HARD_FEE_CAP",
            name="Hardcoded Fee Ceiling",
            evidence="Explicit require check enforces maximum tax limit (<= 25%).",
            explanation="Prevents the owner from dynamically hiking taxes to confiscatory levels (100%)."
        ))

    # 4. Standard events emitted
    if "emit Transfer(" in clean_source and "emit Approval(" in clean_source:
        indicators.append(PositiveIndicator(
            indicator_id="POS_STANDARD_EVENTS",
            name="Standard ERC-20 Events Emitted",
            evidence="Emits both Transfer and Approval events.",
            explanation="Ensures off-chain indexers and DEX routers can reliably track token state."
        ))

    return indicators


# Registry of all default detection rules
ALL_DETECTION_RULES: List[BaseRule] = [
    BlacklistLogicRule(),
    AsymmetricSellRestrictionRule(),
    ExcessiveSellTaxRule(),
    UnlimitedOwnerTaxRule(),
    TradingCooldownDelayRule(),
    PausableTransfersRule(),
    MaxWalletTxLimitRule(),
    HiddenMintPrivilegeRule(),
    SuspiciousAssemblyRule(),
    ExternalRestrictionCallRule(),
]
