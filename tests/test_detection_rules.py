"""Comprehensive unit tests for Honeypot Detection Rules and Security Indicators."""

import unittest

from src.detection_rules import (
    Severity,
    Confidence,
    Finding,
    PositiveIndicator,
    BaseRule,
    ALL_DETECTION_RULES,
    BlacklistLogicRule,
    AsymmetricSellRestrictionRule,
    ExcessiveSellTaxRule,
    UnlimitedOwnerTaxRule,
    TradingCooldownDelayRule,
    PausableTransfersRule,
    MaxWalletTxLimitRule,
    HiddenMintPrivilegeRule,
    SuspiciousAssemblyRule,
    ExternalRestrictionCallRule,
    check_positive_indicators,
)


class TestDetectionRuleStructures(unittest.TestCase):
    """Tests for base structures, enums, and dataclasses."""

    def test_enums(self):
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.LOW.value, "LOW")
        self.assertEqual(Severity.INFORMATIONAL.value, "INFORMATIONAL")

        self.assertEqual(Confidence.HIGH.value, "HIGH")
        self.assertEqual(Confidence.MEDIUM.value, "MEDIUM")
        self.assertEqual(Confidence.LOW.value, "LOW")

    def test_finding_to_dict(self):
        f = Finding(
            rule_id="TEST_ID",
            rule_name="Test Rule",
            category="Security",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            line_number=42,
            evidence="uint256 x = 1;",
            explanation="Explanation text",
            suggested_verification="Manual check",
        )
        d = f.to_dict()
        self.assertEqual(d["rule_id"], "TEST_ID")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["confidence"], "HIGH")
        self.assertEqual(d["line_number"], 42)
        self.assertEqual(d["evidence"], "uint256 x = 1;")

    def test_positive_indicator_to_dict(self):
        p = PositiveIndicator(
            indicator_id="POS_TEST",
            name="Positive Safety Test",
            evidence="code evidence",
            explanation="Safety explanation",
        )
        d = p.to_dict()
        self.assertEqual(d["indicator_id"], "POS_TEST")
        self.assertEqual(d["name"], "Positive Safety Test")

    def test_base_rule_raises(self):
        class IncompleteRule(BaseRule):
            pass

        rule = IncompleteRule()
        with self.assertRaises(NotImplementedError):
            rule.evaluate("code", "code")

    def test_all_detection_rules_registry(self):
        self.assertEqual(len(ALL_DETECTION_RULES), 10)
        rule_ids = [r.rule_id for r in ALL_DETECTION_RULES]
        self.assertEqual(len(rule_ids), len(set(rule_ids)), "All rule IDs must be unique.")


class TestIndividualDetectionRules(unittest.TestCase):
    """Verifies that each detection rule identifies target vulnerability patterns and ignores benign code."""

    def test_blacklist_logic_rule(self):
        rule = BlacklistLogicRule()
        code_with_blacklist = """
        contract Honeypot {
            mapping(address => bool) private _isBlacklisted;
            function _transfer(address from, address to, uint256 amount) internal {
                require(!_isBlacklisted[from], "Address is blacklisted");
            }
        }
        """
        findings = rule.evaluate(code_with_blacklist, code_with_blacklist)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_BLACKLIST" for f in findings))

        clean_code = "contract Clean { mapping(address => uint256) public balances; }"
        self.assertEqual(len(rule.evaluate(clean_code, clean_code)), 0)

    def test_asymmetric_sell_restriction_rule(self):
        rule = AsymmetricSellRestrictionRule()
        code_with_sell_trap = """
        contract Honeypot {
            address public uniswapV2Pair;
            function _transfer(address from, address to, uint256 amount) internal {
                if (to == uniswapV2Pair) {
                    revert("Sells are temporarily blocked");
                }
            }
        }
        """
        findings = rule.evaluate(code_with_sell_trap, code_with_sell_trap)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_SELL_RESTRICTION" for f in findings))

    def test_excessive_sell_tax_rule(self):
        rule = ExcessiveSellTaxRule()
        code_with_high_tax = """
        contract Honeypot {
            uint256 public sellTax = 99;
            function setFees() public {
                uint256 feeAmount = (amount * 90) / 100;
            }
        }
        """
        findings = rule.evaluate(code_with_high_tax, code_with_high_tax)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_EXCESSIVE_SELL_TAX" for f in findings))

    def test_unlimited_owner_tax_rule(self):
        rule = UnlimitedOwnerTaxRule()
        code_with_unbounded_tax = """
        contract Honeypot {
            uint256 public taxRate;
            function setTax(uint256 newRate) external onlyOwner {
                taxRate = newRate;
            }
        }
        """
        findings = rule.evaluate(code_with_unbounded_tax, code_with_unbounded_tax)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_UNLIMITED_OWNER_TAX" for f in findings))

        # With fee cap constraint, rule should not flag unbounded tax
        code_with_cap = """
        contract Safe {
            function setTax(uint256 newRate) external onlyOwner {
                require(newRate <= 10, "Tax exceeds limit");
                taxRate = newRate;
            }
        }
        """
        findings_safe = rule.evaluate(code_with_cap, code_with_cap)
        self.assertEqual(len(findings_safe), 0)

    def test_trading_cooldown_delay_rule(self):
        rule = TradingCooldownDelayRule()
        code_with_cooldown = """
        contract Honeypot {
            mapping(address => uint256) public cooldownTimer;
            function _transfer(address from, address to, uint256 amount) internal {
                require(block.timestamp >= cooldownTimer[from] + 24 hours, "Cooldown active");
                cooldownTimer[from] = block.timestamp;
            }
        }
        """
        findings = rule.evaluate(code_with_cooldown, code_with_cooldown)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_TRADING_COOLDOWN_DELAY" for f in findings))

    def test_pausable_transfers_rule(self):
        rule = PausableTransfersRule()
        code_with_pause = """
        contract Honeypot {
            bool public paused;
            function _transfer(address from, address to, uint256 amount) internal {
                require(!paused, "Transfers are currently halted");
            }
        }
        """
        findings = rule.evaluate(code_with_pause, code_with_pause)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_PAUSABLE_TRANSFERS" for f in findings))

    def test_max_wallet_tx_limit_rule(self):
        rule = MaxWalletTxLimitRule()
        code_with_limits = """
        contract Honeypot {
            uint256 public maxWalletAmount = 1000 * 10**18;
            function _transfer(address from, address to, uint256 amount) internal {
                require(amount <= maxWalletAmount, "Exceeds max wallet limit");
            }
        }
        """
        findings = rule.evaluate(code_with_limits, code_with_limits)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_MAX_WALLET_TX_LIMIT" for f in findings))

    def test_hidden_mint_privilege_rule(self):
        rule = HiddenMintPrivilegeRule()
        code_with_mint = """
        contract Honeypot {
            function mint(address recipient, uint256 amount) external onlyOwner {
                _balances[recipient] += amount;
                _totalSupply += amount;
            }
        }
        """
        findings = rule.evaluate(code_with_mint, code_with_mint)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_HIDDEN_MINT" for f in findings))

    def test_suspicious_assembly_rule(self):
        rule = SuspiciousAssemblyRule()
        code_with_assembly = """
        contract Honeypot {
            function executePayload(address target, bytes memory data) public {
                assembly {
                    let result := delegatecall(gas(), target, add(data, 0x20), mload(data), 0, 0)
                }
            }
        }
        """
        findings = rule.evaluate(code_with_assembly, code_with_assembly)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_SUSPICIOUS_ASSEMBLY" for f in findings))

    def test_external_restriction_call_rule(self):
        rule = ExternalRestrictionCallRule()
        code_with_oracle_call = """
        contract Honeypot {
            address public securityOracle;
            function _transfer(address from, address to, uint256 amount) internal {
                require(ISecurityOracle(securityOracle).isAllowed(from, to), "Denied by oracle");
            }
        }
        """
        findings = rule.evaluate(code_with_oracle_call, code_with_oracle_call)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f.rule_id == "HONEYPOT_EXTERNAL_RESTRICTION_CALL" for f in findings))


class TestPositiveIndicators(unittest.TestCase):
    """Tests detection of positive security indicators."""

    def test_all_positive_indicators_detected(self):
        code = """// SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
        contract AuditedToken is ERC20 {
            function renounceOwnership() public {}
            function setFee(uint256 newTax) external {
                require(newTax <= 10, "Tax capped");
            }
            function triggerEvents() public {
                emit Transfer(address(0), msg.sender, 100);
                emit Approval(msg.sender, address(0), 100);
            }
        }
        """
        indicators = check_positive_indicators(code)
        ids = {p.indicator_id for p in indicators}
        self.assertIn("POS_OPENZEPPELIN_STANDARD", ids)
        self.assertIn("POS_RENOUNCE_OWNERSHIP", ids)
        self.assertIn("POS_HARD_FEE_CAP", ids)
        self.assertIn("POS_STANDARD_EVENTS", ids)

    def test_no_positive_indicators_on_bare_code(self):
        bare_code = "contract Bare {}"
        indicators = check_positive_indicators(bare_code)
        self.assertEqual(len(indicators), 0)


if __name__ == "__main__":
    unittest.main()
