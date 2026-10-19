"""Comprehensive unit and integration test suite for Phase 1 & Phase 2.

Supports both standard library `python -m unittest` and `pytest`.
Covers:
- Phase 1: Environment & Core Configuration (config.py, utils.py)
- Phase 2: Static Analysis Engine & Honeypot Detection Rules (detection_rules.py, source_analyzer.py, risk_scorer.py)
"""

import unittest
from pathlib import Path

from src.config import settings, SUPPORTED_NETWORKS
from src.utils import (
    is_valid_eth_address,
    to_checksum_address_safe,
    is_valid_bytecode,
    sanitize_source_code,
    strip_comments,
    read_file_safe,
)
from src.detection_rules import (
    Severity,
    Confidence,
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
from src.source_analyzer import SourceAnalyzer
from src.risk_scorer import RiskScorer, RiskLevel


class TestPhase1Config(unittest.TestCase):
    def test_supported_networks(self):
        expected_chains = ["ethereum", "bsc", "polygon", "arbitrum", "sepolia"]
        for chain in expected_chains:
            self.assertIn(chain, SUPPORTED_NETWORKS)
            net = settings.get_network(chain)
            self.assertGreater(net.chain_id, 0)
            self.assertTrue(net.rpc_url.startswith("http"))
            self.assertTrue(net.explorer_api_url.startswith("http"))

    def test_invalid_network(self):
        with self.assertRaises(ValueError):
            settings.get_network("nonexistent_chain")

    def test_risk_thresholds(self):
        thresholds = settings.risk_thresholds
        self.assertEqual(thresholds.moderate, 25)
        self.assertEqual(thresholds.high, 50)
        self.assertEqual(thresholds.critical, 75)

    def test_severity_weights(self):
        weights = settings.severity_weights
        self.assertEqual(weights.CRITICAL, 40)
        self.assertEqual(weights.HIGH, 25)
        self.assertEqual(weights.MEDIUM, 15)
        self.assertEqual(weights.LOW, 5)


class TestPhase1Utils(unittest.TestCase):
    def test_is_valid_eth_address(self):
        self.assertTrue(is_valid_eth_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
        self.assertTrue(is_valid_eth_address("0xd8da6bf26964af9d7eed9e03e53415d37aa96045"))
        self.assertFalse(is_valid_eth_address("0x123"))
        self.assertFalse(is_valid_eth_address("d8da6bf26964af9d7eed9e03e53415d37aa96045"))
        self.assertFalse(is_valid_eth_address("0xZZZZ6BF26964aF9D7eEd9e03E53415D37aA96045"))
        self.assertFalse(is_valid_eth_address(""))

    def test_to_checksum_address_safe(self):
        raw = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
        expected = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        checksummed = to_checksum_address_safe(raw)
        self.assertEqual(checksummed, expected)

        with self.assertRaises(ValueError):
            to_checksum_address_safe("invalid_addr")

    def test_is_valid_bytecode(self):
        self.assertTrue(is_valid_bytecode("0x608060405234801561001057600080fd5b50"))
        self.assertTrue(is_valid_bytecode("608060405234801561001057600080fd5b50"))
        self.assertFalse(is_valid_bytecode("0x123"))  # Odd length
        self.assertFalse(is_valid_bytecode("0xZZZZ"))

    def test_sanitize_source_code(self):
        src_with_crlf = "line1\r\nline2\r\nline3"
        sanitized = sanitize_source_code(src_with_crlf)
        self.assertNotIn("\r", sanitized)
        self.assertEqual(sanitized, "line1\nline2\nline3")

    def test_strip_comments_preserves_lines(self):
        code = "line1;\n// single line comment\nline3;\n/* multi\nline\ncomment */\nline7;"
        stripped = strip_comments(code)
        self.assertNotIn("// single line comment", stripped)
        self.assertNotIn("/* multi", stripped)
        # Assert exact line count preservation
        self.assertEqual(len(code.splitlines()), len(stripped.splitlines()))
        self.assertEqual(stripped.splitlines()[0], "line1;")
        self.assertEqual(stripped.splitlines()[2], "line3;")
        self.assertEqual(stripped.splitlines()[6], "line7;")

    def test_read_file_safe(self):
        test_file = Path(__file__).resolve().parent / "_test_dummy.sol"
        try:
            test_file.write_text("pragma solidity ^0.8.0;\ncontract Foo {}\n", encoding="utf-8")
            success, content, filename = read_file_safe(test_file)
            self.assertTrue(success)
            self.assertIn("contract Foo", content)
            self.assertEqual(filename, "_test_dummy.sol")
        finally:
            if test_file.exists():
                test_file.unlink()

        # Non-existent file
        success_bad, msg, _ = read_file_safe(Path("non_existent_file.sol"))
        self.assertFalse(success_bad)
        self.assertIn("not found", msg.lower())


class TestPhase2DetectionRules(unittest.TestCase):
    def test_honeypot_blacklist_rule(self):
        rule = BlacklistLogicRule()
        code_with_mapping = """
        contract Test {
            mapping(address => bool) private _isBlacklisted;
            function setBlacklist(address a, bool s) external {}
        }
        """
        findings = rule.evaluate(code_with_mapping, code_with_mapping)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_BLACKLIST")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

        code_with_mod = """
        contract Test {
            modifier notBlacklisted(address account) {
                require(!isBlacklisted[account], "Trapped");
                _;
            }
        }
        """
        findings_mod = rule.evaluate(code_with_mod, code_with_mod)
        self.assertTrue(any("Modifier Trap" in f.rule_name for f in findings_mod))

    def test_honeypot_sell_restriction_rule(self):
        rule = AsymmetricSellRestrictionRule()
        code = """
        contract Test {
            function _transfer(address from, address to, uint256 amt) internal {
                if (to == uniswapV2Pair) {
                    require(canSell[from], "Sells blocked");
                }
            }
        }
        """
        findings = rule.evaluate(code, code)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_SELL_RESTRICTION")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_honeypot_excessive_sell_tax_rule(self):
        rule = ExcessiveSellTaxRule()
        code_pct = "uint256 public sellTax = 99;"
        findings = rule.evaluate(code_pct, code_pct)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_EXCESSIVE_SELL_TAX")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

        code_bps = "uint256 public totalSellFee = 3000;"
        findings_bps = rule.evaluate(code_bps, code_bps)
        self.assertGreaterEqual(len(findings_bps), 1)

        code_calc = "uint256 fee = (amount * 95) / 100;"
        findings_calc = rule.evaluate(code_calc, code_calc)
        self.assertGreaterEqual(len(findings_calc), 1)

    def test_honeypot_unlimited_owner_tax_rule(self):
        rule = UnlimitedOwnerTaxRule()
        code_unbounded = """
        function setSellTax(uint256 newTax) external onlyOwner {
            sellTax = newTax;
        }
        """
        findings = rule.evaluate(code_unbounded, code_unbounded)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_UNLIMITED_OWNER_TAX")

        code_capped = """
        function setSellTax(uint256 newTax) external onlyOwner {
            require(newTax <= 15, "Fee exceeds ceiling");
            sellTax = newTax;
        }
        """
        findings_capped = rule.evaluate(code_capped, code_capped)
        self.assertEqual(len(findings_capped), 0)

    def test_honeypot_trading_cooldown_delay_rule(self):
        rule = TradingCooldownDelayRule()
        code = "mapping(address => uint256) public _holderLastTransferTimestamp;"
        findings = rule.evaluate(code, code)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_TRADING_COOLDOWN_DELAY")

    def test_honeypot_pausable_transfers_rule(self):
        rule = PausableTransfersRule()
        code = """
        function pause() external onlyOwner {
            paused = true;
        }
        """
        findings = rule.evaluate(code, code)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_PAUSABLE_TRANSFERS")

    def test_honeypot_max_wallet_tx_limit_rule(self):
        rule = MaxWalletTxLimitRule()
        code = "uint256 public maxTxAmount = 1000 * 10**18;"
        findings = rule.evaluate(code, code)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_MAX_WALLET_TX_LIMIT")

    def test_honeypot_hidden_mint_rule(self):
        rule = HiddenMintPrivilegeRule()
        code = "function mint(address account, uint256 amount) external onlyOwner {}"
        findings = rule.evaluate(code, code)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_HIDDEN_MINT")

    def test_honeypot_suspicious_assembly_rule(self):
        rule = SuspiciousAssemblyRule()
        code_asm = "assembly { let ptr := mload(0x40) }"
        findings_asm = rule.evaluate(code_asm, code_asm)
        self.assertGreaterEqual(len(findings_asm), 1)
        self.assertEqual(findings_asm[0].rule_id, "HONEYPOT_SUSPICIOUS_ASSEMBLY")

        code_del = "address(target).delegatecall(data);"
        findings_del = rule.evaluate(code_del, code_del)
        self.assertGreaterEqual(len(findings_del), 1)
        self.assertEqual(findings_del[0].rule_id, "HONEYPOT_SUSPICIOUS_ASSEMBLY")

    def test_honeypot_external_restriction_call_rule(self):
        rule = ExternalRestrictionCallRule()
        code = "require(ITokenFilter(oracle).canTransfer(from, to), 'Denied');"
        findings = rule.evaluate(code, code)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HONEYPOT_EXTERNAL_RESTRICTION_CALL")

    def test_positive_indicators(self):
        code = """
        import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
        contract MyToken is ERC20 {
            function renounceOwnership() public {}
            function setFee(uint256 fee) external {
                require(fee <= 10, "Max fee");
            }
            function trigger() internal {
                emit Transfer(msg.sender, address(0), 1);
                emit Approval(msg.sender, address(0), 1);
            }
        }
        """
        pos = check_positive_indicators(code)
        pos_ids = {p.indicator_id for p in pos}
        self.assertIn("POS_OPENZEPPELIN_STANDARD", pos_ids)
        self.assertIn("POS_RENOUNCE_OWNERSHIP", pos_ids)
        self.assertIn("POS_HARD_FEE_CAP", pos_ids)
        self.assertIn("POS_STANDARD_EVENTS", pos_ids)


class TestPhase2AnalyzerAndScorer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SourceAnalyzer()
        self.scorer = RiskScorer()

    def test_empty_or_invalid_solidity(self):
        res_empty = self.analyzer.analyze("", source_name="Empty")
        self.assertFalse(res_empty.is_valid_solidity)

        res_invalid = self.analyzer.analyze("const x = 42; console.log(x);", source_name="JS")
        self.assertFalse(res_invalid.is_valid_solidity)

    def test_benign_token_analysis(self):
        sample_path = Path(__file__).resolve().parent.parent / "samples" / "BenignToken.sol"
        self.assertTrue(sample_path.exists())

        source_code = sample_path.read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(source_code, source_name="BenignToken")

        self.assertTrue(analysis.is_valid_solidity)
        self.assertEqual(analysis.contract_structure.name, "BenignToken")
        self.assertIn("ERC20", analysis.contract_structure.inheritance)
        self.assertTrue(analysis.contract_structure.has_transfer_function)
        self.assertTrue(analysis.contract_structure.has_owner_control)
        self.assertGreaterEqual(len(analysis.positive_indicators), 2)

        # Risk scoring
        report = self.scorer.calculate_risk(analysis.findings, analysis.positive_indicators)
        self.assertLess(report.risk_score, 25)
        self.assertEqual(report.risk_level, RiskLevel.LOW)
        self.assertGreaterEqual(len(report.mitigating_factors), 2)

    def test_honeypot_token_analysis(self):
        sample_path = Path(__file__).resolve().parent.parent / "samples" / "HoneypotToken.sol"
        self.assertTrue(sample_path.exists())

        source_code = sample_path.read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(source_code, source_name="HoneypotToken")

        self.assertTrue(analysis.is_valid_solidity)
        self.assertEqual(analysis.contract_structure.name, "HoneypotToken")

        # Must detect critical honeypot rules
        rule_ids = {f.rule_id for f in analysis.findings}
        self.assertIn("HONEYPOT_BLACKLIST", rule_ids)
        self.assertIn("HONEYPOT_SELL_RESTRICTION", rule_ids)
        self.assertIn("HONEYPOT_EXCESSIVE_SELL_TAX", rule_ids)
        self.assertIn("HONEYPOT_UNLIMITED_OWNER_TAX", rule_ids)
        self.assertIn("HONEYPOT_PAUSABLE_TRANSFERS", rule_ids)
        self.assertIn("HONEYPOT_MAX_WALLET_TX_LIMIT", rule_ids)
        self.assertIn("HONEYPOT_HIDDEN_MINT", rule_ids)
        self.assertIn("HONEYPOT_SUSPICIOUS_ASSEMBLY", rule_ids)
        self.assertIn("HONEYPOT_EXTERNAL_RESTRICTION_CALL", rule_ids)

        # Risk scoring
        report = self.scorer.calculate_risk(analysis.findings, analysis.positive_indicators)
        self.assertGreaterEqual(report.risk_score, 75)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(report.confidence, Confidence.HIGH)
        self.assertGreaterEqual(len(report.primary_risk_factors), 3)
        self.assertIn("CRITICAL", report.summary_explanation)


if __name__ == "__main__":
    unittest.main()
