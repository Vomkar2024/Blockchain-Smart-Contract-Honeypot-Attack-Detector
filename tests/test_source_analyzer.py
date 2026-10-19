"""Unit tests for SourceAnalyzer and contract structure extraction."""

import unittest
from unittest.mock import MagicMock

from src.source_analyzer import SourceAnalyzer, ContractStructure, SourceAnalysisResult
from src.detection_rules import (
    BaseRule,
    Finding,
    PositiveIndicator,
    Severity,
    Confidence,
    BlacklistLogicRule,
)


class TestContractStructure(unittest.TestCase):
    """Tests for ContractStructure dataclass."""

    def test_default_contract_structure(self):
        struct = ContractStructure(name="Token", pragma="^0.8.20")
        self.assertEqual(struct.name, "Token")
        self.assertEqual(struct.pragma, "^0.8.20")
        self.assertEqual(struct.inheritance, [])
        self.assertEqual(struct.functions, [])
        self.assertEqual(struct.modifiers, [])
        self.assertEqual(struct.state_variables, [])
        self.assertFalse(struct.has_transfer_function)
        self.assertFalse(struct.has_owner_control)
        self.assertEqual(struct.lines_of_code, 0)


class TestSourceAnalysisResult(unittest.TestCase):
    """Tests for SourceAnalysisResult dataclass and serialization."""

    def test_to_dict_serialization(self):
        struct = ContractStructure(
            name="MyToken",
            pragma="0.8.20",
            inheritance=["ERC20", "Ownable"],
            functions=["transfer", "mint"],
            modifiers=["onlyOwner"],
            state_variables=["totalSupply"],
            has_transfer_function=True,
            has_owner_control=True,
            lines_of_code=45,
        )
        finding = Finding(
            rule_id="RULE_1",
            rule_name="Test Rule",
            category="Test Category",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            line_number=10,
            evidence="bad code",
            explanation="Dangerous pattern",
            suggested_verification="Check lines",
        )
        indicator = PositiveIndicator(
            indicator_id="POS_1",
            name="Audited Base",
            evidence="OpenZeppelin import",
            explanation="Uses standard library",
        )

        res = SourceAnalysisResult(
            source_name="test.sol",
            contract_structure=struct,
            findings=[finding],
            positive_indicators=[indicator],
            timestamp="2026-10-14T12:00:00Z",
            is_valid_solidity=True,
            error_message=None,
        )

        d = res.to_dict()
        self.assertEqual(d["source_name"], "test.sol")
        self.assertEqual(d["contract_name"], "MyToken")
        self.assertEqual(d["pragma"], "0.8.20")
        self.assertEqual(d["lines_of_code"], 45)
        self.assertIn("ERC20", d["inheritance"])
        self.assertTrue(d["has_transfer_function"])
        self.assertTrue(d["has_owner_control"])
        self.assertEqual(len(d["findings"]), 1)
        self.assertEqual(d["findings"][0]["rule_id"], "RULE_1")
        self.assertEqual(len(d["positive_indicators"]), 1)
        self.assertEqual(d["positive_indicators"][0]["indicator_id"], "POS_1")
        self.assertTrue(d["is_valid_solidity"])
        self.assertIsNone(d["error_message"])


class TestSourceAnalyzer(unittest.TestCase):
    """Tests for SourceAnalyzer parsing and analysis engine."""

    def setUp(self):
        self.analyzer = SourceAnalyzer()

    def test_extract_structure_full_contract(self):
        code = """pragma solidity ^0.8.20;

contract Base {
    address public owner;
}

contract SafeToken is Base, IERC20 {
    string public name = "Safe";
    uint256 public totalSupply;
    mapping(address => uint256) private _balances;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        _balances[to] += amount;
        return true;
    }

    function customLogic() external onlyOwner {
        totalSupply += 100;
    }
}
"""
        struct = self.analyzer.extract_structure(code, code)
        self.assertEqual(struct.name, "SafeToken")
        self.assertEqual(struct.pragma, "^0.8.20")
        self.assertIn("Base", struct.inheritance)
        self.assertIn("IERC20", struct.inheritance)
        self.assertTrue(struct.has_transfer_function)
        self.assertTrue(struct.has_owner_control)
        self.assertIn("transfer", struct.functions)
        self.assertIn("customLogic", struct.functions)
        self.assertIn("onlyOwner", struct.modifiers)
        self.assertGreater(struct.lines_of_code, 10)

    def test_extract_structure_no_pragma_or_transfer(self):
        code = """contract Minimal {
    function ping() public pure returns (bool) {
        return true;
    }
}"""
        struct = self.analyzer.extract_structure(code, code)
        self.assertEqual(struct.name, "Minimal")
        self.assertEqual(struct.pragma, "unknown")
        self.assertEqual(struct.inheritance, [])
        self.assertFalse(struct.has_transfer_function)
        self.assertFalse(struct.has_owner_control)
        self.assertIn("ping", struct.functions)

    def test_analyze_empty_source(self):
        res = self.analyzer.analyze("", source_name="EmptyFile")
        self.assertFalse(res.is_valid_solidity)
        self.assertIsNotNone(res.error_message)
        self.assertIn("empty", res.error_message.lower())
        self.assertEqual(res.contract_structure.name, "Empty")

    def test_analyze_whitespace_source(self):
        res = self.analyzer.analyze("   \n\t  \n  ", source_name="WhitespaceFile")
        self.assertFalse(res.is_valid_solidity)
        self.assertIn("empty or contains only whitespace", res.error_message)

    def test_analyze_non_solidity_code(self):
        non_solidity = """
        def python_func():
            print("This is not solidity code")
        """
        res = self.analyzer.analyze(non_solidity, source_name="Script.py")
        self.assertFalse(res.is_valid_solidity)
        self.assertIn("does not appear to be valid Solidity code", res.error_message)
        self.assertEqual(res.contract_structure.name, "Invalid")

    def test_analyze_valid_solidity_with_positive_indicators(self):
        code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract GoodToken is ERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() ERC20("Good", "GD") {
        emit Transfer(address(0), msg.sender, 100);
        emit Approval(msg.sender, address(0), 100);
    }

    function renounceOwnership() public {}

    function setFee(uint256 newSellFee) external {
        require(newSellFee <= 10, "Fee too high");
    }
}
"""
        res = self.analyzer.analyze(code, source_name="GoodToken.sol")
        self.assertTrue(res.is_valid_solidity)
        self.assertIsNone(res.error_message)
        self.assertEqual(res.contract_structure.name, "GoodToken")

        # Verify positive indicators detected
        indicator_ids = [p.indicator_id for p in res.positive_indicators]
        self.assertIn("POS_OPENZEPPELIN_STANDARD", indicator_ids)
        self.assertIn("POS_RENOUNCE_OWNERSHIP", indicator_ids)
        self.assertIn("POS_HARD_FEE_CAP", indicator_ids)
        self.assertIn("POS_STANDARD_EVENTS", indicator_ids)

    def test_analyze_with_custom_rules_and_error_handling(self):
        # Create a mock rule that raises an exception during evaluate()
        failing_rule = MagicMock(spec=BaseRule)
        failing_rule.rule_id = "FAIL_RULE"
        failing_rule.rule_name = "Failing Test Rule"
        failing_rule.severity = Severity.HIGH
        failing_rule.confidence = Confidence.MEDIUM
        failing_rule.evaluate.side_effect = RuntimeError("Simulated crash in rule evaluation")

        analyzer = SourceAnalyzer(rules=[failing_rule, BlacklistLogicRule()])
        code = "pragma solidity ^0.8.0; contract TestContract {}"

        res = analyzer.analyze(code, source_name="TestCrash.sol")
        self.assertTrue(res.is_valid_solidity)

        # Verify that the engine gracefully handled the failing rule by creating an ERROR finding
        error_findings = [f for f in res.findings if f.rule_id == "FAIL_RULE_ERROR"]
        self.assertEqual(len(error_findings), 1)
        self.assertEqual(error_findings[0].category, "Engine Error")
        self.assertIn("Simulated crash", error_findings[0].evidence)


if __name__ == "__main__":
    unittest.main()
