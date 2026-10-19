"""Unit tests for the Machine Learning FeatureExtractor module."""

import unittest
from types import SimpleNamespace
import pandas as pd

from src.feature_extractor import (
    FeatureExtractor,
    FEATURE_NAMES,
    FEATURE_DESCRIPTIONS,
    get_default_features,
)
from src.contract_loader import LoadedContract


class TestFeatureConstants(unittest.TestCase):
    """Verifies feature schema, descriptions, and zero-initialization."""

    def test_feature_names_count_and_uniqueness(self):
        self.assertEqual(len(FEATURE_NAMES), 19)
        self.assertEqual(len(FEATURE_NAMES), len(set(FEATURE_NAMES)))

    def test_feature_descriptions_match_names(self):
        for name in FEATURE_NAMES:
            self.assertIn(name, FEATURE_DESCRIPTIONS)
            self.assertTrue(len(FEATURE_DESCRIPTIONS[name]) > 5)

    def test_default_features(self):
        defaults = get_default_features()
        self.assertEqual(len(defaults), 19)
        for name in FEATURE_NAMES:
            self.assertEqual(defaults[name], 0)


class TestFeatureExtractorExtraction(unittest.TestCase):
    """Verifies feature extraction across raw source strings, contracts, and vectors."""

    def setUp(self):
        self.extractor = FeatureExtractor()

    def test_extract_from_none_and_empty(self):
        for bad_input in [None, "", "   \n\t  ", 12345]:
            feats = self.extractor.extract_features_from_source(bad_input)
            self.assertEqual(feats, get_default_features())
            vec = self.extractor.extract_feature_vector(bad_input)
            self.assertEqual(vec, [0.0] * len(FEATURE_NAMES))

    def test_extract_features_safe_contract(self):
        code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract BenignToken is ERC20 {
    address public owner;

    constructor() ERC20("Benign", "BNG") {
        owner = msg.sender;
        emit Transfer(address(0), msg.sender, 1000);
        emit Approval(msg.sender, address(0), 1000);
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }

    function renounceOwnership() public {
        owner = address(0);
    }
}
"""
        feats = self.extractor.extract_features_from_source(code)
        self.assertGreater(feats["lines_of_code"], 0)
        self.assertGreater(feats["num_functions"], 0)
        self.assertEqual(feats["has_transfer_function"], 1)
        self.assertEqual(feats["has_owner_control"], 1)
        self.assertEqual(feats["has_blacklist_mapping"], 0)
        self.assertEqual(feats["has_sell_restriction_logic"], 0)
        self.assertEqual(feats["has_excessive_fee"], 0)
        self.assertEqual(feats["has_openzeppelin_imports"], 1)
        self.assertEqual(feats["has_renounce_ownership"], 1)
        self.assertGreater(feats["num_positive_indicators"], 0)

    def test_extract_features_honeypot_contract(self):
        honeypot_code = """pragma solidity ^0.8.20;

contract TrapToken {
    address public uniswapV2Pair;
    mapping(address => bool) private _isBlacklisted;
    uint256 public sellTax = 99;

    function transfer(address to, uint256 amount) public returns (bool) {
        require(!_isBlacklisted[msg.sender], "Blacklisted");
        if (to == uniswapV2Pair) {
            revert("Sell trap");
        }
        return true;
    }

    function mint(address to, uint256 amount) external {
        // hidden mint
    }
}
"""
        feats = self.extractor.extract_features_from_source(honeypot_code)
        self.assertEqual(feats["has_blacklist_mapping"], 1)
        self.assertEqual(feats["has_sell_restriction_logic"], 1)
        self.assertEqual(feats["has_excessive_fee"], 1)
        self.assertEqual(feats["has_hidden_mint"], 1)
        self.assertGreater(feats["num_total_findings"], 0)

    def test_extract_feature_vector(self):
        code = "pragma solidity ^0.8.0; contract T { function transfer() public {} }"
        vector = self.extractor.extract_feature_vector(code)
        self.assertIsInstance(vector, list)
        self.assertEqual(len(vector), len(FEATURE_NAMES))
        for val in vector:
            self.assertIsInstance(val, float)

    def test_extract_from_contract_object_with_source(self):
        loaded = LoadedContract(
            input_type="source_code",
            name="ContractObj",
            source_code="pragma solidity ^0.8.0; contract Dummy { function transfer() public {} }",
        )
        feats = self.extractor.extract_from_contract(loaded)
        self.assertEqual(feats["has_transfer_function"], 1)

    def test_extract_from_contract_object_bytecode_only(self):
        # 200 hex characters -> ~ 100 bytes -> max(1, 200 // 100) = 2 lines
        bytecode = "0x" + ("608060405234801561001057600080fd5b50" * 5)
        loaded = LoadedContract(
            input_type="bytecode",
            name="BytecodeObj",
            bytecode=bytecode,
        )
        feats = self.extractor.extract_from_contract(loaded)
        self.assertGreater(feats["lines_of_code"], 0)
        self.assertEqual(feats["has_transfer_function"], 0)

    def test_extract_from_arbitrary_object_no_code(self):
        obj = SimpleNamespace()
        feats = self.extractor.extract_from_contract(obj)
        self.assertEqual(feats, get_default_features())

    def test_extract_dataframe_batch(self):
        sources = [
            "pragma solidity ^0.8.0; contract A {}",
            "pragma solidity ^0.8.0; contract B { function transfer() public {} }",
        ]
        df = self.extractor.extract_dataframe(sources, include_metadata=True)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 2)
        self.assertIn("contract_index", df.columns)
        for name in FEATURE_NAMES:
            self.assertIn(name, df.columns)


if __name__ == "__main__":
    unittest.main()
