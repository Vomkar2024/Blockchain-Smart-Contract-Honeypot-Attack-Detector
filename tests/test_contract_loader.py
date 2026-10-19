"""Unit tests for LoadedContract and ContractLoader ingestion engine."""

import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile
import shutil

from src.contract_loader import LoadedContract, ContractLoader


class TestLoadedContractDataClass(unittest.TestCase):
    """Tests for LoadedContract model, properties, and summary string."""

    def test_properties_and_summary(self):
        contract = LoadedContract(
            input_type="file",
            name="SafeToken",
            source_code="pragma solidity ^0.8.0; contract SafeToken {}",
            bytecode="0x6080604052",
            address="0x1234567890123456789012345678901234567890",
            network="ethereum",
            is_verified=True,
            is_success=True,
        )
        self.assertTrue(contract.has_source)
        self.assertTrue(contract.has_bytecode)
        summary = contract.summary()
        self.assertIn("[FILE]", summary)
        self.assertIn("SafeToken", summary)
        self.assertIn("SUCCESS", summary)
        self.assertIn("Net: ethereum", summary)
        self.assertIn("Verified", summary)

        d = contract.to_dict()
        self.assertEqual(d["name"], "SafeToken")
        self.assertTrue(d["has_source"])
        self.assertTrue(d["has_bytecode"])

    def test_failed_contract_summary(self):
        failed = LoadedContract(
            input_type="address",
            name="FailedToken",
            is_success=False,
            error_message="Connection timed out",
        )
        self.assertFalse(failed.has_source)
        self.assertFalse(failed.has_bytecode)
        summary = failed.summary()
        self.assertIn("FAILED (Connection timed out)", summary)


class TestContractLoaderMethods(unittest.TestCase):
    """Tests for individual ContractLoader static loading methods."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_extract_contract_name_and_version(self):
        code = """// SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        interface IERC20 {}
        contract BaseToken is IERC20 {}
        contract MainImplementation is BaseToken {}
        """
        # Must extract the last contract implementation
        name = ContractLoader._extract_contract_name(code)
        self.assertEqual(name, "MainImplementation")

        version = ContractLoader._extract_compiler_version(code)
        self.assertEqual(version, "^0.8.20")

        self.assertIsNone(ContractLoader._extract_contract_name(""))
        self.assertIsNone(ContractLoader._extract_compiler_version("contract A {}"))

    def test_load_from_file_valid(self):
        test_file = self.temp_dir / "Token.sol"
        test_file.write_text("pragma solidity ^0.8.0; contract MyToken {}", encoding="utf-8")

        contract = ContractLoader.load_from_file(test_file)
        self.assertTrue(contract.is_success)
        self.assertEqual(contract.input_type, "file")
        self.assertEqual(contract.name, "MyToken")
        self.assertEqual(contract.compiler_version, "^0.8.0")
        self.assertTrue(contract.has_source)

    def test_load_from_file_nonexistent(self):
        missing = self.temp_dir / "NonExistent.sol"
        contract = ContractLoader.load_from_file(missing)
        self.assertFalse(contract.is_success)
        self.assertIn("File not found", contract.error_message)

    def test_load_from_source(self):
        code = "pragma solidity ^0.8.19; contract DirectContract {}"
        contract = ContractLoader.load_from_source(code)
        self.assertTrue(contract.is_success)
        self.assertEqual(contract.input_type, "source_code")
        self.assertEqual(contract.name, "DirectContract")
        self.assertEqual(contract.compiler_version, "^0.8.19")

        # Empty source code
        empty_contract = ContractLoader.load_from_source("   \n ")
        self.assertFalse(empty_contract.is_success)
        self.assertIn("empty", empty_contract.error_message.lower())

    def test_load_from_bytecode_valid(self):
        raw_hex = "608060405234801561001057600080fd5b50"
        contract = ContractLoader.load_from_bytecode(raw_hex, name="BytecodeContract")
        self.assertTrue(contract.is_success)
        self.assertEqual(contract.input_type, "bytecode")
        self.assertTrue(contract.bytecode.startswith("0x"))
        self.assertFalse(contract.is_verified)

    def test_load_from_bytecode_invalid(self):
        invalid_hex = "0xZZZ123NotHex!"
        contract = ContractLoader.load_from_bytecode(invalid_hex)
        self.assertFalse(contract.is_success)
        self.assertIn("Invalid hex-encoded", contract.error_message)

    def test_load_from_address_invalid(self):
        contract = ContractLoader.load_from_address("0xInvalidAddress")
        self.assertFalse(contract.is_success)
        self.assertIn("Invalid EVM address format", contract.error_message)

    @patch("src.contract_loader.BlockchainClient")
    @patch("src.contract_loader.ExplorerClient")
    def test_load_from_address_verified_source(self, mock_explorer_cls, mock_blockchain_cls):
        mock_explorer = MagicMock()
        mock_explorer_cls.return_value = mock_explorer
        mock_explorer.get_verified_source.return_value = (
            True,
            {
                "is_verified": True,
                "contract_name": "VerifiedToken",
                "source_code": "contract VerifiedToken {}",
                "compiler_version": "v0.8.20+commit.a1b2c3d4",
                "abi": "[]",
            },
            None,
        )

        mock_blockchain = MagicMock()
        mock_blockchain_cls.return_value = mock_blockchain
        mock_blockchain.get_token_metadata.return_value = {"name": "VerifiedToken", "symbol": "VT"}
        mock_blockchain.get_bytecode.return_value = "0x6080604052"

        valid_addr = "0x1234567890123456789012345678901234567890"
        contract = ContractLoader.load_from_address(valid_addr, network_name="ethereum")

        self.assertTrue(contract.is_success)
        self.assertTrue(contract.is_verified)
        self.assertEqual(contract.name, "VerifiedToken")
        self.assertEqual(contract.source_code, "contract VerifiedToken {}")
        self.assertEqual(contract.bytecode, "0x6080604052")

    @patch("src.contract_loader.BlockchainClient")
    @patch("src.contract_loader.ExplorerClient")
    def test_load_from_address_unverified_with_bytecode(self, mock_explorer_cls, mock_blockchain_cls):
        mock_explorer = MagicMock()
        mock_explorer_cls.return_value = mock_explorer
        mock_explorer.get_verified_source.return_value = (False, {}, "Unverified")

        mock_blockchain = MagicMock()
        mock_blockchain_cls.return_value = mock_blockchain
        mock_blockchain.get_token_metadata.return_value = {"name": "UnverifiedCoin", "symbol": "UC"}
        mock_blockchain.get_bytecode.return_value = "0x6080604052"

        valid_addr = "0x1234567890123456789012345678901234567890"
        contract = ContractLoader.load_from_address(valid_addr, network_name="ethereum")

        self.assertTrue(contract.is_success)
        self.assertFalse(contract.is_verified)
        self.assertEqual(contract.name, "UnverifiedCoin")
        self.assertEqual(contract.bytecode, "0x6080604052")
        self.assertIsNone(contract.source_code)

    @patch("src.contract_loader.BlockchainClient")
    @patch("src.contract_loader.ExplorerClient")
    def test_load_from_address_unreachable(self, mock_explorer_cls, mock_blockchain_cls):
        mock_explorer = MagicMock()
        mock_explorer_cls.return_value = mock_explorer
        mock_explorer.get_verified_source.return_value = (False, {}, "Unverified")

        mock_blockchain = MagicMock()
        mock_blockchain_cls.return_value = mock_blockchain
        mock_blockchain.get_token_metadata.return_value = {}
        mock_blockchain.get_bytecode.return_value = None

        valid_addr = "0x1234567890123456789012345678901234567890"
        contract = ContractLoader.load_from_address(valid_addr, network_name="ethereum")

        self.assertFalse(contract.is_success)
        self.assertEqual(contract.name, "UnreachableContract")

    def test_load_from_address_benchmark_hard_threat(self):
        """Verify on-chain benchmark address loads with verified source and high threat metadata."""
        bench_addr = "0x71c8dC0563b7c8449c25fBA0B991461FfFAe7748"
        contract = ContractLoader.load_from_address(bench_addr, network_name="ethereum")
        self.assertTrue(contract.is_success)
        self.assertEqual(contract.input_type, "address")
        self.assertEqual(contract.name, "HighRiskUnboundedTaxToken")
        self.assertTrue(contract.has_source)
        self.assertTrue(contract.has_bytecode)
        self.assertTrue(contract.is_verified)
        self.assertEqual(contract.metadata.get("symbol"), "HRUNBOUND")

    def test_load_auto_inferences(self):
        # Empty input
        empty = ContractLoader.load_auto("   ")
        self.assertFalse(empty.is_success)

        # Existing file path
        test_file = self.temp_dir / "AutoToken.sol"
        test_file.write_text("contract AutoToken {}", encoding="utf-8")
        from_file = ContractLoader.load_auto(str(test_file))
        self.assertTrue(from_file.is_success)
        self.assertEqual(from_file.input_type, "file")

        # Source code string
        code_input = "pragma solidity ^0.8.0;\ncontract InlineToken {}"
        from_code = ContractLoader.load_auto(code_input)
        self.assertTrue(from_code.is_success)
        self.assertEqual(from_code.input_type, "source_code")

        # Bytecode hex
        bytecode_input = "0x608060405234801561001057600080fd5b50"
        from_bc = ContractLoader.load_auto(bytecode_input)
        self.assertTrue(from_bc.is_success)
        self.assertEqual(from_bc.input_type, "bytecode")


if __name__ == "__main__":
    unittest.main()
