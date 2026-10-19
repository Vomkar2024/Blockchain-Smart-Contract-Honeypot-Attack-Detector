"""Comprehensive unit and integration test suite for Phase 3:
Contract Ingestion, Blockchain & External Integrations.

Covers:
- ContractLoader (files, source strings, bytecode, address lookups, load_auto)
- BlockchainClient (RPC querying, bytecode, string and bytes32 ERC-20 metadata, offline mode)
- ExplorerClient (Etherscan API, multi-file JSON parsing, ABI fetching, rate limits)
- SimulationAdapter (Honeypot.is, GoPlus, Mock provider, auto-fallback cascade)
- ReportGenerator (CompleteAuditReport, JSON/CSV/Markdown output, batch CSV export)
"""

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.contract_loader import LoadedContract, ContractLoader
from src.blockchain_client import BlockchainClient, _decode_bytes32_string
from src.explorer_client import ExplorerClient
from src.simulation_adapter import SimulationAdapter, SimulationResult
from src.report_generator import CompleteAuditReport, ReportGenerator
from src.detection_rules import Finding, Severity, Confidence
from src.source_analyzer import SourceAnalysisResult, ContractStructure
from src.risk_scorer import RiskScorer


class TestContractLoader(unittest.TestCase):
    def setUp(self):
        self.sample_dir = Path(__file__).resolve().parent.parent / "samples"
        self.benign_file = self.sample_dir / "BenignToken.sol"

    def test_load_from_file_valid(self):
        self.assertTrue(self.benign_file.exists(), "Sample BenignToken.sol should exist")
        loaded = ContractLoader.load_from_file(self.benign_file)
        self.assertTrue(loaded.is_success)
        self.assertEqual(loaded.input_type, "file")
        self.assertTrue(loaded.has_source)
        self.assertFalse(loaded.has_bytecode)
        self.assertIn("BenignToken", loaded.name)
        self.assertIsNotNone(loaded.compiler_version)

    def test_load_from_file_nonexistent(self):
        loaded = ContractLoader.load_from_file("nonexistent_contract_file.sol")
        self.assertFalse(loaded.is_success)
        self.assertIn("File not found", loaded.error_message)

    def test_load_from_source_valid(self):
        code = "pragma solidity ^0.8.0;\ncontract TestVault { address owner; }"
        loaded = ContractLoader.load_from_source(code)
        self.assertTrue(loaded.is_success)
        self.assertEqual(loaded.name, "TestVault")
        self.assertEqual(loaded.compiler_version, "^0.8.0")
        self.assertTrue(loaded.has_source)

    def test_load_from_source_empty(self):
        loaded = ContractLoader.load_from_source("   ")
        self.assertFalse(loaded.is_success)
        self.assertIn("empty", loaded.error_message.lower())

    def test_load_from_bytecode_valid(self):
        raw_hex = "608060405234801561001057600080fd5b50"
        loaded = ContractLoader.load_from_bytecode(raw_hex, name="MyBytecode")
        self.assertTrue(loaded.is_success)
        self.assertEqual(loaded.name, "MyBytecode")
        self.assertTrue(loaded.bytecode.startswith("0x"))
        self.assertTrue(loaded.has_bytecode)
        self.assertFalse(loaded.has_source)

    def test_load_from_bytecode_invalid(self):
        loaded = ContractLoader.load_from_bytecode("not_a_hex_string_123")
        self.assertFalse(loaded.is_success)
        self.assertIn("Invalid", loaded.error_message)

    def test_load_from_address_invalid(self):
        loaded = ContractLoader.load_from_address("0xInvalidAddr")
        self.assertFalse(loaded.is_success)
        self.assertIn("Invalid EVM address", loaded.error_message)

    @patch("src.contract_loader.ExplorerClient")
    @patch("src.contract_loader.BlockchainClient")
    def test_load_from_address_verified(self, mock_bc_cls, mock_exp_cls):
        mock_exp = mock_exp_cls.return_value
        mock_exp.get_verified_source.return_value = (
            True,
            {
                "is_verified": True,
                "contract_name": "VerifiedHoneypot",
                "source_code": "contract VerifiedHoneypot {}",
                "compiler_version": "0.8.19",
                "abi": "[]",
            },
            None,
        )

        mock_bc = mock_bc_cls.return_value
        mock_bc.get_token_metadata.return_value = {"name": "VerifiedHoneypot", "symbol": "VHP", "is_erc20": True}
        mock_bc.get_bytecode.return_value = "0x60806040"

        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        loaded = ContractLoader.load_from_address(addr, network_name="ethereum")

        self.assertTrue(loaded.is_success)
        self.assertEqual(loaded.name, "VerifiedHoneypot")
        self.assertTrue(loaded.is_verified)
        self.assertTrue(loaded.has_source)
        self.assertTrue(loaded.has_bytecode)

    @patch("src.contract_loader.ExplorerClient")
    @patch("src.contract_loader.BlockchainClient")
    def test_load_from_address_unverified_with_bytecode(self, mock_bc_cls, mock_exp_cls):
        mock_exp = mock_exp_cls.return_value
        mock_exp.get_verified_source.return_value = (False, {}, "Source not verified")

        mock_bc = mock_bc_cls.return_value
        mock_bc.get_token_metadata.return_value = {"name": "UnverifiedToken", "is_erc20": True}
        mock_bc.get_bytecode.return_value = "0x60806040"

        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        loaded = ContractLoader.load_from_address(addr)

        self.assertTrue(loaded.is_success)
        self.assertFalse(loaded.is_verified)
        self.assertFalse(loaded.has_source)
        self.assertTrue(loaded.has_bytecode)
        self.assertIn("unverified", loaded.error_message.lower())

    def test_load_auto(self):
        # 1. Existing file
        res_file = ContractLoader.load_auto(str(self.benign_file))
        self.assertEqual(res_file.input_type, "file")

        # 2. Address
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        with patch.object(ContractLoader, "load_from_address") as mock_load_addr:
            mock_load_addr.return_value = LoadedContract(input_type="address", name="Test", is_success=True)
            res_addr = ContractLoader.load_auto(addr)
            mock_load_addr.assert_called_once()
            self.assertEqual(res_addr.input_type, "address")

        # 3. Source code
        res_src = ContractLoader.load_auto("pragma solidity ^0.8.0;\ncontract AutoToken {}")
        self.assertEqual(res_src.input_type, "source_code")

        # 4. Bytecode
        res_bc = ContractLoader.load_auto("0x608060405234801561001057600080fd5b50")
        self.assertEqual(res_bc.input_type, "bytecode")

        # 5. Empty input
        res_empty = ContractLoader.load_auto("   ")
        self.assertFalse(res_empty.is_success)

    def test_loaded_contract_summary(self):
        loaded = LoadedContract(
            input_type="file",
            name="TestContract",
            source_code="contract Test {}",
            is_verified=True,
            is_success=True,
        )
        self.assertTrue(loaded.has_source)
        self.assertFalse(loaded.has_bytecode)
        summary = loaded.summary()
        self.assertIn("FILE", summary)
        self.assertIn("TestContract", summary)
        self.assertIn("SUCCESS", summary)


class TestBlockchainClient(unittest.TestCase):
    def test_decode_bytes32_string(self):
        # Standard bytes32 with trailing nulls
        raw = b"MakerDAO\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        decoded = _decode_bytes32_string(raw)
        self.assertEqual(decoded, "MakerDAO")

        # Hex representation
        hex_val = "0x" + raw.hex()
        self.assertEqual(_decode_bytes32_string(hex_val), "MakerDAO")

    def test_invalid_address_raises_error(self):
        client = BlockchainClient(network_name="ethereum")
        with self.assertRaises(ValueError):
            client.get_bytecode("invalid_addr")

    def test_is_connected(self):
        client = BlockchainClient(network_name="ethereum")
        mock_instance = MagicMock()
        mock_instance.is_connected.return_value = True
        client._w3 = mock_instance

        self.assertTrue(client.is_connected())

    def test_get_bytecode_contract_and_eoa(self):
        client = BlockchainClient(network_name="ethereum")
        mock_instance = MagicMock()
        mock_instance.is_connected.return_value = True
        client._w3 = mock_instance
        client._connected = True

        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

        # Contract returning code
        mock_instance.eth.get_code.return_value = bytes.fromhex("60806040")
        code = client.get_bytecode(addr)
        self.assertEqual(code, "0x60806040")
        self.assertTrue(client.is_contract(addr))

        # EOA returning empty bytes
        mock_instance.eth.get_code.return_value = b""
        eoa_code = client.get_bytecode(addr)
        self.assertIsNone(eoa_code)
        self.assertFalse(client.is_contract(addr))

    def test_get_chain_id_and_block_number(self):
        client = BlockchainClient(network_name="ethereum")
        mock_instance = MagicMock()
        mock_instance.is_connected.return_value = True
        mock_instance.eth.chain_id = 1
        mock_instance.eth.block_number = 18000000
        client._w3 = mock_instance
        client._connected = True

        self.assertEqual(client.get_chain_id(), 1)
        self.assertEqual(client.get_block_number(), 18000000)

    def test_get_token_metadata_string_abi(self):
        client = BlockchainClient(network_name="ethereum")
        mock_instance = MagicMock()
        mock_instance.is_connected.return_value = True
        client._w3 = mock_instance
        client._connected = True

        mock_contract = MagicMock()
        mock_contract.functions.name().call.return_value = "Test Token"
        mock_contract.functions.symbol().call.return_value = "TT"
        mock_contract.functions.decimals().call.return_value = 18
        mock_contract.functions.totalSupply().call.return_value = 1000000
        mock_instance.eth.contract.return_value = mock_contract

        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        meta = client.get_token_metadata(addr)

        self.assertTrue(meta["is_erc20"])
        self.assertEqual(meta["name"], "Test Token")
        self.assertEqual(meta["symbol"], "TT")
        self.assertEqual(meta["decimals"], 18)
        self.assertEqual(meta["total_supply"], 1000000)

    def test_get_token_metadata_bytes32_fallback(self):
        client = BlockchainClient(network_name="ethereum")
        mock_instance = MagicMock()
        mock_instance.is_connected.return_value = True
        client._w3 = mock_instance
        client._connected = True

        # First contract (string) raises Exception
        mock_str_contract = MagicMock()
        mock_str_contract.functions.name().call.side_effect = Exception("Reverted")
        mock_str_contract.functions.symbol().call.side_effect = Exception("Reverted")
        mock_str_contract.functions.decimals().call.return_value = 18
        mock_str_contract.functions.totalSupply().call.return_value = 5000000

        # Second contract (bytes32) returns bytes32
        mock_b32_contract = MagicMock()
        mock_b32_contract.functions.name().call.return_value = b"MakerToken\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        mock_b32_contract.functions.symbol().call.return_value = b"MKR\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        mock_instance.eth.contract.side_effect = [mock_str_contract, mock_b32_contract]

        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        meta = client.get_token_metadata(addr)

        self.assertTrue(meta["is_erc20"])
        self.assertEqual(meta["name"], "MakerToken")
        self.assertEqual(meta["symbol"], "MKR")

    def test_offline_graceful_handling(self):
        client = BlockchainClient(network_name="ethereum", rpc_url="http://127.0.0.1:19999")
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

        self.assertFalse(client.is_connected())
        self.assertIsNone(client.get_chain_id())
        self.assertIsNone(client.get_bytecode(addr))
        self.assertIsNone(client.get_balance(addr))
        meta = client.get_token_metadata(addr)
        self.assertFalse(meta["is_erc20"])


class TestExplorerClient(unittest.TestCase):
    def setUp(self):
        self.client = ExplorerClient(network_name="ethereum")
        self.addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

    def test_invalid_address(self):
        success, data, err = self.client.get_verified_source("0xBad")
        self.assertFalse(success)
        self.assertIn("Invalid", err)

    @patch("requests.get")
    def test_get_verified_source_single_file(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "1",
            "message": "OK",
            "result": [{
                "ContractName": "CleanToken",
                "CompilerVersion": "v0.8.20+commit.a1b79de6",
                "OptimizationUsed": "1",
                "Runs": "200",
                "ConstructorArguments": "",
                "ABI": '[{"type":"constructor"}]',
                "SourceCode": "contract CleanToken { function test() public {} }",
            }]
        }
        mock_get.return_value = mock_resp

        success, data, err = self.client.get_verified_source(self.addr)
        self.assertTrue(success)
        self.assertIsNone(err)
        self.assertEqual(data["contract_name"], "CleanToken")
        self.assertTrue(data["is_verified"])
        self.assertIn("CleanToken", data["source_code"])

    @patch("requests.get")
    def test_get_verified_source_multi_file_json(self, mock_get):
        multi_json = json.dumps({
            "sources": {
                "IERC20.sol": {"content": "interface IERC20 {}"},
                "Token.sol": {"content": "contract Token is IERC20 {}"},
            }
        })
        # Double-bracket syntax from Etherscan
        wrapped_source = "{{" + multi_json[1:-1] + "}}"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "1",
            "message": "OK",
            "result": [{
                "ContractName": "Token",
                "CompilerVersion": "v0.8.20",
                "ABI": "[]",
                "SourceCode": wrapped_source,
            }]
        }
        mock_get.return_value = mock_resp

        success, data, err = self.client.get_verified_source(self.addr)
        self.assertTrue(success)
        self.assertIn("IERC20.sol", data["source_code"])
        self.assertIn("Token.sol", data["source_code"])

    @patch("requests.get")
    def test_get_verified_source_unverified(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "1",
            "message": "OK",
            "result": [{
                "ContractName": "",
                "SourceCode": "",
            }]
        }
        mock_get.return_value = mock_resp

        success, data, err = self.client.get_verified_source(self.addr)
        self.assertFalse(success)
        self.assertIn("not verified", err)

    @patch("requests.get")
    def test_get_verified_source_rate_limit(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "0",
            "message": "NOTOK",
            "result": "Max rate limit reached",
        }
        mock_get.return_value = mock_resp

        success, data, err = self.client.get_verified_source(self.addr)
        self.assertFalse(success)
        self.assertIn("rate limit", err.lower())

    @patch("requests.get")
    def test_get_contract_abi(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "1",
            "message": "OK",
            "result": '[{"name":"balanceOf","type":"function"}]',
        }
        mock_get.return_value = mock_resp

        success, abi_str, err = self.client.get_contract_abi(self.addr)
        self.assertTrue(success)
        self.assertIn("balanceOf", abi_str)


class TestSimulationAdapter(unittest.TestCase):
    def setUp(self):
        self.addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

    def test_mock_simulator_benign(self):
        adapter = SimulationAdapter(provider="mock", mock_is_honeypot=False, mock_buy_tax=2.5, mock_sell_tax=3.0)
        res = adapter.simulate_token(self.addr)

        self.assertTrue(res.is_available)
        self.assertFalse(res.is_honeypot)
        self.assertEqual(res.buy_tax_percent, 2.5)
        self.assertEqual(res.sell_tax_percent, 3.0)
        self.assertIsNone(res.honeypot_reason)

    def test_mock_simulator_honeypot(self):
        adapter = SimulationAdapter(
            provider="mock",
            mock_is_honeypot=True,
            mock_reason="Transfer simulation failed: TRANSFER_FAILED"
        )
        res = adapter.simulate_token(self.addr)

        self.assertTrue(res.is_available)
        self.assertTrue(res.is_honeypot)
        self.assertIn("TRANSFER_FAILED", res.honeypot_reason)

    @patch("requests.get")
    def test_honeypot_is_mocked_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "honeypotResult": {
                "isHoneypot": True,
                "honeypotReason": "Cannot sell token: execution reverted",
            },
            "simulationResult": {
                "buyTax": 10.0,
                "sellTax": 99.0,
                "buyGas": "150000",
                "sellGas": "0",
            }
        }
        mock_get.return_value = mock_resp

        adapter = SimulationAdapter(provider="honeypot.is")
        res = adapter.simulate_token(self.addr)

        self.assertTrue(res.is_available)
        self.assertTrue(res.is_honeypot)
        self.assertEqual(res.buy_tax_percent, 10.0)
        self.assertEqual(res.sell_tax_percent, 99.0)
        self.assertEqual(res.buy_gas, 150000)
        self.assertIn("Cannot sell token", res.honeypot_reason)

    @patch("requests.get")
    def test_goplus_mocked_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "result": {
                self.addr.lower(): {
                    "is_honeypot": "1",
                    "buy_tax": "0.05",
                    "sell_tax": "0.95",
                }
            }
        }
        mock_get.return_value = mock_resp

        adapter = SimulationAdapter(provider="goplus")
        res = adapter.simulate_token(self.addr)

        self.assertTrue(res.is_available)
        self.assertTrue(res.is_honeypot)
        self.assertEqual(res.buy_tax_percent, 5.0)
        self.assertEqual(res.sell_tax_percent, 95.0)
        self.assertIn("GoPlus flagged", res.honeypot_reason)

    @patch.object(SimulationAdapter, "_query_honeypot_is")
    @patch.object(SimulationAdapter, "_query_goplus")
    def test_auto_cascade(self, mock_goplus, mock_honeypot):
        # Honeypot.is fails
        mock_honeypot.return_value = SimulationResult(
            provider="Honeypot.is",
            is_available=False,
            error_message="API timeout",
        )
        # GoPlus succeeds
        mock_goplus.return_value = SimulationResult(
            provider="GoPlus",
            is_available=True,
            is_honeypot=False,
            buy_tax_percent=1.0,
            sell_tax_percent=1.0,
        )

        adapter = SimulationAdapter(provider="auto")
        res = adapter.simulate_token(self.addr)

        self.assertTrue(res.is_available)
        self.assertEqual(res.provider, "GoPlus")
        self.assertFalse(res.is_honeypot)

    def test_invalid_address(self):
        adapter = SimulationAdapter()
        res = adapter.simulate_token("0xBadAddr")
        self.assertFalse(res.is_available)
        self.assertIn("Invalid address", res.error_message)


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.contract = LoadedContract(
            input_type="file",
            name="TrapToken",
            source_code="contract TrapToken {}",
            address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            network="ethereum",
            is_verified=True,
            is_success=True,
        )
        self.finding = Finding(
            rule_id="HP-001",
            rule_name="Blacklist / Trading Restriction",
            category="Trading Restrictions",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            line_number=42,
            evidence="isBlacklisted[sender] == true",
            explanation="Prevents flagged accounts from transferring.",
            suggested_verification="Audit blacklist modifiers.",
        )
        self.static_analysis = SourceAnalysisResult(
            source_name="TrapToken",
            contract_structure=ContractStructure(
                name="TrapToken",
                pragma="^0.8.0",
                lines_of_code=100,
            ),
            findings=[self.finding],
            positive_indicators=[],
            timestamp="2026-10-14T12:00:00Z",
        )
        self.risk_report = RiskScorer().calculate_risk(self.static_analysis.findings)
        self.simulation = SimulationResult(
            provider="MockSimulator",
            is_available=True,
            is_honeypot=True,
            buy_tax_percent=2.0,
            sell_tax_percent=100.0,
            honeypot_reason="Sell simulation reverted",
        )

    def test_build_report_and_to_dict(self):
        report = ReportGenerator.build_report(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
            simulation=self.simulation,
        )
        data = report.to_dict()

        self.assertEqual(data["contract"]["name"], "TrapToken")
        self.assertGreater(data["risk_assessment"]["risk_score"], 0)
        self.assertEqual(data["simulation"]["is_honeypot"], True)
        self.assertEqual(len(data["static_analysis"]["findings"]), 1)

    def test_json_serialization_and_saving(self):
        report = ReportGenerator.build_report(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
            simulation=self.simulation,
        )
        json_str = report.to_json()
        self.assertIn("TrapToken", json_str)
        self.assertIn("risk_score", json_str)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "sub" / "report.json"
            saved_path = report.save_json(out_file)
            self.assertTrue(saved_path.exists())
            with open(saved_path, "r", encoding="utf-8") as f:
                loaded_data = json.load(f)
            self.assertEqual(loaded_data["contract"]["name"], "TrapToken")

    def test_csv_generation_and_saving(self):
        report = ReportGenerator.build_report(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
        )
        csv_str = report.to_csv()
        self.assertIn("HP-001", csv_str)
        self.assertIn("TrapToken", csv_str)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "report.csv"
            saved = report.save_csv(out_file)
            self.assertTrue(saved.exists())

    def test_csv_clean_contract(self):
        clean_static = SourceAnalysisResult(
            source_name="Clean",
            contract_structure=ContractStructure(
                name="Clean",
                pragma="^0.8.0",
                lines_of_code=50,
            ),
            findings=[],
            positive_indicators=[],
            timestamp="2026-10-14T12:00:00Z",
        )
        clean_risk = RiskScorer().calculate_risk([])
        report = ReportGenerator.build_report(
            contract=self.contract,
            static_analysis=clean_static,
            risk_report=clean_risk,
        )
        csv_str = report.to_csv()
        self.assertIn("No Suspicious Patterns Detected", csv_str)

    def test_to_markdown(self):
        report = ReportGenerator.build_report(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
            simulation=self.simulation,
        )
        md = report.to_markdown()
        self.assertIn("# Honeypot Audit Report: TrapToken", md)
        self.assertIn("/100", md)
        self.assertIn("HP-001", md)
        self.assertIn("Sell simulation reverted", md)

    def test_save_batch_csv(self):
        report1 = ReportGenerator.build_report(
            contract=self.contract,
            static_analysis=self.static_analysis,
            risk_report=self.risk_report,
        )
        clean_contract = LoadedContract(input_type="file", name="SafeCoin", is_success=True)
        report2 = ReportGenerator.build_report(contract=clean_contract)

        with tempfile.TemporaryDirectory() as tmp_dir:
            batch_file = Path(tmp_dir) / "batch.csv"
            saved = ReportGenerator.save_batch_csv([report1, report2], batch_file)
            self.assertTrue(saved.exists())

            with open(saved, "r", encoding="utf-8") as f:
                reader = list(csv.reader(f))
                # Header + 1 finding from report1 + 1 clean row from report2 = 3 rows
                self.assertEqual(len(reader), 3)
                self.assertEqual(reader[0][0], "Contract Name")
                self.assertEqual(reader[1][0], "TrapToken")
                self.assertEqual(reader[2][0], "SafeCoin")


if __name__ == "__main__":
    unittest.main()
