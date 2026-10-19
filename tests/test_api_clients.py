"""Unit tests for BlockchainClient and ExplorerClient with mocked network calls."""

import unittest
from unittest.mock import patch, MagicMock
import requests

from src.blockchain_client import BlockchainClient, _decode_bytes32_string
from src.explorer_client import ExplorerClient


class TestBlockchainClientHelpers(unittest.TestCase):
    """Tests for low-level encoding/decoding utilities in blockchain_client."""

    def test_decode_bytes32_string(self):
        # Raw bytes with null terminator
        raw_bytes = b"MKR\x00\x00\x00"
        self.assertEqual(_decode_bytes32_string(raw_bytes), "MKR")

        # Hex encoded string
        hex_str = "0x" + b"DAI\x00\x00".hex()
        self.assertEqual(_decode_bytes32_string(hex_str), "DAI")

        # Standard string
        self.assertEqual(_decode_bytes32_string("USDT"), "USDT")

        # None value
        self.assertIsNone(_decode_bytes32_string(None))


class TestBlockchainClientMethods(unittest.TestCase):
    """Tests for BlockchainClient RPC interactions with Web3 mocked."""

    def setUp(self):
        self.client = BlockchainClient(network_name="ethereum", rpc_url="http://mock-rpc:8545")
        self.valid_address = "0x1234567890123456789012345678901234567890"

    @patch("web3.Web3")
    def test_is_connected(self, mock_web3_cls):
        mock_w3 = MagicMock()
        mock_web3_cls.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        self.client._w3 = mock_w3
        self.assertTrue(self.client.is_connected())

        # Test failure
        self.client._connected = None
        mock_w3.is_connected.side_effect = Exception("RPC down")
        self.assertFalse(self.client.is_connected())

    def test_get_chain_id_and_block_number(self):
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.chain_id = 1
        mock_w3.eth.block_number = 19500000
        self.client._w3 = mock_w3
        self.client._connected = True

        self.assertEqual(self.client.get_chain_id(), 1)
        self.assertEqual(self.client.get_block_number(), 19500000)

        # When offline
        self.client._connected = False
        self.assertIsNone(self.client.get_chain_id())
        self.assertIsNone(self.client.get_block_number())

    def test_get_balance(self):
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.get_balance.return_value = 1000000000000000000
        self.client._w3 = mock_w3
        self.client._connected = True

        # Valid address
        bal = self.client.get_balance(self.valid_address)
        self.assertEqual(bal, 1000000000000000000)

        # Invalid address returns None
        self.assertIsNone(self.client.get_balance("invalid_address"))

    def test_get_bytecode_and_is_contract(self):
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_code = MagicMock()
        mock_code.hex.return_value = "0x6080604052"
        mock_w3.eth.get_code.return_value = mock_code

        self.client._w3 = mock_w3
        self.client._connected = True

        # Contract with bytecode
        code = self.client.get_bytecode(self.valid_address)
        self.assertEqual(code, "0x6080604052")
        self.assertTrue(self.client.is_contract(self.valid_address))

        # EOA address (returns 0x)
        mock_code.hex.return_value = "0x"
        code_eoa = self.client.get_bytecode(self.valid_address)
        self.assertIsNone(code_eoa)
        self.assertFalse(self.client.is_contract(self.valid_address))

        # Invalid address raises ValueError
        with self.assertRaises(ValueError):
            self.client.get_bytecode("invalid_addr")

    def test_get_token_metadata_standard(self):
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True

        mock_contract = MagicMock()
        mock_contract.functions.name().call.return_value = "Tether USD"
        mock_contract.functions.symbol().call.return_value = "USDT"
        mock_contract.functions.decimals().call.return_value = 6
        mock_contract.functions.totalSupply().call.return_value = 1000000000000
        mock_w3.eth.contract.return_value = mock_contract

        self.client._w3 = mock_w3
        self.client._connected = True

        meta = self.client.get_token_metadata(self.valid_address)
        self.assertEqual(meta["name"], "Tether USD")
        self.assertEqual(meta["symbol"], "USDT")
        self.assertEqual(meta["decimals"], 6)
        self.assertEqual(meta["total_supply"], 1000000000000)


class TestExplorerClientMethods(unittest.TestCase):
    """Tests for ExplorerClient payload parsing and API requests with mocked HTTP responses."""

    def setUp(self):
        self.client = ExplorerClient(network_name="ethereum", api_key="TEST_API_KEY")
        self.valid_address = "0x1234567890123456789012345678901234567890"

    def test_parse_source_code_plain_string(self):
        raw = "pragma solidity ^0.8.0; contract Simple {}"
        parsed = self.client._parse_source_code_payload(raw)
        self.assertEqual(parsed, raw)

    def test_parse_source_code_double_brace_json(self):
        json_input = '{{ "sources": { "Token.sol": { "content": "contract Token {}" } } }}'
        parsed = self.client._parse_source_code_payload(json_input)
        self.assertIn("File: Token.sol", parsed)
        self.assertIn("contract Token {}", parsed)

    def test_parse_source_code_single_brace_json(self):
        json_input = '{ "Token.sol": { "content": "contract Token {}" } }'
        parsed = self.client._parse_source_code_payload(json_input)
        self.assertIn("File: Token.sol", parsed)
        self.assertIn("contract Token {}", parsed)

    @patch("requests.get")
    def test_get_verified_source_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "status": "1",
            "message": "OK",
            "result": [{
                "ContractName": "SafeToken",
                "CompilerVersion": "v0.8.20+commit.a1b2c3d4",
                "SourceCode": "contract SafeToken {}",
                "ABI": "[]",
            }]
        }
        mock_get.return_value = mock_resp

        success, data, err = self.client.get_verified_source(self.valid_address)
        self.assertTrue(success)
        self.assertIsNone(err)
        self.assertTrue(data["is_verified"])
        self.assertEqual(data["contract_name"], "SafeToken")

    @patch("requests.get")
    def test_get_verified_source_unverified(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "status": "1",
            "message": "OK",
            "result": [{
                "ContractName": "",
                "CompilerVersion": "",
                "SourceCode": "",
                "ABI": "Contract source code not verified",
            }]
        }
        mock_get.return_value = mock_resp

        success, data, err = self.client.get_verified_source(self.valid_address)
        self.assertFalse(success)
        self.assertFalse(data["is_verified"])
        self.assertIn("not verified", err)

    @patch("requests.get")
    def test_get_verified_source_rate_limit(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "status": "0",
            "message": "NOTOK",
            "result": "Max rate limit reached",
        }
        mock_get.return_value = mock_resp

        success, data, err = self.client.get_verified_source(self.valid_address)
        self.assertFalse(success)
        self.assertIn("rate limit", err.lower())

    @patch("requests.get")
    def test_get_verified_source_timeout(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")
        success, data, err = self.client.get_verified_source(self.valid_address)
        self.assertFalse(success)
        self.assertIn("Timeout connecting", err)


if __name__ == "__main__":
    unittest.main()
