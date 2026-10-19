"""Blockchain Explorer API client (Etherscan, BscScan, PolygonScan, etc.) for fetching verified contract source code."""

import json
import logging
from typing import Dict, Any, Optional, Tuple
import requests

from src.config import settings, NetworkConfig
from src.utils import is_valid_eth_address, to_checksum_address_safe

logger = logging.getLogger(__name__)


class ExplorerClient:
    """
    Client for interacting with Etherscan-compatible block explorer APIs.
    Fetches verified Solidity source code, compiler metadata, and ABI.
    """

    def __init__(self, network_name: str = "ethereum", api_key: Optional[str] = None):
        self.network: NetworkConfig = settings.get_network(network_name)
        self.api_key: str = api_key if api_key is not None else settings.get_explorer_api_key(network_name)

    def _parse_source_code_payload(self, raw_source: str) -> str:
        """
        Handle multi-file or JSON-standard-input formats returned by Etherscan.
        Flattens multi-file JSON dictionaries into concatenated Solidity source.
        """
        if not raw_source:
            return ""

        trimmed = raw_source.strip()

        # Handle double curly brace syntax used by Etherscan standard JSON format: {{ "sources": ... }}
        if trimmed.startswith("{{") and trimmed.endswith("}}"):
            trimmed = trimmed[1:-1]

        if trimmed.startswith("{") and trimmed.endswith("}"):
            try:
                data = json.loads(trimmed)
                # Check standard compiler JSON input format: {"sources": {"file.sol": {"content": "..."}}}
                if "sources" in data and isinstance(data["sources"], dict):
                    combined_parts = []
                    for file_name, file_meta in data["sources"].items():
                        content = file_meta.get("content", "") if isinstance(file_meta, dict) else str(file_meta)
                        combined_parts.append(f"// File: {file_name}\n{content}")
                    return "\n\n".join(combined_parts)
                # Check direct dictionary of filename -> {content: ...} or filename -> string
                combined_parts = []
                for file_name, content in data.items():
                    if isinstance(content, dict) and "content" in content:
                        combined_parts.append(f"// File: {file_name}\n{content['content']}")
                    elif isinstance(content, str):
                        combined_parts.append(f"// File: {file_name}\n{content}")
                if combined_parts:
                    return "\n\n".join(combined_parts)
            except Exception as e:
                logger.debug(f"Failed to parse source as JSON, treating as raw string: {e}")

        return raw_source

    def get_verified_source(self, address: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """
        Fetch verified source code and metadata from the block explorer API.

        Returns:
            (success: bool, data_dict: Dict[str, Any], error_message: Optional[str])
        """
        if not is_valid_eth_address(address):
            return False, {}, f"Invalid EVM address format: {address}"

        checksum_address = to_checksum_address_safe(address)
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": checksum_address,
        }
        if self.api_key:
            params["apikey"] = self.api_key

        url = self.network.explorer_api_url

        try:
            response = requests.get(
                url,
                params=params,
                timeout=settings.request_timeout,
                headers={"User-Agent": "HoneypotDetector/1.0"}
            )
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.Timeout:
            return False, {}, f"Timeout connecting to block explorer for {self.network.name}."
        except requests.exceptions.RequestException as e:
            return False, {}, f"Network error communicating with {self.network.name} explorer: {str(e)}"
        except ValueError:
            return False, {}, f"Explorer returned non-JSON response from {url}."

        status = payload.get("status")
        message = payload.get("message", "")
        result = payload.get("result", [])

        if status != "1" or not result:
            err = payload.get("result", message)
            if "NOTOK" in message or "rate limit" in str(err).lower():
                return False, {}, f"Explorer API rate limit or error: {err}"
            return False, {}, f"Contract source not found or unverified: {err}"

        contract_data = result[0]
        raw_source = contract_data.get("SourceCode", "")

        if not raw_source or raw_source == "":
            return False, {
                "is_verified": False,
                "contract_name": contract_data.get("ContractName", "UnverifiedContract"),
                "compiler_version": contract_data.get("CompilerVersion", ""),
                "address": checksum_address,
                "network": self.network.name,
            }, "Contract source code is not verified on the block explorer."

        parsed_source = self._parse_source_code_payload(raw_source)

        return True, {
            "is_verified": True,
            "contract_name": contract_data.get("ContractName", "VerifiedContract"),
            "compiler_version": contract_data.get("CompilerVersion", ""),
            "optimization_used": contract_data.get("OptimizationUsed", ""),
            "runs": contract_data.get("Runs", ""),
            "constructor_arguments": contract_data.get("ConstructorArguments", ""),
            "abi": contract_data.get("ABI", ""),
            "source_code": parsed_source,
            "address": checksum_address,
            "network": self.network.name,
        }, None

    def get_contract_abi(self, address: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Fetch contract ABI directly from the block explorer API.

        Returns:
            (success: bool, abi_json_str: Optional[str], error_message: Optional[str])
        """
        if not is_valid_eth_address(address):
            return False, None, f"Invalid EVM address format: {address}"

        checksum_address = to_checksum_address_safe(address)
        params = {
            "module": "contract",
            "action": "getabi",
            "address": checksum_address,
        }
        if self.api_key:
            params["apikey"] = self.api_key

        url = self.network.explorer_api_url

        try:
            response = requests.get(
                url,
                params=params,
                timeout=settings.request_timeout,
                headers={"User-Agent": "HoneypotDetector/1.0"}
            )
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as e:
            return False, None, f"Network error fetching ABI: {str(e)}"
        except ValueError:
            return False, None, "Invalid JSON received from explorer API."

        status = payload.get("status")
        result = payload.get("result", "")

        if status == "1" and result:
            return True, result, None

        return False, None, f"Failed to retrieve ABI: {result or payload.get('message', 'Unknown error')}"
