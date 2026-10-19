"""EVM Blockchain Client using Web3.py for RPC communication, bytecode retrieval, and ERC-20 metadata."""

import logging
from typing import Dict, Any, Optional
from src.config import settings, NetworkConfig
from src.utils import is_valid_eth_address, to_checksum_address_safe

logger = logging.getLogger(__name__)

# Standard ERC-20 minimal ABI (string returns)
ERC20_METADATA_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
]

# Legacy ERC-20 ABI (bytes32 returns, e.g. MKR)
ERC20_BYTES32_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "bytes32"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "bytes32"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
]


def _decode_bytes32_string(val: Any) -> Optional[str]:
    """Decode bytes32 or hex value into a clean string, stripping null terminators."""
    if isinstance(val, (bytes, bytearray)):
        try:
            return val.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
        except Exception:
            return None
    elif isinstance(val, str) and val.startswith("0x"):
        try:
            raw_bytes = bytes.fromhex(val[2:])
            return raw_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
        except Exception:
            return None
    return str(val) if val is not None else None


class BlockchainClient:
    """
    Client for querying EVM-compatible blockchains via JSON-RPC.
    Gracefully degrades when offline or RPC endpoint is unreachable.
    """

    def __init__(self, network_name: str = "ethereum", rpc_url: Optional[str] = None):
        self.network: NetworkConfig = settings.get_network(network_name)
        self.rpc_url: str = rpc_url or self.network.rpc_url
        self._w3 = None
        self._connected: Optional[bool] = None

    def _get_web3(self):
        """Lazy initialization of Web3 instance."""
        if self._w3 is None:
            try:
                from web3 import Web3
                self._w3 = Web3(Web3.HTTPProvider(
                    self.rpc_url,
                    request_kwargs={"timeout": settings.request_timeout}
                ))
            except ImportError:
                logger.warning("web3 package not installed or failed to import.")
                return None
            except Exception as e:
                logger.error(f"Error initializing Web3 provider for {self.network.name}: {e}")
                return None
        return self._w3

    def is_connected(self) -> bool:
        """Check if RPC connection is active and responsive."""
        if self._connected is not None:
            return self._connected

        w3 = self._get_web3()
        if w3 is None:
            self._connected = False
            return False

        try:
            self._connected = bool(w3.is_connected())
        except Exception as e:
            logger.warning(f"Failed to connect to RPC {self.rpc_url}: {e}")
            self._connected = False

        return self._connected

    def get_chain_id(self) -> Optional[int]:
        """Fetch current chain ID from provider."""
        if not self.is_connected():
            return None
        try:
            return self._get_web3().eth.chain_id
        except Exception as e:
            logger.error(f"Error fetching chain ID: {e}")
            return None

    def get_block_number(self) -> Optional[int]:
        """Fetch latest block number from the network."""
        if not self.is_connected():
            return None
        try:
            return self._get_web3().eth.block_number
        except Exception as e:
            logger.error(f"Error fetching block number: {e}")
            return None

    def get_balance(self, address: str) -> Optional[int]:
        """Fetch native currency balance (in wei) for an address."""
        if not is_valid_eth_address(address) or not self.is_connected():
            return None
        try:
            w3 = self._get_web3()
            checksum_addr = to_checksum_address_safe(address)
            return w3.eth.get_balance(checksum_addr)
        except Exception as e:
            logger.error(f"Error fetching balance for {address}: {e}")
            return None

    def is_contract(self, address: str) -> bool:
        """Check if an address has deployed code (is a smart contract, not an EOA)."""
        code = self.get_bytecode(address)
        return bool(code and len(code) > 2)

    def get_bytecode(self, address: str) -> Optional[str]:
        """
        Retrieve deployed runtime bytecode for a given contract address.
        Returns hex string (with '0x' prefix) or None if account is an EOA or call fails.
        """
        if not is_valid_eth_address(address):
            raise ValueError(f"Invalid contract address: {address}")

        if not self.is_connected():
            logger.warning(f"Cannot get bytecode: RPC client not connected for {self.network.name}")
            return None

        try:
            w3 = self._get_web3()
            checksum_addr = to_checksum_address_safe(address)
            code_bytes = w3.eth.get_code(checksum_addr)
            hex_code = code_bytes.hex()
            if not hex_code.startswith("0x"):
                hex_code = "0x" + hex_code
            if hex_code in ("0x", "0x0"):
                logger.info(f"Address {address} has no deployed bytecode (EOA).")
                return None
            return hex_code
        except Exception as e:
            logger.error(f"Failed to retrieve bytecode for {address}: {e}")
            return None

    def get_token_metadata(self, address: str) -> Dict[str, Any]:
        """
        Attempt to read standard ERC-20 metadata from the contract.
        Supports standard string returns as well as bytes32 fallbacks.
        Returns a dictionary with name, symbol, decimals, totalSupply, and is_erc20.
        """
        metadata: Dict[str, Any] = {
            "name": None,
            "symbol": None,
            "decimals": None,
            "total_supply": None,
            "is_erc20": False,
        }

        if not is_valid_eth_address(address) or not self.is_connected():
            return metadata

        w3 = self._get_web3()
        if w3 is None:
            return metadata

        checksum_addr = to_checksum_address_safe(address)

        # 1. Try standard string ABI
        try:
            contract = w3.eth.contract(address=checksum_addr, abi=ERC20_METADATA_ABI)

            try:
                metadata["name"] = contract.functions.name().call()
            except Exception:
                pass

            try:
                metadata["symbol"] = contract.functions.symbol().call()
            except Exception:
                pass

            try:
                metadata["decimals"] = contract.functions.decimals().call()
            except Exception:
                pass

            try:
                metadata["total_supply"] = contract.functions.totalSupply().call()
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"Error querying standard ERC-20 metadata for {address}: {e}")

        # 2. If name or symbol failed, try bytes32 ABI (e.g. MKR)
        if metadata["name"] is None or metadata["symbol"] is None:
            try:
                bytes32_contract = w3.eth.contract(address=checksum_addr, abi=ERC20_BYTES32_ABI)
                if metadata["name"] is None:
                    try:
                        raw_name = bytes32_contract.functions.name().call()
                        metadata["name"] = _decode_bytes32_string(raw_name)
                    except Exception:
                        pass
                if metadata["symbol"] is None:
                    try:
                        raw_sym = bytes32_contract.functions.symbol().call()
                        metadata["symbol"] = _decode_bytes32_string(raw_sym)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Error querying bytes32 ERC-20 metadata for {address}: {e}")

        if metadata["name"] is not None or metadata["symbol"] is not None or metadata["total_supply"] is not None:
            metadata["is_erc20"] = True

        return metadata
