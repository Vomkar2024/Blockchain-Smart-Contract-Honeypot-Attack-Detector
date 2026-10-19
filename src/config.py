"""Configuration settings and environment variable management."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
MODELS_DIR = BASE_DIR / "models"
SAMPLES_DIR = BASE_DIR / "samples"
DATA_DIR = BASE_DIR / "data"

for directory in (REPORTS_DIR, MODELS_DIR, SAMPLES_DIR, DATA_DIR):
    directory.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class NetworkConfig:
    """Configuration for an EVM-compatible blockchain network."""
    name: str
    chain_id: int
    rpc_url: str
    explorer_api_url: str
    explorer_browser_url: str
    api_key_env_var: str


SUPPORTED_NETWORKS: Dict[str, NetworkConfig] = {
    "ethereum": NetworkConfig(
        name="Ethereum Mainnet",
        chain_id=1,
        rpc_url=os.getenv("ETH_RPC_URL", "https://eth-mainnet.public.blastapi.io"),
        explorer_api_url="https://api.etherscan.io/api",
        explorer_browser_url="https://etherscan.io",
        api_key_env_var="ETHERSCAN_API_KEY",
    ),
    "bsc": NetworkConfig(
        name="BNB Smart Chain",
        chain_id=56,
        rpc_url=os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
        explorer_api_url="https://api.bscscan.com/api",
        explorer_browser_url="https://bscscan.com",
        api_key_env_var="BSCSCAN_API_KEY",
    ),
    "polygon": NetworkConfig(
        name="Polygon Mainnet",
        chain_id=137,
        rpc_url=os.getenv("POLYGON_RPC_URL", "https://polygon-rpc.com"),
        explorer_api_url="https://api.polygonscan.com/api",
        explorer_browser_url="https://polygonscan.com",
        api_key_env_var="POLYGONSCAN_API_KEY",
    ),
    "arbitrum": NetworkConfig(
        name="Arbitrum One",
        chain_id=42161,
        rpc_url=os.getenv("ARBITRUM_RPC_URL", "https://arb1.arbitrum.io/rpc"),
        explorer_api_url="https://api.arbiscan.io/api",
        explorer_browser_url="https://arbiscan.io",
        api_key_env_var="ARBISCAN_API_KEY",
    ),
    "sepolia": NetworkConfig(
        name="Sepolia Testnet",
        chain_id=11155111,
        rpc_url=os.getenv("SEPOLIA_RPC_URL", "https://rpc.sepolia.org"),
        explorer_api_url="https://api-sepolia.etherscan.io/api",
        explorer_browser_url="https://sepolia.etherscan.io",
        api_key_env_var="ETHERSCAN_API_KEY",
    ),
}


@dataclass
class RiskThresholds:
    """Configurable boundaries for risk scoring (0-100 scale)."""
    moderate: int = int(os.getenv("RISK_THRESHOLD_MODERATE", "25"))
    high: int = int(os.getenv("RISK_THRESHOLD_HIGH", "50"))
    critical: int = int(os.getenv("RISK_THRESHOLD_CRITICAL", "75"))


@dataclass
class SeverityWeights:
    """Score points assigned per finding severity level."""
    CRITICAL: int = 40
    HIGH: int = 25
    MEDIUM: int = 15
    LOW: int = 5
    INFORMATIONAL: int = 0


@dataclass
class Settings:
    """Master application configuration settings."""
    app_name: str = "Blockchain Smart Contract Honeypot Attack Detector"
    app_version: str = "1.0.0"
    default_network: str = os.getenv("DEFAULT_NETWORK", "ethereum").lower()
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "15"))
    max_source_code_size_kb: int = int(os.getenv("MAX_SOURCE_CODE_SIZE_KB", "1024"))

    # Simulation settings
    honeypot_is_api_url: str = os.getenv(
        "HONEYPOT_IS_API_URL", "https://api.honeypot.is/v2/IsHoneypot"
    )
    goplus_api_url: str = os.getenv(
        "GOPLUS_API_URL", "https://api.gopluslabs.io/api/v1/token_security"
    )

    # Sub-configs
    risk_thresholds: RiskThresholds = field(default_factory=RiskThresholds)
    severity_weights: SeverityWeights = field(default_factory=SeverityWeights)

    # Machine Learning artifacts
    random_forest_model_path: Path = MODELS_DIR / "random_forest_model.joblib"
    logistic_regression_model_path: Path = MODELS_DIR / "logistic_regression_model.joblib"
    scaler_path: Path = MODELS_DIR / "scaler.joblib"
    model_metadata_path: Path = MODELS_DIR / "model_metadata.json"
    dataset_csv_path: Path = DATA_DIR / "sample_contract_features.csv"

    def get_network(self, network_name: str) -> NetworkConfig:
        """Retrieve network configuration by name (case-insensitive)."""
        key = network_name.lower().strip()
        if key not in SUPPORTED_NETWORKS:
            available = ", ".join(SUPPORTED_NETWORKS.keys())
            raise ValueError(
                f"Unsupported network '{network_name}'. Supported networks: {available}"
            )
        return SUPPORTED_NETWORKS[key]

    def get_explorer_api_key(self, network_name: str) -> str:
        """Fetch explorer API key for the given network from environment variables."""
        network = self.get_network(network_name)
        return os.getenv(network.api_key_env_var, "").strip()


# Global settings singleton
settings = Settings()
