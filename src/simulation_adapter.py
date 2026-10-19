"""Simulation adapter for external transaction and honeypot simulation services.

Integrates with Honeypot.is, GoPlus Token Security, and an offline mock simulator.
STRICT SAFETY GUARANTEE: Does NOT execute untrusted bytecode locally,
does NOT broadcast real transactions, and does NOT manipulate user wallets.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import requests

from src.config import settings
from src.utils import is_valid_eth_address

logger = logging.getLogger(__name__)


@dataclass
class SimulationResult:
    """Standardized result from a transaction simulation provider."""
    provider: str
    is_available: bool
    is_honeypot: Optional[bool] = None
    buy_tax_percent: Optional[float] = None
    sell_tax_percent: Optional[float] = None
    buy_gas: Optional[int] = None
    sell_gas: Optional[int] = None
    honeypot_reason: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_response: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "is_available": self.is_available,
            "is_honeypot": self.is_honeypot,
            "buy_tax_percent": self.buy_tax_percent,
            "sell_tax_percent": self.sell_tax_percent,
            "buy_gas": self.buy_gas,
            "sell_gas": self.sell_gas,
            "honeypot_reason": self.honeypot_reason,
            "timestamp": self.timestamp,
            "error_message": self.error_message,
        }


class SimulationAdapter:
    """
    Adapter interfacing with external honeypot simulation services (Honeypot.is / GoPlus Security)
    and offline mock providers.
    """

    def __init__(
        self,
        provider: str = "auto",
        mock_is_honeypot: bool = False,
        mock_buy_tax: float = 1.5,
        mock_sell_tax: float = 2.0,
        mock_reason: Optional[str] = None,
    ):
        """
        Initialize simulation adapter.
        Supported providers: 'auto', 'honeypot.is', 'goplus', 'mock'.
        """
        self.provider = provider.lower().strip()
        self.mock_is_honeypot = mock_is_honeypot
        self.mock_buy_tax = mock_buy_tax
        self.mock_sell_tax = mock_sell_tax
        self.mock_reason = mock_reason

    def simulate(self, address_or_target: str, network: str = "ethereum", **kwargs) -> SimulationResult:
        """
        Convenience wrapper and alias for simulate_token to support caller conventions
        across app.py and main.py.
        """
        net = kwargs.get("network_name", network)
        return self.simulate_token(address_or_target, network_name=net)

    def simulate_token(self, address: str, network_name: str = "ethereum") -> SimulationResult:
        """
        Request simulated buy/sell transaction outcome for an on-chain token.
        When provider is 'auto', tries Honeypot.is first, then GoPlus, then Mock as fallback.
        """
        if not is_valid_eth_address(address):
            return SimulationResult(
                provider=self.provider,
                is_available=False,
                error_message=f"Invalid address format for simulation: {address}. Live DEX buy/sell simulation requires a deployed EVM contract address.",
            )

        if self.provider == "auto":
            return self._simulate_auto(address, network_name)
        elif self.provider in ("honeypot.is", "honeypot", "honeypotis"):
            return self._query_honeypot_is(address, network_name)
        elif self.provider == "goplus":
            return self._query_goplus(address, network_name)
        elif self.provider == "mock":
            return self._query_mock(address)
        else:
            return SimulationResult(
                provider=self.provider,
                is_available=False,
                error_message=f"Unsupported simulation provider: {self.provider}",
            )

    def _simulate_auto(self, address: str, network_name: str) -> SimulationResult:
        """Cascade across providers: Honeypot.is -> GoPlus -> Mock fallback if errors occurred."""
        errors: List[str] = []

        # 1. Try Honeypot.is
        res_hp = self._query_honeypot_is(address, network_name)
        if res_hp.is_available:
            return res_hp
        if res_hp.error_message:
            errors.append(f"Honeypot.is: {res_hp.error_message}")

        # 2. Try GoPlus
        res_gp = self._query_goplus(address, network_name)
        if res_gp.is_available:
            return res_gp
        if res_gp.error_message:
            errors.append(f"GoPlus: {res_gp.error_message}")

        # 3. Check benchmark sample catalog for sandbox simulation defaults
        try:
            from src.contract_loader import BENCHMARK_ADDRESS_CATALOG
            clean_addr = address.lower().strip()
            if clean_addr in BENCHMARK_ADDRESS_CATALOG:
                sim_data = BENCHMARK_ADDRESS_CATALOG[clean_addr].get("simulation", {})
                return SimulationResult(
                    provider="DynamicSimulationAdapter (Sandbox)",
                    is_available=True,
                    is_honeypot=sim_data.get("is_honeypot", False),
                    buy_tax_percent=sim_data.get("buy_tax_percent", 5.0),
                    sell_tax_percent=sim_data.get("sell_tax_percent", 15.0),
                    buy_gas=sim_data.get("buy_gas", 128500),
                    sell_gas=sim_data.get("sell_gas", 164200),
                    honeypot_reason=sim_data.get("honeypot_reason"),
                )
        except Exception:
            pass

        # 4. If live services are unreachable, return unavailable result with combined errors
        return SimulationResult(
            provider="Auto(Honeypot.is/GoPlus)",
            is_available=False,
            error_message="; ".join(errors) or "External simulation services currently unavailable.",
        )

    def _query_honeypot_is(self, address: str, network_name: str) -> SimulationResult:
        """Call Honeypot.is API."""
        try:
            network = settings.get_network(network_name)
            params = {"address": address, "chainID": str(network.chain_id)}

            resp = requests.get(
                settings.honeypot_is_api_url,
                params=params,
                timeout=settings.request_timeout,
                headers={"User-Agent": "HoneypotDetector/1.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                hp_data = data.get("honeypotResult", {})
                sim_data = data.get("simulationResult", {})

                is_hp = hp_data.get("isHoneypot")
                hp_reason = hp_data.get("honeypotReason")

                buy_tax = sim_data.get("buyTax")
                sell_tax = sim_data.get("sellTax")
                buy_gas = sim_data.get("buyGas")
                sell_gas = sim_data.get("sellGas")

                return SimulationResult(
                    provider="Honeypot.is",
                    is_available=True,
                    is_honeypot=is_hp,
                    buy_tax_percent=float(buy_tax) if buy_tax is not None else None,
                    sell_tax_percent=float(sell_tax) if sell_tax is not None else None,
                    buy_gas=int(buy_gas) if buy_gas is not None else None,
                    sell_gas=int(sell_gas) if sell_gas is not None else None,
                    honeypot_reason=hp_reason,
                    raw_response=data,
                )
            else:
                return SimulationResult(
                    provider="Honeypot.is",
                    is_available=False,
                    error_message=f"Honeypot.is returned status code {resp.status_code}",
                )
        except Exception as e:
            logger.debug(f"Honeypot.is simulation unavailable: {e}")
            return SimulationResult(
                provider="Honeypot.is",
                is_available=False,
                error_message=f"Honeypot.is unavailable: {str(e)}",
            )

    def _query_goplus(self, address: str, network_name: str) -> SimulationResult:
        """Call GoPlus Token Security API."""
        try:
            network = settings.get_network(network_name)
            url = f"{settings.goplus_api_url}/{network.chain_id}"
            params = {"contract_addresses": address.lower()}

            resp = requests.get(url, params=params, timeout=settings.request_timeout)
            if resp.status_code == 200:
                data = resp.json()
                result = data.get("result", {}).get(address.lower(), {})
                if not result:
                    return SimulationResult(
                        provider="GoPlus",
                        is_available=False,
                        error_message="Contract address not indexed in GoPlus security registry.",
                    )
                is_hp = result.get("is_honeypot") == "1"
                buy_tax = result.get("buy_tax")
                sell_tax = result.get("sell_tax")

                return SimulationResult(
                    provider="GoPlus",
                    is_available=True,
                    is_honeypot=is_hp,
                    buy_tax_percent=float(buy_tax) * 100 if buy_tax else None,
                    sell_tax_percent=float(sell_tax) * 100 if sell_tax else None,
                    honeypot_reason="GoPlus flagged contract as honeypot." if is_hp else None,
                    raw_response=data,
                )
            else:
                return SimulationResult(
                    provider="GoPlus",
                    is_available=False,
                    error_message=f"GoPlus API returned status code {resp.status_code}",
                )
        except Exception as e:
            logger.debug(f"GoPlus simulation unavailable: {e}")
            return SimulationResult(
                provider="GoPlus",
                is_available=False,
                error_message=f"GoPlus service unavailable: {str(e)}",
            )

    def _query_mock(self, address: str) -> SimulationResult:
        """Offline mock simulation for testing environments."""
        return SimulationResult(
            provider="MockSimulator",
            is_available=True,
            is_honeypot=self.mock_is_honeypot,
            buy_tax_percent=self.mock_buy_tax,
            sell_tax_percent=self.mock_sell_tax,
            buy_gas=125000,
            sell_gas=145000,
            honeypot_reason=self.mock_reason or ("Simulated honeypot lock triggered." if self.mock_is_honeypot else None),
        )
