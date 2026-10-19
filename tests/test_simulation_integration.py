import unittest
from unittest.mock import patch, MagicMock
from src.simulation_adapter import SimulationAdapter, SimulationResult
import app


class TestSimulationIntegration(unittest.TestCase):
    def setUp(self):
        self.test_addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

    def test_adapter_simulate_alias_with_mock(self):
        adapter = SimulationAdapter(provider="mock", mock_is_honeypot=False, mock_buy_tax=1.2, mock_sell_tax=1.8)
        res = adapter.simulate(self.test_addr, network="ethereum")
        self.assertIsInstance(res, SimulationResult)
        self.assertTrue(res.is_available)
        self.assertFalse(res.is_honeypot)
        self.assertEqual(res.buy_tax_percent, 1.2)
        self.assertEqual(res.sell_tax_percent, 1.8)

    def test_adapter_simulate_invalid_target(self):
        adapter = SimulationAdapter(provider="auto")
        res = adapter.simulate("NonExistentContractName", network="bsc")
        self.assertFalse(res.is_available)
        self.assertIn("Invalid address format", res.error_message)

    def test_app_execute_contract_audit_with_simulation_enabled(self):
        sample_code = """pragma solidity ^0.8.20;
        contract SimpleToken {
            string public name = "Simple";
        }"""
        with patch.object(SimulationAdapter, "simulate") as mock_sim:
            mock_sim.return_value = SimulationResult(
                provider="MockSimulator",
                is_available=True,
                is_honeypot=False,
                buy_tax_percent=0.5,
                sell_tax_percent=0.5,
            )
            report = app.execute_contract_audit(
                contract_input=sample_code,
                input_type="source_code",
                network_name="ethereum",
                simulate=True,
            )
            self.assertIsNotNone(report.simulation)
            self.assertTrue(report.simulation.is_available)
            self.assertEqual(report.simulation.buy_tax_percent, 0.5)

            # Test JSON serialization includes simulation payload
            report_dict = report.to_dict()
            self.assertIn("simulation", report_dict)
            self.assertEqual(report_dict["simulation"]["provider"], "MockSimulator")
