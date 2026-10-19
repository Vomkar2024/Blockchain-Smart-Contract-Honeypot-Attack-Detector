"""Comprehensive Test Suite for Phase 6: Interfaces (CLI & MERN Web App).

Covers:
- Command-line argument parsing and validation in main.py
- CLI execution on benign and honeypot educational contracts
- Output file generation for JSON complete audit reports and CSV findings summaries
- Direct source code string analysis via --code
- ML retraining command invocation (--train-ml)
- Python web application and analysis bridge routines (app.py)
- MERN stack architecture verification (server and client structures)
"""

import json
import os
import sys
import unittest
from pathlib import Path
from src.config import SAMPLES_DIR, REPORTS_DIR
import main
import app


class TestMainCLIParsing(unittest.TestCase):
    """Verifies that command-line argument flags parse correctly."""

    def test_parse_file_flag(self):
        args = main.parse_arguments(["--file", "samples/sample_safe_token.sol"])
        self.assertEqual(args.file, "samples/sample_safe_token.sol")
        self.assertFalse(args.train_ml)

    def test_parse_address_and_network(self):
        args = main.parse_arguments([
            "-a", "0x1234567890123456789012345678901234567890",
            "-n", "bsc"
        ])
        self.assertEqual(args.address, "0x1234567890123456789012345678901234567890")
        self.assertEqual(args.network, "bsc")

    def test_parse_code_flag(self):
        code_snippet = "pragma solidity ^0.8.20; contract Test {}"
        args = main.parse_arguments(["-c", code_snippet])
        self.assertEqual(args.code, code_snippet)

    def test_parse_output_flags(self):
        args = main.parse_arguments([
            "-f", "samples/sample_safe_token.sol",
            "-o", "reports/out.json",
            "--csv-output", "reports/out.csv"
        ])
        self.assertEqual(args.output, "reports/out.json")
        self.assertEqual(args.csv_output, "reports/out.csv")

    def test_parse_train_ml_flag(self):
        args = main.parse_arguments(["--train-ml"])
        self.assertTrue(args.train_ml)


class TestMainCLIExecution(unittest.TestCase):
    """Tests end-to-end execution of main.py across benign, honeypot, and export modes."""

    def setUp(self):
        self.safe_path = SAMPLES_DIR / "sample_safe_token.sol"
        self.honeypot_path = SAMPLES_DIR / "sample_honeypot_token.sol"
        self.test_json_out = REPORTS_DIR / "unit_test_cli_out.json"
        self.test_csv_out = REPORTS_DIR / "unit_test_cli_out.csv"

        # Cleanup prior test outputs if present
        for f in (self.test_json_out, self.test_csv_out):
            if f.exists():
                try: f.unlink()
                except Exception: pass

    def tearDown(self):
        for f in (self.test_json_out, self.test_csv_out):
            if f.exists():
                try: f.unlink()
                except Exception: pass

    def test_cli_safe_token_execution(self):
        """SafeToken should evaluate as LOW risk and exit with code 0."""
        exit_code = main.main(["--file", str(self.safe_path)])
        self.assertEqual(exit_code, 0)

    def test_cli_honeypot_token_execution(self):
        """HoneypotToken should evaluate as CRITICAL risk and exit with code 1."""
        exit_code = main.main(["--file", str(self.honeypot_path)])
        self.assertEqual(exit_code, 1)

    def test_cli_direct_code_execution(self):
        """Direct code input should execute cleanly."""
        code_sample = """pragma solidity ^0.8.20;
contract CleanToken {
    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }
}"""
        exit_code = main.main(["--code", code_sample])
        # Benign simple code should return 0 or 1 based on heuristic / ML, but should not crash
        self.assertIn(exit_code, [0, 1])

    def test_cli_file_exports(self):
        """CLI should generate and persist valid JSON and CSV reports when requested."""
        exit_code = main.main([
            "--file", str(self.safe_path),
            "--output", str(self.test_json_out),
            "--csv-output", str(self.test_csv_out),
        ])
        self.assertEqual(exit_code, 0)

        # Check JSON output
        self.assertTrue(self.test_json_out.exists())
        with open(self.test_json_out, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["contract"]["name"], "SafeToken")
            self.assertEqual(data["risk_assessment"]["risk_level"], "LOW")
            self.assertIn("machine_learning", data)

        # Check CSV output
        self.assertTrue(self.test_csv_out.exists())
        csv_content = self.test_csv_out.read_text(encoding="utf-8")
        self.assertIn("Contract Name", csv_content)
        self.assertIn("SafeToken", csv_content)

    def test_cli_invalid_file(self):
        """Non-existent file should report failure and exit with code 2."""
        exit_code = main.main(["--file", "non_existent_contract_file.sol"])
        self.assertEqual(exit_code, 2)

    def test_cli_train_ml(self):
        """--train-ml flag should successfully retrain and return code 0."""
        exit_code = main.main(["--train-ml"])
        self.assertEqual(exit_code, 0)


class TestAppExecutionBridge(unittest.TestCase):
    """Tests the core analysis routines exposed by app.py."""

    def test_execute_safe_token_audit(self):
        safe_path = SAMPLES_DIR / "sample_safe_token.sol"
        report = app.execute_contract_audit(str(safe_path), input_type="file")
        self.assertTrue(report.contract.is_success)
        self.assertEqual(report.contract.name, "SafeToken")
        self.assertEqual(report.risk_report.risk_level.value, "LOW")
        self.assertFalse(report.ml_prediction["is_honeypot"])
        self.assertEqual(len(report.static_analysis.findings), 0)
        self.assertGreaterEqual(len(report.static_analysis.positive_indicators), 3)

    def test_execute_honeypot_token_audit(self):
        honeypot_path = SAMPLES_DIR / "sample_honeypot_token.sol"
        report = app.execute_contract_audit(str(honeypot_path), input_type="file")
        self.assertTrue(report.contract.is_success)
        self.assertEqual(report.contract.name, "HoneypotToken")
        self.assertEqual(report.risk_report.risk_level.value, "CRITICAL")
        self.assertTrue(report.ml_prediction["is_honeypot"])
        self.assertGreater(len(report.static_analysis.findings), 5)

    def test_app_has_no_streamlit_dependency(self):
        """Verifies that app.py has zero dependencies on streamlit and does not expose render_streamlit_app."""
        self.assertFalse(hasattr(app, "render_streamlit_app"))
        # Check that streamlit is not in sys.modules
        self.assertNotIn("streamlit", sys.modules)


class TestMERNStackIntegrity(unittest.TestCase):
    """Verifies that all MERN backend and frontend components exist and are correctly structured."""

    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.server_dir = self.base_dir / "server"
        self.client_dir = self.base_dir / "client"

    def test_root_package_json_exists(self):
        self.assertTrue((self.base_dir / "package.json").exists())

    def test_server_files_exist(self):
        self.assertTrue((self.server_dir / "package.json").exists())
        self.assertTrue((self.server_dir / "server.js").exists())
        self.assertTrue((self.server_dir / "models" / "AuditReport.js").exists())
        self.assertTrue((self.server_dir / "routes" / "auditRoutes.js").exists())

    def test_client_files_exist(self):
        self.assertTrue((self.client_dir / "package.json").exists())
        self.assertTrue((self.client_dir / "vite.config.js").exists())
        self.assertTrue((self.client_dir / "index.html").exists())
        self.assertTrue((self.client_dir / "src" / "App.jsx").exists())
        self.assertTrue((self.client_dir / "src" / "App.css").exists())
        self.assertTrue((self.client_dir / "src" / "components" / "HeaderMetrics.jsx").exists())
        self.assertTrue((self.client_dir / "src" / "components" / "ContractInput.jsx").exists())
        self.assertTrue((self.client_dir / "src" / "components" / "RiskGauge.jsx").exists())
        self.assertTrue((self.client_dir / "src" / "components" / "FindingsTable.jsx").exists())
        self.assertTrue((self.client_dir / "src" / "components" / "PositiveIndicators.jsx").exists())
        self.assertTrue((self.client_dir / "src" / "components" / "LimitationAdvisories.jsx").exists())
        self.assertTrue((self.client_dir / "src" / "components" / "AuditHistory.jsx").exists())

    def test_client_build_artifact_exists(self):
        dist_dir = self.client_dir / "dist"
        self.assertTrue(dist_dir.exists(), "React Vite production build directory client/dist should exist.")
        self.assertTrue((dist_dir / "index.html").exists())


if __name__ == "__main__":
    unittest.main()
