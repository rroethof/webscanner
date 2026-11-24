import importlib.util
from pathlib import Path
import tempfile
import unittest

src = Path(__file__).resolve().parents[1] / "reporting" / "nuclei_diagnostics.py"
spec = importlib.util.spec_from_file_location("nuclei_diagnostics", src)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NucleiDiagnosticsTests(unittest.TestCase):
    def run_diagnosis(self, log, errors=86):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "nuclei_console.txt"
            p.write_text(log)
            return module.diagnose(p, {"observed": True, "request_errors": errors})

    def test_aggregate_errors_not_assigned_to_crowdsec(self):
        d = self.run_diagnosis("[INF] Errors: 86 | Requests: 17363/17546 (99%)")
        self.assertEqual(d["classification"], "UNKNOWN")
        self.assertEqual(d["unattributed_request_errors"], 86)
        self.assertNotIn("http_403", d["observed_log_signals"])

    def test_403_is_not_waf_proof(self):
        d = self.run_diagnosis("request returned 403 Forbidden\nErrors: 86 | Requests: 17363/17546")
        self.assertIn("http_403", d["observed_log_signals"])
        self.assertEqual(d["unattributed_request_errors"], 86)
        self.assertNotIn("CONTROL_EFFECTIVE", str(d))

    def test_timeout_and_connection_signals(self):
        d = self.run_diagnosis("request timeout\nconnection reset by peer")
        self.assertIn("timeout", d["observed_log_signals"])
        self.assertIn("connection", d["observed_log_signals"])


if __name__ == "__main__":
    unittest.main()
