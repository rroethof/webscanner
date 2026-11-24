import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / "reporting" / "security_controls.py"
spec = importlib.util.spec_from_file_location("security_controls", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SecurityControlsTests(unittest.TestCase):
    def classify(self, events):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "evidence.json"
            f.write_text(json.dumps({"events": events}))
            return module.classify_evidence(f, "https://bw02.example.org")

    def test_403_alone_is_unverified(self):
        self.assertEqual(self.classify([{"host": "bw02.example.org", "http_status": 403}])["status"], "UNVERIFIED")

    def test_correlated_evidence(self):
        event = {"host": "bw02.example.org", "http_status": 403,
                 "crowdsec_alert_id": "75373", "crowdsec_rule": "crowdsecurity/vpatch-env-access",
                 "proxy_log_reference": "access.log:2026-11-24T08:41:24",
                 "crowdsec_alert_reference": "cscli alerts inspect 75373"}
        data = self.classify([event])
        self.assertEqual(data["status"], "CONTROL_EFFECTIVE")
        self.assertEqual(len(data["events"]), 1)

    def test_other_host_rejected(self):
        self.assertEqual(self.classify([{"host": "other.example.org", "http_status": 403,
            "crowdsec_alert_id": "1", "crowdsec_rule": "rule",
            "proxy_log_reference": "log", "crowdsec_alert_reference": "alert"}])["status"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
