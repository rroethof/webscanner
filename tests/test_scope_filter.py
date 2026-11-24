import importlib.util
import pathlib
import unittest

FILE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "scope_filter.py"
spec = importlib.util.spec_from_file_location("scope_filter", FILE)
scope_filter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope_filter)


class ScopeFilterTests(unittest.TestCase):
    def test_same_origin_and_dedup(self):
        valid, rejected = scope_filter.filter_urls(
            "https://start.ds.spie-nl.com",
            [
                "https://start.ds.spie-nl.com/a?x=1#fragment",
                "https://start.ds.spie-nl.com/a?x=1",
                "https://start.ds.spie-nl.com/a?x=2",
                "https://cloud.ds.spie-nl.com/private",
                "https://start.ds.spie-nl.com.evil.example/x",
                "https://start.ds.spie-nl.com@evil.example/x",
                "https://start.ds.spie-nl.com:8443/admin",
                "http://start.ds.spie-nl.com/",
                "javascript:alert(1)",
            ],
        )
        self.assertEqual(valid, [
            "https://start.ds.spie-nl.com/a?x=1",
            "https://start.ds.spie-nl.com/a?x=2",
        ])
        self.assertEqual(len(rejected), 6)

    def test_explicit_port_and_case(self):
        valid, rejected = scope_filter.filter_urls(
            "https://EXAMPLE.org:8443/",
            ["https://example.org:8443/test", "https://example.org/test"],
        )
        self.assertEqual(valid, ["https://example.org:8443/test"])
        self.assertEqual(len(rejected), 1)

    def test_invalid_target(self):
        with self.assertRaises(ValueError):
            scope_filter.filter_urls("example.org", [])


if __name__ == "__main__":
    unittest.main()
