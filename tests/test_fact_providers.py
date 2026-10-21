import unittest

from src.ohscanner.fact_providers import FactProvider, FactProviderRegistry


class FactProviderRegistryTests(unittest.TestCase):
    def test_unrequested_provider_is_not_built(self):
        calls = []
        registry = FactProviderRegistry((FactProvider(
            "syntax", "1.0", "facts_v1", ("ast",), ("cpp",), "low",
            lambda inputs: calls.append("built") or {"file.cc": []},
        ),))
        values, missing, metrics = registry.build({}, (), ("cpp",))
        self.assertEqual(values, {"ast": {}})
        self.assertEqual(missing, ())
        self.assertEqual(calls, [])
        self.assertEqual(metrics["provider_count"], 0)

    def test_requested_fact_runs_provider_once(self):
        calls = []
        registry = FactProviderRegistry((FactProvider(
            "syntax", "1.0", "facts_v1", ("ast",), ("cpp",), "low",
            lambda inputs: calls.append(inputs["ast"]) or {"file.cc": []},
        ),))
        ast = {"file.cc": {"parse_status": "complete"}}
        values, missing, metrics = registry.build(ast, ("facts_v1",), ("cpp",))
        self.assertEqual(values["facts_v1"], {"file.cc": []})
        self.assertEqual(missing, ())
        self.assertEqual(calls, [ast])
        self.assertEqual(metrics["provider_count"], 1)

    def test_unsupported_and_failed_facts_remain_missing(self):
        registry = FactProviderRegistry((FactProvider(
            "cpp_only", "1.0", "cpp_facts", ("ast",), ("cpp",), "medium",
            lambda _inputs: (_ for _ in ()).throw(RuntimeError("no facts")),
        ),))
        values, missing, metrics = registry.build({}, ("cpp_facts",), ("js",))
        self.assertEqual(values, {"ast": {}})
        self.assertEqual(missing, ("cpp_facts",))
        self.assertEqual(metrics["provider_count"], 0)

    def test_duplicate_outputs_rejected(self):
        providers = tuple(FactProvider(
            name, "1.0", "shared_fact", ("ast",), ("cpp",), "low", lambda _: {}
        ) for name in ("one", "two"))
        with self.assertRaises(ValueError):
            FactProviderRegistry(providers)


if __name__ == "__main__":
    unittest.main()
