import unittest

from src.providers import AdapterContext, get_adapter, normalize_tool_output


def context(tool_version=None):
    return AdapterContext(
        run_id="run-001",
        target_id="target-001",
        commit="abc123",
        scope_files=2,
        scope_loc=100,
        elapsed_seconds=1.25,
        peak_memory_mb=64.0,
        tool_version=tool_version,
    )


class ProviderAdapterTests(unittest.TestCase):
    def test_semgrep_adapter_normalizes_json(self) -> None:
        payload = {
            "version": "1.100.0",
            "results": [
                {
                    "check_id": "oh.demo-rule",
                    "path": "src/demo.c",
                    "start": {"line": 12, "col": 5},
                    "extra": {
                        "message": "demo candidate",
                        "severity": "WARNING",
                        "metadata": {"cwe": ["CWE-120"]},
                    },
                }
            ],
        }

        result = normalize_tool_output("semgrep", payload, context())

        self.assertEqual(result.tool, "semgrep")
        self.assertEqual(result.tool_version, "1.100.0")
        self.assertEqual(result.diagnostic_count, 1)
        diagnostic = result.diagnostics[0]
        self.assertEqual(diagnostic.evidence_type, "pattern")
        self.assertEqual(diagnostic.file, "src/demo.c")
        self.assertEqual(diagnostic.line, 12)
        self.assertEqual(diagnostic.candidate_cwe, "CWE-120")
        self.assertEqual(diagnostic.confidence, "unassessed")

    def test_codeql_adapter_normalizes_sarif(self) -> None:
        payload = {
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.20.0"}},
                    "results": [
                        {
                            "ruleId": "cpp/path-injection",
                            "level": "warning",
                            "message": {"text": "untrusted path candidate"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/a.cpp"},
                                        "region": {"startLine": 20, "startColumn": 7},
                                    }
                                }
                            ],
                            "properties": {"tags": ["external/cwe/cwe-022"]},
                        }
                    ],
                }
            ]
        }

        result = normalize_tool_output("codeql", payload, context())

        self.assertEqual(result.tool_version, "2.20.0")
        self.assertEqual(result.diagnostic_count, 1)
        diagnostic = result.diagnostics[0]
        self.assertEqual(diagnostic.evidence_type, "dataflow")
        self.assertEqual(diagnostic.rule_id, "cpp/path-injection")
        self.assertEqual(diagnostic.candidate_cwe, "CWE-022")

    def test_clang_adapter_normalizes_existing_baseline_json(self) -> None:
        payload = {
            "clang_version": "Ubuntu clang version 14.0.0",
            "diagnostics": [
                {
                    "file": "cJSON.c",
                    "line": 10,
                    "column": 2,
                    "level": "warning",
                    "message": "example warning [core.NullDereference]",
                    "checker": "core.NullDereference",
                }
            ],
        }

        result = normalize_tool_output("clang", payload, context())

        self.assertEqual(result.tool, "clang_sa")
        self.assertEqual(result.diagnostic_count, 1)
        self.assertEqual(result.diagnostics[0].evidence_type, "symbolic")
        self.assertEqual(result.diagnostics[0].rule_id, "core.NullDereference")

    def test_cppcheck_adapter_normalizes_xml(self) -> None:
        payload = """<?xml version="1.0"?>
<results version="2">
  <cppcheck version="2.14"/>
  <errors>
    <error id="nullPointer" severity="error" msg="Null pointer" verbose="Possible null pointer" cwe="476">
      <location file="src/demo.cpp" line="42" column="9"/>
    </error>
  </errors>
</results>
"""

        result = normalize_tool_output("cppcheck", payload, context())

        self.assertEqual(result.tool_version, "2.14")
        self.assertEqual(result.diagnostic_count, 1)
        diagnostic = result.diagnostics[0]
        self.assertEqual(diagnostic.evidence_type, "syntax")
        self.assertEqual(diagnostic.file, "src/demo.cpp")
        self.assertEqual(diagnostic.candidate_cwe, "CWE-476")

    def test_registry_alias_and_unknown_provider(self) -> None:
        self.assertEqual(get_adapter("clang-static-analyzer").provider, "clang_sa")
        self.assertEqual(get_adapter("joern-cpg").provider, "joern")
        with self.assertRaisesRegex(ValueError, "unsupported provider adapter"):
            get_adapter("unknown-tool")

    def test_joern_adapter_normalizes_query_findings(self) -> None:
        payload = {
            "joern_version": "4.0.649",
            "findings": [
                {
                    "rule_id": "oh-nothrow-alloc-unchecked-deref",
                    "file": "src/bus_center_client_proxy.cpp",
                    "line": 70,
                    "column": 58,
                    "symbol": "ClientOnNodeStatusChanged",
                    "message": "nothrow allocation dereferenced without a null guard",
                    "severity": "warning",
                    "evidence_type": "control_flow",
                    "cwe": ["CWE-476"],
                }
            ],
        }

        result = normalize_tool_output("joern", payload, context())

        self.assertEqual(result.tool, "joern")
        self.assertEqual(result.tool_version, "4.0.649")
        self.assertEqual(result.diagnostic_count, 1)
        diagnostic = result.diagnostics[0]
        self.assertEqual(diagnostic.evidence_type, "control_flow")
        self.assertEqual(diagnostic.file, "src/bus_center_client_proxy.cpp")
        self.assertEqual(diagnostic.line, 70)
        self.assertEqual(diagnostic.column, 58)
        self.assertEqual(diagnostic.symbol, "ClientOnNodeStatusChanged")
        self.assertEqual(diagnostic.rule_id, "oh-nothrow-alloc-unchecked-deref")
        self.assertEqual(diagnostic.candidate_cwe, "CWE-476")

    def test_joern_adapter_accepts_bare_finding_list(self) -> None:
        payload = [
            {"file": "src/a.cpp", "line": 3, "message": "candidate"},
        ]

        result = normalize_tool_output("joern", payload, context(tool_version="4.0.649"))

        self.assertEqual(result.tool_version, "4.0.649")
        self.assertEqual(result.diagnostic_count, 1)
        # A query that declares no evidence type must not have a mechanism
        # invented for it.
        self.assertEqual(result.diagnostics[0].evidence_type, "unknown")

    def test_joern_adapter_models_missing_coordinates_as_unknown(self) -> None:
        payload = {
            "findings": [
                {"file": "src/a.cpp", "line": 0, "column": -1, "message": "synthetic node"}
            ]
        }

        result = normalize_tool_output("joern", payload, context())

        diagnostic = result.diagnostics[0]
        self.assertIsNone(diagnostic.line)
        self.assertIsNone(diagnostic.column)

    def test_joern_adapter_rejects_unsupported_payload(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be a mapping with 'findings'"):
            normalize_tool_output("joern", "not-a-report", context())
        with self.assertRaisesRegex(ValueError, "unsupported evidence_type"):
            normalize_tool_output(
                "joern",
                {"findings": [{"file": "a.cpp", "evidence_type": "made-up"}]},
                context(),
            )


if __name__ == "__main__":
    unittest.main()
