from __future__ import annotations

import unittest

from src.ohscanner.facts import build_fact_view_v2, build_syntax_facts


class FactViewV2Tests(unittest.TestCase):
    def setUp(self):
        self.ast = {
            "src/a.cpp": {
                "parse_status": "complete",
                "functions": [{"name": "Handle", "start_line": 1, "end_line": 3}],
                "calls": [{"name": "ReadInt32", "line": 2, "arguments": ("parcel",)}],
                "variables": [{"name": "length"}],
            },
            "src/partial.cpp": {
                "parse_status": "partial",
                "functions": [],
                "calls": [],
                "variables": [],
            },
        }

    def test_v1_remains_unchanged_for_history(self):
        v1 = build_syntax_facts(self.ast)
        self.assertEqual(v1["src/a.cpp"]["schema_version"], 1)
        self.assertEqual(v1["src/a.cpp"]["guards"], [])

    def test_v2_exposes_unresolved_facts_without_inventing_proof(self):
        v2 = build_fact_view_v2(self.ast)
        self.assertEqual(v2["src/a.cpp"]["schema_version"], 2)
        self.assertEqual(v2["src/a.cpp"]["call_edges"][0]["resolution_status"], "unresolved")
        self.assertEqual(v2["src/a.cpp"]["cfg_edges"], [])
        self.assertEqual(v2["src/a.cpp"]["ranges"], [])
        self.assertEqual(v2["src/a.cpp"]["taint"], [])
        self.assertTrue(any(item["missing_fact"] == "resolved_call_edge" for item in v2["src/a.cpp"]["unknowns"]))
        self.assertTrue(any(item["subject"] == "source_semantics" for item in v2["src/partial.cpp"]["unknowns"]))

    def test_external_facts_are_explicit_and_bounded(self):
        external = {
            "src/a.cpp": {
                "cfg_edges": [{"source_block": "entry", "target_block": "exit", "dominance_status": "proved"}],
                "ranges": [{"symbol": "length", "minimum": 0, "maximum": 7, "unit": "bytes", "confidence": "derived"}],
                "taint": [{"source": "parcel", "sink": "memcpy", "flow_status": "candidate", "attacker_control": "unknown"}],
            }
        }
        v2 = build_fact_view_v2(self.ast, external)
        self.assertEqual(v2["src/a.cpp"]["ranges"][0]["maximum"], 7)
        self.assertEqual(v2["src/a.cpp"]["taint"][0]["flow_status"], "candidate")


if __name__ == "__main__":
    unittest.main()
