from __future__ import annotations

import hashlib
import unittest

from src.ohscanner.cross_version import enrich_diagnostic_identity


class CrossVersionExternalIdentityTests(unittest.TestCase):
    def diagnostic(self, line: int, message: str) -> dict:
        source = "namespace OHOS { class DelayedSingleton { std::shared_ptr<int> instance_; }; }"
        return {
            "diagnostic_id": "legacy:" + str(line),
            "provider": "ohscanner.cpp.shared_ptr_race",
            "tool_version": "0.5.0",
            "rule_id": "ohcpp-shared-ptr-race-candidate-001",
            "file": "base/include/singleton.h",
            "line": line,
            "message": message,
            "symbol": "instance_",
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        }

    def test_external_projection_is_stable_when_source_line_moves(self) -> None:
        source = (
            "namespace OHOS { class DelayedSingleton { "
            "std::shared_ptr<int> instance_; "
            "void Set(std::shared_ptr<int> p) { instance_ = p; } "
            "std::shared_ptr<int> Get() { return instance_; } "
            "}; }"
        )
        moved = "// comment moves the source line\n" + source
        first = enrich_diagnostic_identity(
            self.diagnostic(1, "candidate"),
            repository="openharmony/commonlibrary_c_utils",
            commit="a" * 40,
            snapshot_sha256="b" * 64,
            profile_id="light-ast",
            source_blob_oid="c" * 40,
            source_text=source,
            rule_version="1.0.0",
            rule_lineage_id="rule-lineage-v1",
            symbol_identity="OHOS::DelayedSingleton::instance_",
        )
        second = enrich_diagnostic_identity(
            self.diagnostic(2, "candidate"),
            repository="openharmony/commonlibrary_c_utils",
            commit="a" * 40,
            snapshot_sha256="b" * 64,
            profile_id="light-ast",
            source_blob_oid="c" * 40,
            source_text=moved,
            rule_version="1.0.0",
            rule_lineage_id="rule-lineage-v1",
            symbol_identity="OHOS::DelayedSingleton::instance_",
        )
        self.assertEqual(
            first["finding_identity_id"],
            second["finding_identity_id"],
        )
        self.assertNotEqual(first["occurrence_id"], second["occurrence_id"])


if __name__ == "__main__":
    unittest.main()