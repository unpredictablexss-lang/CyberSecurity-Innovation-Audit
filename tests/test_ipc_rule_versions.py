"""IPC rule-version catalogue and finding identity integration contract."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from src.ohscanner.detectors.interface import models
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.identity import build_identity_record, line_byte_range
from tests.test_ipc_detector import context


ROOT = Path(__file__).resolve().parent
DETECTOR_ONLY_RULES = {
    "ipc.resource.unbounded-observer-registration",
    "ipc.auth.privileged-app-bypass",
}


class IpcRuleVersionTests(unittest.TestCase):
    def test_explicit_version_map_covers_every_ipc_rule_and_fails_closed(self):
        versions = getattr(models, "RULE_VERSION_BY_RULE", {})
        expected = set(models.IMPACT_BY_RULE) | DETECTOR_ONLY_RULES

        self.assertEqual(len(models.IMPACT_BY_RULE), 19)
        self.assertEqual(set(versions), expected)
        self.assertTrue(all(isinstance(value, str) and value.strip()
                            for value in versions.values()))
        self.assertIsNone(versions.get("ipc.rule.not-in-catalogue"))

    def test_detector_finding_uses_rule_version_and_forms_bound_occurrence(self):
        text = (ROOT / "fixtures" / "ipc" / "auth_positive.cpp").read_text(encoding="utf-8")
        scan_context = context(text, "services/ability/ability_stub.cpp")
        run = IpcInterfaceDetector().detect(scan_context, scan_context.units)
        finding = next(item for item in run.findings if item.rule_id == "ipc.auth.missing")
        versions = getattr(models, "RULE_VERSION_BY_RULE", {})

        self.assertIn(finding.rule_id, versions)
        self.assertEqual(finding.rule_version, versions[finding.rule_id])

        unit = next(item for item in scan_context.units if item.path == finding.file)
        byte_start, byte_end = line_byte_range(unit.text, finding.line)
        blob_oid = hashlib.sha1(
            b"blob " + str(len(unit.text.encode("utf-8"))).encode("ascii")
            + b"\0" + unit.text.encode("utf-8")
        ).hexdigest()
        identity = build_identity_record({
            "repository": scan_context.request.repository,
            "commit": scan_context.request.commit,
            "snapshot_sha256": scan_context.request.snapshot_sha256,
            "profile_id": scan_context.request.profile_id,
            "legacy_diagnostic_id": "test:ipc-auth-missing",
            "detector_id": IpcInterfaceDetector.detector_id,
            "detector_version": IpcInterfaceDetector.version,
            "rule_id": finding.rule_id,
            "rule_version": finding.rule_version,
            "file": finding.file,
            "line": finding.line,
            "message": finding.message,
            "source_blob_oid": blob_oid,
            "source_sha256": unit.sha256,
            "byte_start": byte_start,
            "byte_end": byte_end,
        })
        self.assertEqual(identity["source_binding"]["status"], "bound")
        self.assertEqual(identity["occurrence"]["status"], "stable")
        self.assertTrue(identity["occurrence"]["id"].startswith("ohocc:v1:"))


if __name__ == "__main__":
    unittest.main()
