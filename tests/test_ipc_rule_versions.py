"""IPC rule-version catalogue and finding identity integration contract."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import unittest
from pathlib import Path

from src.ohscanner.detectors.interface import models
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from tests.test_ipc_detector import context, context_sources
from tests.test_ipc_unbounded_observer import SERVICE, STUB


ROOT = Path(__file__).resolve().parent
DETECTOR_ONLY_RULES = {
    "ipc.resource.unbounded-observer-registration",
    "ipc.auth.privileged-app-bypass",
}
RULE_VERSION_BASELINE = {
    "ipc.relay.descriptor-boundary": "1.0.0",
    "ipc.auth.missing": "1.0.0",
    "ipc.auth.guard-coverage": "1.0.0",
    "ipc.auth.caller-class": "1.0.0",
    "ipc.auth.identity-domain": "1.0.0",
    "ipc.auth.request-identity": "1.0.0",
    "ipc.auth.service-identity": "1.0.0",
    "ipc.auth.object-owner": "1.0.0",
    "ipc.network.auth-session-whitelist": "1.0.0",
    "ipc.auth.denial-transport-success": "1.0.0",
    "ipc.parcel.copy-range": "1.0.0",
    "ipc.parcel.position-underflow": "1.0.0",
    "ipc.parcel.bounds": "1.0.0",
    "ipc.parcel.write-bounds": "1.0.0",
    "ipc.tlv.fixed-width-length": "1.0.0",
    "ipc.parcel.array-allocation-width": "0.1.0",
    "ipc.parcel.lifecycle": "1.0.0",
    "ipc.auth.flow": "1.0.0",
    "ipc.data.sensitive-flow": "1.0.0",
    "ipc.capability.export": "1.0.0",
    "ipc.resource.unbounded-observer-registration": "1.0.0",
    "ipc.auth.privileged-app-bypass": "1.0.0",
}


class IpcRuleVersionTests(unittest.TestCase):
    def test_explicit_version_map_covers_every_ipc_rule_and_fails_closed(self):
        versions = getattr(models, "RULE_VERSION_BY_RULE", {})
        expected = set(models.IMPACT_BY_RULE) | DETECTOR_ONLY_RULES

        self.assertEqual(len(models.IMPACT_BY_RULE), 20)
        self.assertEqual(set(versions), expected)
        self.assertEqual(set(RULE_VERSION_BASELINE), expected)
        self.assertTrue(all(isinstance(value, str) and value.strip()
                            for value in versions.values()))
        for rule_id, expected_version in RULE_VERSION_BASELINE.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(versions[rule_id], expected_version)
        self.assertIsNone(versions.get("ipc.rule.not-in-catalogue"))

    def test_detector_runner_preserves_unknown_identity_without_git_blob_oid(self):
        text = (ROOT / "fixtures" / "ipc" / "auth_positive.cpp").read_text(encoding="utf-8")
        scan_context = context(text, "services/ability/ability_stub.cpp")
        registry = DetectorRegistry()
        registry.register(IpcInterfaceDetector())
        reports, _ = run_all_with_coverage(scan_context, registry)
        diagnostic = next(item for item in reports[0].diagnostics
                           if item.rule_id == "ipc.auth.missing")
        versions = getattr(models, "RULE_VERSION_BY_RULE", {})

        self.assertIn(diagnostic.rule_id, versions)
        self.assertEqual(
            diagnostic.finding_identity["observation"]["rule_version"],
            versions[diagnostic.rule_id],
        )
        self.assertEqual(diagnostic.finding_identity["source_binding"]["status"], "unbound")
        self.assertEqual(diagnostic.finding_identity["occurrence"]["status"], "unknown")
        self.assertIn("missing:source_blob_oid",
                      diagnostic.finding_identity["occurrence"]["unknown_reasons"])

    def test_detector_runner_binds_content_derived_git_blob_oid(self):
        text = (ROOT / "fixtures" / "ipc" / "auth_positive.cpp").read_text(encoding="utf-8")
        scan_context = context(text, "services/ability/ability_stub.cpp")
        unit = scan_context.units[0]
        blob_oid = hashlib.sha1(
            b"blob " + str(len(unit.text.encode("utf-8"))).encode("ascii")
            + b"\0" + unit.text.encode("utf-8")
        ).hexdigest()
        scan_context = replace(scan_context, shared_facts={
            **scan_context.shared_facts,
            "source_blob_oid": {unit.path: blob_oid},
        })
        registry = DetectorRegistry()
        registry.register(IpcInterfaceDetector())
        reports, _ = run_all_with_coverage(scan_context, registry)
        diagnostic = next(item for item in reports[0].diagnostics
                           if item.rule_id == "ipc.auth.missing")
        identity = diagnostic.finding_identity

        self.assertEqual(identity["source_binding"]["status"], "bound")
        self.assertEqual(identity["source_binding"]["source_blob_oid"], blob_oid)
        self.assertEqual(identity["source_binding"]["verification"], "not_performed_by_identity_layer")
        self.assertEqual(identity["occurrence"]["status"], "stable")
        self.assertTrue(identity["occurrence"]["id"].startswith("ohocc:v1:"))

    def test_fixture_emissions_always_have_catalogued_versions(self):
        registry = DetectorRegistry()
        registry.register(IpcInterfaceDetector())
        versions = models.RULE_VERSION_BY_RULE
        emitted_rules = set()
        for path in (ROOT / "fixtures" / "ipc").rglob("*.cpp"):
            text = path.read_text(encoding="utf-8")
            scan_context = context(text, path.relative_to(ROOT).as_posix())
            reports, _ = run_all_with_coverage(scan_context, registry)
            for diagnostic in reports[0].diagnostics:
                emitted_rules.add(diagnostic.rule_id)
                self.assertIn(diagnostic.rule_id, versions,
                              msg=f"uncatalogued emitted IPC rule: {diagnostic.rule_id}")
                self.assertEqual(
                    diagnostic.finding_identity["observation"]["rule_version"],
                    versions.get(diagnostic.rule_id),
                    msg=f"uncatalogued or unversioned emitted IPC rule: {diagnostic.rule_id}",
                )
        self.assertTrue({
            "ipc.auth.missing",
            "ipc.auth.denial-transport-success",
            "ipc.network.auth-session-whitelist",
            "ipc.tlv.fixed-width-length",
        }.issubset(emitted_rules))

    def test_detector_only_rules_are_versioned_through_production_runner(self):
        scan_context = context_sources((
            ("stub.cpp", STUB),
            ("service.cpp", SERVICE),
        ))
        registry = DetectorRegistry()
        registry.register(IpcInterfaceDetector())
        reports, _ = run_all_with_coverage(scan_context, registry)
        emitted = {item.rule_id: item for item in reports[0].diagnostics}

        for rule_id in DETECTOR_ONLY_RULES:
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, emitted)
                self.assertEqual(
                    emitted[rule_id].finding_identity["observation"]["rule_version"],
                    models.RULE_VERSION_BY_RULE[rule_id],
                )


if __name__ == "__main__":
    unittest.main()
