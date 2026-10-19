"""Bounded, source-typed cross-TU caller-role delegation regressions."""
import hashlib
from pathlib import Path
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest


BASE = Path(__file__).parent / "fixtures" / "ipc" / "member_delegation"


def context_sources(items):
    units = []
    ast = {}
    for path, text in sorted(items):
        parsed = parse_source(text, language="cpp")
        unit = SourceUnit(path, "cpp", text,
                          hashlib.sha256(text.encode()).hexdigest(),
                          parsed.parse_status)
        units.append(unit)
        ast[path] = parsed.to_dict()
    request = ScanRequest("ipc-delegation-test", "fixture/ipc",
                          "synthetic-member-delegation-v1",
                          snapshot_digest(tuple(units)), "current-component:fixture/ipc")
    return ScanContext(request, tuple(units), {"ast": ast})


class MemberDelegationTests(unittest.TestCase):
    def test_only_source_typed_terminal_delegate_receives_nested_guard_credit(self):
        header = (BASE / "service.h").read_text()
        fixed = (BASE / "service.cpp").read_text()
        guard_start = fixed.index(
            "    if (!PermissionVerification::GetInstance()->IsSACall()) {")
        guard_end = fixed.index("    }", guard_start) + len("    }")
        guard_end = fixed.index("\n", guard_end) + 1
        vulnerable = fixed[:guard_start] + fixed[guard_end:]
        delegated = (
            "    return appMgrServiceInner_->GetAppRunningStateByBundleName(bundleName);")
        effect_before = fixed.replace(delegated, "    StartAbility();\n" + delegated)
        identity_reset = fixed.replace(
            "    if (!IsReady()) {",
            "    IPCSkeleton::ResetCallingIdentity();\n    if (!IsReady()) {")

        for name, source, expected in (
            ("missing-terminal-guard", vulnerable, True),
            ("nested-source-typed-guard", fixed, False),
            ("modeled-effect-before-delegate", effect_before, True),
            ("identity-reset-before-delegate", identity_reset, True),
        ):
            with self.subTest(case=name):
                ctx = context_sources((("service.h", header), ("service.cpp", source)))
                run = IpcInterfaceDetector().detect(ctx, ctx.units)
                auth02 = [f for f in run.findings if f.rule_id == "ipc.auth.missing"]
                self.assertEqual(bool(auth02), expected)
                if not expected:
                    note = next((item for item in run.limitations
                                 if item.startswith("Cross-TU one-hop guard credited:")), "")
                    self.assertIn("AppMgrServiceInner::GetAppRunningStateByBundleName", note)
                    self.assertIn("admits <sa-caller>", note)

        # The member spelling alone is insufficient if its type is outside scope.
        ctx = context_sources((("service.cpp", fixed),))
        run = IpcInterfaceDetector().detect(ctx, ctx.units)
        self.assertIn("ipc.auth.missing", {f.rule_id for f in run.findings})


if __name__ == "__main__":
    unittest.main()
