"""Repository-scoped caller-role contract and cross-TU delegation regressions."""
import hashlib
import unittest

from src.ohscanner.contracts import ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.analysis import Interpreter, State, Value
from src.ohscanner.detectors.interface.models import IpcPolicy


STUB = """
class IRemoteStub {};
class AppMgrStub : public IRemoteStub {
public:
    virtual int GetBundleNameByPid(int pid) = 0;
    int HandleGetBundleNameByPid(MessageParcel &data) {
        int pid = data.ReadInt32();
        return GetBundleNameByPid(pid);
    }
};
"""

SERVICE_H = """
class AppMgrServiceInner;
class AppMgrService : public AppMgrStub {
public:
    std::shared_ptr<AppMgrServiceInner> appMgrServiceInner_;
    int GetBundleNameByPid(int pid);
};
class AppMgrServiceInner {
public:
    int GetBundleNameByPid(int pid);
};
"""

SERVICE_CPP = """
int AppMgrService::GetBundleNameByPid(int pid) {
    return appMgrServiceInner_->GetBundleNameByPid(pid);
}
"""

INNER_VULNERABLE = """
int AppMgrServiceInner::GetBundleNameByPid(int pid) {
    return GetAppRunningRecordByPid(pid);
}
"""

INNER_FIXED = """
int AppMgrServiceInner::GetBundleNameByPid(int pid) {
    if (!PermissionVerification::GetInstance()->IsSACall()) {
        return ERR_PERMISSION_DENIED;
    }
    return GetAppRunningRecordByPid(pid);
}
"""

INNER_LATE_GUARD = """
int AppMgrServiceInner::GetBundleNameByPid(int pid) {
    auto record = GetAppRunningRecordByPid(pid);
    if (!PermissionVerification::GetInstance()->IsSACall()) {
        return ERR_PERMISSION_DENIED;
    }
    return record;
}
"""

INNER_WRONG_ROLE = """
int AppMgrServiceInner::GetBundleNameByPid(int pid) {
    if (!TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID())) {
        return ERR_PERMISSION_DENIED;
    }
    return GetAppRunningRecordByPid(pid);
}
"""


def run(role_body, repository="openharmony/ability_ability_runtime"):
    texts = {
        "stub.cpp": STUB,
        "app_mgr_service.h": SERVICE_H,
        "app_mgr_service.cpp": SERVICE_CPP,
        "app_mgr_service_inner.cpp": role_body,
    }
    units = tuple(SourceUnit(
        path, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "complete")
        for path, text in texts.items())
    request = ScanRequest(
        "repo-caller-contract", repository, "synthetic-v1",
        snapshot_digest(units), "current-component:" + repository)
    interpreter = Interpreter(units, IpcPolicy(), request)
    root = next(fn for fn in interpreter.functions
                if fn.owner == "AppMgrStub" and fn.name == "HandleGetBundleNameByPid")
    interpreter.root = root
    interpreter.root_grade = "allowlist"
    interpreter.active = (root,)
    env = {name: Value("parcel", name) for name in root.parcel_params}
    interpreter.block(root, root.body, [State(env=env)], 0)
    return interpreter


class RepositoryCallerContractTests(unittest.TestCase):
    def test_cross_tu_sa_gate_suppresses_target_candidates_after_effect_contract(self):
        interpreter = run(INNER_FIXED)
        self.assertFalse({o.rule for o in interpreter.observations}
                         & {"ipc.auth.missing", "ipc.auth.caller-class"})
        self.assertTrue(any("Cross-TU" in item for item in interpreter.hop_notes))

    def test_missing_sa_gate_emits_candidates_for_exact_repository_contract(self):
        interpreter = run(INNER_VULNERABLE)
        rules = {o.rule for o in interpreter.observations}
        self.assertIn("ipc.auth.missing", rules)
        self.assertIn("ipc.auth.caller-class", rules)

    def test_gate_after_identity_lookup_does_not_satisfy_contract(self):
        interpreter = run(INNER_LATE_GUARD)
        rules = {o.rule for o in interpreter.observations}
        self.assertIn("ipc.auth.missing", rules)
        self.assertIn("ipc.auth.caller-class", rules)

    def test_different_caller_role_does_not_satisfy_sa_contract(self):
        interpreter = run(INNER_WRONG_ROLE)
        rules = {o.rule for o in interpreter.observations}
        self.assertIn("ipc.auth.missing", rules)
        self.assertIn("ipc.auth.caller-class", rules)

    def test_repository_contract_does_not_cross_repository_boundary(self):
        interpreter = run(INNER_VULNERABLE, repository="fixture/other")
        rules = {o.rule for o in interpreter.observations}
        self.assertNotIn("ipc.auth.missing", rules)
        self.assertNotIn("ipc.auth.caller-class", rules)


if __name__ == "__main__":
    unittest.main()
