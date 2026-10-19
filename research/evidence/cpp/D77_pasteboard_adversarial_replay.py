from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


D52 = "dd22c7cb5e5f207a6c38c50f45b7369ee8575840"
D52_TREE = "e374a0d61c9ec664ddd29fc17002797828c480ee"
SAMGR = "08e2a552b839ea7727251cb9b749a5c1dd9cfeff"
SAMGR_TREE = "b7a89e95be788f2f2372258e341f7be842c7826d"
INIT = "e06651300f349e728c76edda806dbf6496fd620d"
INIT_TREE = "b77ef22dfc6fa75db5f3707970db9d908a1b6302"
ACCESS_TOKEN = "c53a55c371d88c46b0785cc4adb444876e6a9628"
ACCESS_TOKEN_TREE = "4942df10e6ed926dab1106e5752cf294305240d6"

D52_FILES = [
    "services/core/include/i_pasteboard_service.h",
    "services/zidl/src/pasteboard_service_stub.cpp",
    "services/zidl/src/pasteboard_service_proxy.cpp",
    "framework/innerkits/src/pasteboard_client.cpp",
    "interfaces/kits/napi/src/napi_pasteboard.cpp",
    "services/core/src/pasteboard_service.cpp",
    "utils/native/src/pasteboard_permission.cpp",
    "utils/mock/src/mock_permission.cpp",
    "profile/3701.xml",
    "profile/BUILD.gn",
    "etc/init/pasteboardservice.cfg",
    "services/BUILD.gn",
]


def git(git_dir: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", f"--git-dir={git_dir}", *args], text=True, encoding="utf-8", errors="replace",
        stderr=subprocess.DEVNULL,
    ).strip()


def source(git_dir: Path, commit: str, path: str) -> tuple[bytes, str, str]:
    blob = git(git_dir, "rev-parse", f"{commit}:{path}")
    raw = subprocess.check_output(["git", f"--git-dir={git_dir}", "show", f"{commit}:{path}"])
    return raw, blob, hashlib.sha256(raw).hexdigest()


def excerpts(raw: bytes, patterns: list[str], radius: int = 3) -> dict:
    lines = raw.decode("utf-8", errors="replace").splitlines()
    found = []
    for pattern in patterns:
        hits = [i for i, line in enumerate(lines) if re.search(pattern, line)]
        found.append({
            "pattern": pattern,
            "lines": [i + 1 for i in hits],
            "excerpts": [
                {"start_line": max(1, i + 1 - radius),
                 "text": "\n".join(f"{n + 1}: {lines[n]}" for n in range(max(0, i - radius), min(len(lines), i + radius + 1)))}
                for i in hits
            ],
        })
    return {"line_count": len(lines), "probes": found}


def grep(git_dir: Path, commit: str, pattern: str, paths: list[str]) -> list[str]:
    proc = subprocess.run(
        ["git", f"--git-dir={git_dir}", "grep", "-n", "-E", pattern, commit, "--", *paths],
        text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"git grep failed ({proc.returncode}): {pattern}")
    return proc.stdout.splitlines()


def repo_info(git_dir: Path, commit: str, expected_tree: str, files: list[str]) -> dict:
    tree = git(git_dir, "rev-parse", f"{commit}^{{tree}}")
    evidence = []
    for path in files:
        raw, blob, sha = source(git_dir, commit, path)
        evidence.append({"path": path, "blob_oid": blob, "sha256": sha, "bytes": len(raw)})
    return {"commit": commit, "tree": tree, "expected_tree": expected_tree,
            "tree_matches": tree == expected_tree, "evidence": evidence}


def main() -> None:
    p = argparse.ArgumentParser(description="Replay fixed D52 Pasteboard and SAMgr adversarial probes.")
    p.add_argument("--d52-git-dir", type=Path, required=True, help="Git dir containing D52 historical commit")
    p.add_argument("--samgr-git-dir", type=Path, required=True, help="Git dir containing fixed SAMgr commit")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()

    d52 = repo_info(a.d52_git_dir, D52, D52_TREE, D52_FILES)
    samgr = repo_info(a.samgr_git_dir, SAMGR, SAMGR_TREE,
                      ["services/samgr/native/source/system_ability_manager_stub.cpp",
                       "services/samgr/native/BUILD.gn"])
    core, _, _ = source(a.d52_git_dir, D52, "services/core/src/pasteboard_service.cpp")
    stub, _, _ = source(a.d52_git_dir, D52, "services/zidl/src/pasteboard_service_stub.cpp")
    helper, _, _ = source(a.d52_git_dir, D52, "utils/native/src/pasteboard_permission.cpp")
    mock, _, _ = source(a.d52_git_dir, D52, "utils/mock/src/mock_permission.cpp")
    samgr_stub, _, _ = source(a.samgr_git_dir, SAMGR, "services/samgr/native/source/system_ability_manager_stub.cpp")

    helper_refs = grep(a.d52_git_dir, D52, r"CheckSelfPermission|CheckCallingPermission|MockPermission::VerifyPermission", ["."])
    samgr_get_gate_refs = grep(a.samgr_git_dir, SAMGR, r"CheckGetSAPermission", ["services/samgr/native/source/system_ability_manager_stub.cpp"])
    penglai_refs = grep(a.samgr_git_dir, SAMGR, r"SUPPORT_PENGLAI_MODE|CheckPengLaiPermission", ["services/samgr/native/source/system_ability_manager_stub.cpp"])
    samgr_token_check_refs = grep(a.samgr_git_dir, SAMGR, r"CheckPermission\(", ["services/samgr/native/source/system_ability_manager_stub.cpp"])

    result = {
        "task": "D77 adversarial review",
        "inputs": {
            "D74_commit": "a29275f7a795da17171fd3df2c712ef3a8576cb7",
            "T74_commit": "fb45fcc4d61d1ce3a56eff8386b83f9f3a652ec7",
            "D75_commit": "f3171a784c0e256c5d879ace3aeb78d6acfaf121",
            "D76_commit": "88b357fa0f7d4906e3baff9392c6b27126c88d40",
            "T76_commit": "968ea9852bab858a8eab35ccdd6c4fcc45281cca",
            "D52_repository": "openharmony/miscservices_pasteboard",
            "D52": d52,
            "SAMgr_repository": "openharmony/systemabilitymgr_samgr",
            "SAMgr": samgr,
            "D76_supporting_refs": {
                "startup_init": {"commit": INIT, "tree": INIT_TREE},
                "security_access_token": {"commit": ACCESS_TOKEN, "tree": ACCESS_TOKEN_TREE},
            },
        },
        "probes": {
            "D52_route": {
                "stub": excerpts(stub, [r"memberFuncMap_.*GET_PASTE_DATA", r"OnRemoteRequest\(", r"ReadInterfaceToken", r"GetCallingPid", r"GetCallingUid", r"OnGetPasteData\(", r"GetPasteData\(pasteData\)"]),
                "core": excerpts(core, [r"PasteboardService::GetPasteData\(", r"GetUserId\(\)", r"clips_\.find\(userId\)", r"data = \*\(it->second\)", r"OsAccountManager::GetOsAccountLocalIdFromUid"]),
                "interpretation": "D52 has descriptor/token-shape validation and per-OS-user selection. The latter is caller-identity partitioning and invalid-user failure, not a caller read-permission predicate. PID/UID lines in the stub are logging only.",
            },
            "D52_permission_helpers": {
                "repository_hits": helper_refs,
                "CheckSelfPermission": excerpts(helper, [r"PasteboardPermission::CheckSelfPermission", r"return true"]),
                "CheckCallingPermission": excerpts(helper, [r"PasteboardPermission::CheckCallingPermission", r"MockPermission::VerifyPermission"]),
                "MockPermission": excerpts(mock, [r"MockPermission::VerifyPermission", r"return true"]),
                "interpretation": "Whole-tree hits are definitions/declarations, not a call site on GET_PASTE_DATA. The helper and mock return true, but no reachable route is established.",
            },
            "SAMgr_acquisition_controls": {
                "CheckGetSAPermission_refs": samgr_get_gate_refs,
                "Penglai_mode_refs": penglai_refs,
                "SAMgr_CheckPermission_refs": samgr_token_check_refs,
                "CheckGetSAPermission": excerpts(samgr_stub, [r"bool CheckGetSAPermission", r"WITH_SELINUX", r"return true;.*not check selinux permission"]),
                "GetSystemAbilityInner_and_CheckSystemAbilityInner": excerpts(samgr_stub, [r"int32_t SystemAbilityManagerStub::GetSystemAbilityInner", r"int32_t SystemAbilityManagerStub::CheckSystemAbilityInner", r"if \(!CheckGetSAPermission", r"CheckPengLaiPermission"]),
                "interpretation": "The SAMgr source has conditional SELinux and SUPPORT_PENGLAI_MODE acquisition checks. Other CheckPermission call sites are operation-specific. A successful SA lookup returns a remote object; this source does not show a generic SAMgr policy re-check on each subsequent Pasteboard Binder method.",
            },
        },
        "judgment": {
            "D52_candidate": "retain_narrow_source_only",
            "confirmed": "At the exact D52 component commit, GET_PASTE_DATA reaches the core user-scoped clip lookup/copy without a visible in-component caller read-permission predicate.",
            "counterexample_or_boundary": "The core maps IPC caller UID to an OS account and selects that account's clip; this is isolation and can fail for invalid identity, not permission authorization. SAMgr also has a SUPPORT_PENGLAI_MODE acquisition branch omitted from D76's SELinux-focused explanation; whether it exists in a D52 product is unknown.",
            "external_authorization": "unknown",
            "product_applicability": "unknown",
            "attacker_reachability": "unknown",
            "CVE_causality": "unknown",
            "no_claim": "No product bypass, system-wide absence of authorization, CVE cause, or product safety conclusion.",
        },
        "minimum_additional_evidence": [
            "Exact product fingerprint/build manifest binding D52 component and matching SAMgr/init/AccessToken versions.",
            "Final installed profile and build/install mapping from source profile/3701.xml to the init-referenced /system/profile/pasteboard_service.xml.",
            "Product build flags for WITH_SELINUX and SUPPORT_PENGLAI_MODE, effective SELinux/Penglai SA policy, and product SAMgr checks.",
            "Service-side or framework-level Binder policy/generated hook evidence for each GET_PASTE_DATA call, plus an exact-image authorized/unauthorized caller test.",
        ],
    }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"D52_tree_matches": d52["tree_matches"], "SAMgr_tree_matches": samgr["tree_matches"],
                      "D52_files": len(d52["evidence"]), "SAMgr_files": len(samgr["evidence"]),
                      "D52_permission_hits": len(helper_refs), "SAMgr_peng_lai_hits": len(penglai_refs)}, indent=2))


if __name__ == "__main__":
    main()
