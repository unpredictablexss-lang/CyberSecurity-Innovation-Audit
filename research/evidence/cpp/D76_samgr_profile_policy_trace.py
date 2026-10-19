from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


SOURCES = {
    "samgr": {
        "commit": "08e2a552b839ea7727251cb9b749a5c1dd9cfeff",
        "repo": "openharmony/systemabilitymgr_samgr",
        "remote": "https://gitcode.com/openharmony/systemabilitymgr_samgr.git",
        "declared_repository": "https://gitee.com/openharmony/systemabilitymgr_samgr",
        "specs": [
            ("bundle.json", r'"repository"', 2, 3),
            ("interfaces/innerkits/common/include/sa_profiles.h", r"struct SaProfile|process;|saId =|libPath|distributed =", 2, 3),
            ("services/common/src/parse_util.cpp", r'SA_TAG_|ParseSaProfiles\(|\.json|ParseJsonFile\(|ParseSystemAbilityGetSaBaseInfo|ParseSystemAbilityGetSaExtInfo|ParseSystemAbility\(|GetStringFromJson\(systemAbilityJson, SA_TAG_|permission', 2, 4),
            ("services/samgr/native/BUILD.gn", r'build_selinux|WITH_SELINUX', 2, 3),
            ("services/samgr/native/source/system_ability_manager_stub.cpp", r'CheckGetSAPermission|GetServiceCheck|GetSystemAbilityInner|CheckSystemAbilityInner|LoadSACheck|CanRequest\(|CheckPermission\(|VerifyAccessToken|GetCallingTokenID', 2, 4),
            ("etc/samgr_standard.cfg", r'"name" : "samgr"|"permission"|"permission_acls"|"secon"', 1, 3),
            ("etc/BUILD.gn", r'samgr_standard\.cfg', 2, 3),
            ("test/resource/profile/profile.json", r'"process"|"systemability"|"name"|"libpath"|permission', 1, 3),
            ("services/common/test/unittest/parse_util_test.cpp", r'ParseSaProfiles\(TEST_RESOURCE_PATH \+ "profile\.json"\)', 2, 4),
        ],
    },
    "startup_init": {
        "commit": "e06651300f349e728c76edda806dbf6496fd620d",
        "repo": "openharmony/startup_init",
        "remote": "https://gitcode.com/openharmony/startup_init.git",
        "specs": [
            ("services/init/init_service_manager.c", r'calloc\(1, sizeof\(Service\)\)|static int GetServiceArgs|permission_acls|ParseOneServiceArgs|GetAccessToken\(\)', 2, 4),
            ("services/init/include/init_service.h", r'permArgs|permAclsArgs|tokenId', 2, 3),
            ("services/init/standard/init_service.c", r'int SetAccessToken|SetSelfTokenID|NativeTokenInfoParams|service->permArgs|service->permAclsArgs|GetAccessTokenId', 2, 4),
            ("services/init/init_common_service.c", r'static int SetPerms|SetAccessToken\(service\)|failed to set permissions|SetServiceContent', 2, 4),
        ],
    },
    "access_token": {
        "commit": "c53a55c371d88c46b0785cc4adb444876e6a9628",
        "repo": "openharmony/security_access_token",
        "remote": "https://gitcode.com/openharmony/security_access_token.git",
        "specs": [
            ("interfaces/innerkits/nativetoken/include/nativetoken_kit.h", r'NativeTokenInfoParams|permsNum|aclsNum|perms;|acls;', 2, 3),
            ("interfaces/innerkits/nativetoken/src/nativetoken.c", r'GetAccessTokenId\(|PrepareAccessTokenId|SyncNativeTokenToKernel', 2, 4),
            ("services/accesstokenmanager/main/cpp/src/permission/accesstoken_info_manager.cpp", r'GetNativePermissionList|native\.apl < briefDef\.availableLevel|native\.nativeAcls|statusList\.emplace_back|VerifyAccessToken\(AccessTokenID tokenID', 2, 4),
            ("interfaces/innerkits/accesstoken/src/accesstoken_kit.cpp", r'AccessTokenKit::VerifyAccessToken\(AccessTokenID tokenID, const std::string& permissionName\)|TransferPermissionToOpcode|GetPermissionFromKernel|AccessTokenManagerClient::GetInstance\(\)\.VerifyAccessToken', 2, 4),
            ("interfaces/innerkits/token_setproc/src/token_setproc.c", r'int SetSelfTokenID|TOKENID_DEVNODE|ACCESS_TOKENID_SET_TOKENID', 2, 3),
        ],
    },
    "D52_historical_pasteboard": {
        "commit": "dd22c7cb5e5f207a6c38c50f45b7369ee8575840",
        "repo": "openharmony/miscservices_pasteboard",
        "remote": "https://gitcode.com/openharmony/miscservices_pasteboard.git",
        "specs": [
            ("profile/BUILD.gn", r'ohos_sa_profile|3701\.xml', 2, 3),
            ("profile/3701.xml", r'<process>|<name>|<libpath>|<distributed>', 1, 3),
            ("etc/init/pasteboardservice.cfg", r'pasteboard_service\.xml|"permission"|"permission_acls"|"secon"', 1, 3),
            ("services/core/src/pasteboard_service.cpp", r'PasteboardService::GetPasteData\(', 2, 5),
        ],
    },
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def extract(repo: Path, commit: str, spec: tuple[str, str, int, int]) -> dict:
    relpath, pattern, before, after = spec
    blob = git(repo, "rev-parse", f"{commit}:{relpath}")
    raw = subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{relpath}"])
    lines = raw.decode("utf-8", "replace").splitlines()
    hits = [i for i, line in enumerate(lines) if re.search(pattern, line)]
    excerpts = []
    for i in hits:
        lo, hi = max(0, i - before), min(len(lines), i + after + 1)
        excerpts.append({"start_line": lo + 1, "end_line": hi,
                         "text": "\n".join(f"{n + 1}: {lines[n]}" for n in range(lo, hi))})
    return {"path": relpath, "blob_oid": blob, "sha256": hashlib.sha256(raw).hexdigest(),
            "matched_line_numbers": [i + 1 for i in hits], "excerpts": excerpts}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--samgr-repo", type=Path, required=True)
    p.add_argument("--init-repo", type=Path, required=True)
    p.add_argument("--access-token-repo", type=Path, required=True)
    p.add_argument("--pasteboard-repo", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    manifest_lines = a.manifest.read_text(encoding="utf-8").splitlines()
    paths = {"samgr": a.samgr_repo, "startup_init": a.init_repo,
             "access_token": a.access_token_repo, "D52_historical_pasteboard": a.pasteboard_repo}
    result = {"audit": "D76 SAMgr profile and service-token policy source trace",
              "manifest_snapshot": {"path": a.manifest.name,
                                    "sha256": hashlib.sha256(a.manifest.read_bytes()).hexdigest(),
                                    "entries": [{"line": n, "text": manifest_lines[n - 1].strip()}
                                                for n in (306, 302, 274)],
                                    "commit": None,
                                    "note": "Provided manifest snapshot; its Git commit is not available in this workspace."},
              "repositories": {}}
    for name, repo in paths.items():
        spec = SOURCES[name]
        commit = spec["commit"]
        result["repositories"][name] = {
            "repo": spec["repo"], "remote": spec["remote"], "commit": commit,
            "tree": git(repo, "rev-parse", f"{commit}^{{tree}}"),
            "evidence": [extract(repo, commit, x) for x in spec["specs"]],
        }
        if "declared_repository" in spec:
            result["repositories"][name]["declared_repository"] = spec["declared_repository"]
    result["controls"] = [
        {"id": "sa-profile-positive-schema", "source": "samgr test/resource/profile/profile.json",
         "expectation": "Parser fixture path is used by ParseSaProfiles unit test; SA JSON profile has no permission fields; parser reads only known SaProfile keys.",
         "execution": "source-bound code-path control; C++ unit test binary not run"},
        {"id": "init-cfg-positive-perms-and-acls", "source": "samgr etc/samgr_standard.cfg",
         "expectation": "Init cfg contains nonempty permission and permission_acls arrays, consumed as service native-token inputs.",
         "execution": "source-bound config and parser/consumer trace; init runtime not run"},
        {"id": "D52-pasteboard-init-cfg-negative-fields", "source": "D52 historical etc/init/pasteboardservice.cfg",
         "expectation": "Pinned component cfg contains neither permission nor permission_acls; installed-profile mapping remains unknown.",
         "execution": "source-bound config inspection; not proof of product merged config"},
    ]
    result["interpretation"] = {
        "samgr_sa_profile_fields": "SaProfile and ParseSystemAbilityGetSaExtInfo do not define/read permission or permission_acls; this SAMgr parser accepts JSON SA profile schema and rejects non-JSON profile paths.",
        "init_service_cfg_fields": "Distinct init service cfg fields are parsed into permission/perms and permission_acls/acls arrays, then passed as inputs to native service AccessToken creation and SetSelfTokenID.",
        "acl_limit": "AccessToken code uses native ACL entries to include permissions despite an APL available-level threshold. This is token construction policy, not a per-caller service ACL. Runtime product effects depend on AccessToken implementation/policy and build.",
        "samgr_query_gate": "SAMgr Get/Check/Load SA operations conditionally call SELinux ServiceChecker with IPC caller SID and SA id; WITH_SELINUX absent returns true. This gates acquiring/returning an SA proxy, not each subsequent binder method call to the SA.",
        "D52_boundary": "D52 profile/3701.xml is XML and its component init cfg path names pasteboard_service.xml. The current SAMgr JSON parser cannot parse that XML. No D52 product manifest/build rule evidence resolves the XML install filename mapping or binds this pinned SAMgr/init/AccessToken revisions to D52 product.",
    }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: {"commit": v["commit"], "tree": v["tree"], "files": len(v["evidence"])}
                      for k, v in result["repositories"].items()}, indent=2))


if __name__ == "__main__":
    main()
