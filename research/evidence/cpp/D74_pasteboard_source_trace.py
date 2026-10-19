from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


SPECS = {
    "D52_historical": [
        ("services/core/include/i_pasteboard_service.h", r"GET_PASTE_DATA|virtual bool GetPasteData", 2, 4),
        ("services/zidl/src/pasteboard_service_stub.cpp", r"memberFuncMap_.*GET_PASTE_DATA|PasteboardServiceStub::OnRemoteRequest|GetCallingPid|PasteboardServiceStub::OnGetPasteData", 2, 5),
        ("services/zidl/src/pasteboard_service_proxy.cpp", r"PasteboardServiceProxy::GetPasteData|SendRequest\(GET_PASTE_DATA", 2, 6),
        ("framework/innerkits/src/pasteboard_client.cpp", r"PasteboardClient::GetPasteData|pasteboardServiceProxy_->GetPasteData|void PasteboardClient::ConnectService", 2, 7),
        ("interfaces/kits/napi/src/napi_pasteboard.cpp", r"SystemPasteboardNapi::GetPasteData|PasteboardClient::GetInstance\(\)->GetPasteData", 2, 7),
        ("services/core/src/pasteboard_service.cpp", r"MakeAndRegisterAbility|PasteboardService::OnStart|PasteboardService::GetPasteData", 2, 7),
        ("utils/native/src/pasteboard_permission.cpp", r"PasteboardPermission::CheckSelfPermission|PasteboardPermission::CheckCallingPermission|MockPermission::VerifyPermission", 2, 6),
        ("profile/3701.xml", r"<process>|<name>|<distributed>", 2, 3),
        ("profile/BUILD.gn", r"ohos_sa_profile|3701.xml", 2, 3),
        ("etc/init/pasteboardservice.cfg", r"pasteboard_service\.xml|secon", 2, 3),
    ],
    "current": [
        ("services/IPasteboardService.idl", r"option_stub_hooks on|ipccode 200.*GetPasteData", 2, 5),
        ("services/BUILD.gn", r"idl_gen_interface\(\"pasteboard_service_interface\"|IPasteboardService\.idl", 2, 5),
        ("services/core/include/pasteboard_service.h", r"class PasteboardService final|virtual int32_t GetPasteData", 2, 5),
        ("framework/innerkits/src/pasteboard_client.cpp", r"PasteboardClient::GetPasteData\(PasteData|proxyService->GetPasteData", 2, 6),
        ("framework/innerkits/src/pasteboard_service_loader.cpp", r"CheckSystemAbility\(PASTEBOARD_SERVICE_ID\)|LoadSystemAbility\(PASTEBOARD_SERVICE_ID", 2, 5),
        ("interfaces/kits/napi/src/napi_systempasteboard.cpp", r"SystemPasteboardNapi::GetData\(|PasteboardClient::GetInstance\(\)->GetPasteData", 2, 6),
        ("services/core/src/pasteboard_service.cpp", r"MakeAndRegisterAbility|PasteboardService::PasteboardService\(|PasteboardService::CallbackEnter|GetPasteDataInner\(|GetCallingTokenID\(\)|!VerifyPermission\(tokenId\)|PasteboardService::VerifyPermission\(|IsPermissionGranted\(READ_PASTEBOARD_PERMISSION|IsPermissionGranted\(SECURE_PASTE_PERMISSION", 2, 6),
        ("etc/init/pasteboardservice.cfg", r"pasteboard_service\.json|permission_acls|ohos\.permission\.READ_PASTEBOARD|secon", 2, 4),
    ],
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def evidence_for(repo: Path, commit: str, spec: tuple[str, str, int, int]) -> dict:
    relpath, pattern, before, after = spec
    blob = git(repo, "rev-parse", f"{commit}:{relpath}")
    source = subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{relpath}"])
    text = source.decode("utf-8", errors="replace")
    lines = text.splitlines()
    hits = [i for i, line in enumerate(lines) if re.search(pattern, line)]
    excerpts = []
    for index in hits:
        lo = max(0, index - before)
        hi = min(len(lines), index + after + 1)
        excerpts.append({"start_line": lo + 1, "end_line": hi,
                         "text": "\n".join(f"{n + 1}: {lines[n]}" for n in range(lo, hi))})
    return {
        "path": relpath,
        "blob_oid": blob,
        "sha256": hashlib.sha256(source).hexdigest(),
        "matched_line_numbers": [i + 1 for i in hits],
        "excerpts": excerpts,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--historical-repo", type=Path, required=True)
    parser.add_argument("--current-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    commits = {
        "D52_historical": ("openharmony/miscservices_pasteboard", "dd22c7cb5e5f207a6c38c50f45b7369ee8575840", args.historical_repo),
        "current": ("openharmony/distributeddatamgr_pasteboard", "e73747b227104e6743e957ce31040edf58507221", args.current_repo),
    }
    result = {"audit": "D74 cross-layer Pasteboard source trace", "repos": {}}
    for label, (name, commit, repo) in commits.items():
        tree = git(repo, "rev-parse", f"{commit}^{{tree}}")
        result["repos"][label] = {
            "repository": name,
            "commit": commit,
            "tree": tree,
            "remote": git(repo, "remote", "get-url", "origin"),
            "evidence": [evidence_for(repo, commit, spec) for spec in SPECS[label]],
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({label: {"commit": value["commit"], "tree": value["tree"],
                              "files": len(value["evidence"])}
                      for label, value in result["repos"].items()}, indent=2))


if __name__ == "__main__":
    main()
