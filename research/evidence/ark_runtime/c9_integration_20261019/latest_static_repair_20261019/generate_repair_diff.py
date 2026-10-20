from __future__ import annotations
import difflib, hashlib, json, os, subprocess
from datetime import datetime, timezone
from pathlib import Path
REPO = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c-line-static-20261019")
OUT = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c-line-opt-20261019\research\evidence\ark_runtime\c9_integration_20261019\latest_static_repair_20261019")
HEAD = "09ba5aba03c7c7d6787bace349b8fc0a6b0a5457"
FILES = [
    "src/ohscanner/detectors/ark_runtime/runtime_ir.py",
    "src/ohscanner/detectors/ark_runtime/syntax.py",
    "src/ohscanner/detectors/ark_runtime/type_origin.py",
    "src/ohscanner/detectors/ark_runtime/runtime_exception.py",
    "src/ohscanner/detectors/ark_runtime/size_overflow.py",
    "src/ohscanner/detectors/ark_runtime/receiver_guard.py",
]
def git_bytes(args):
    return subprocess.check_output(["git", "-C", str(REPO), *args])
def text(b):
    return b.decode("utf-8", "surrogateescape")
def main():
    chunks=[]
    for path in FILES:
        old_raw = git_bytes(["show", f"{HEAD}:{path}"]) if path != "src/ohscanner/detectors/ark_runtime/runtime_ir.py" and path != "src/ohscanner/detectors/ark_runtime/syntax.py" and path != "src/ohscanner/detectors/ark_runtime/type_origin.py" and path != "src/ohscanner/detectors/ark_runtime/runtime_exception.py" and path != "src/ohscanner/detectors/ark_runtime/size_overflow.py" else b""
        # All five missing modules are new relative to HEAD; receiver_guard is modified.
        new_raw = (REPO / path).read_bytes()
        old = text(old_raw).splitlines(keepends=True)
        new = text(new_raw).splitlines(keepends=True)
        if old_raw:
            header = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
        else:
            header = f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
        diff = list(difflib.unified_diff(old, new, fromfile=("a/" + path if old_raw else "/dev/null"), tofile=("b/" + path), n=3))
        chunks.append(header + "".join(diff))
    patch = "".join(chunks)
    patch_bytes = patch.encode("utf-8", "surrogateescape")
    (OUT / "repair.diff").write_bytes(patch_bytes)
    patch_sha = hashlib.sha256(patch_bytes).hexdigest()
    changed=[]
    for path in FILES:
        p=REPO/path
        changed.append({"path":path, "sha256":hashlib.sha256(p.read_bytes()).hexdigest(), "bytes":p.stat().st_size})
    summary={
        "schema":"c9-latest-static-repair-summary/v1",
        "generated_at":datetime.now(timezone.utc).isoformat(),
        "checkout":str(REPO),
        "head":HEAD,
        "source_commit":"e4e0761501a83ac25cc67d04c527eefe9f4a1b50",
        "source_tree":"307ac8237263db793028e0bf34a82a85f60821a5",
        "repair_diff":{"path":"repair.diff","sha256":patch_sha,"bytes":len(patch_bytes)},
        "files":changed,
        "scope":"Only src/ohscanner/detectors/ark_runtime and tests/detectors/ark_runtime were eligible; actual edits are source modules only.",
        "semantics":{"detector_version":"0.6.2","static_model_version":"0.8.13","policy":"pinned-source import-completeness only; no contracts/Runner/Catalog/test edits"},
    }
    (OUT/"repair-summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(summary,ensure_ascii=False,indent=2))
if __name__ == "__main__":
    main()


