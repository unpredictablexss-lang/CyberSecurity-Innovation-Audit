from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
AUDIT = HERE / "t43_taihe_ffi_audit_20261026.json"
RAW = HERE / "t43_taihe_ffi_cli_20261026.json"
SOURCE_REPO = Path(r"D:\openHarmonyScanner\tmp\t43-taihe-source-20261026")
COMMIT = "d91f43e80d892bca694c6b0fce8ea27cd644919f"
TREE = "8c5eecdad09e2fe960ce5f3728959a4726f0a91d"
IDS = [f"CR-{i:04d}" for i in range(197, 214)]


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(SOURCE_REPO), *args], text=True).strip()


def main() -> int:
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    queue_path = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    with queue_path.open(encoding="utf-8-sig", newline="") as f:
        queue = list(csv.DictReader(f))
    rows = {r["queue_id"]: r for r in queue}
    wanted = [rows[q] for q in IDS]
    errors: list[str] = []

    def check(ok: bool, message: str) -> None:
        if not ok:
            errors.append(message)

    check(len(queue) == 345 and len(rows) == 345, "frozen A0 queue count changed")
    check(git("rev-parse", "HEAD") == COMMIT and git("rev-parse", "HEAD^{tree}") == TREE, "pinned Taihe source identity mismatch")
    check(audit["source_identity"]["commit"] == COMMIT and audit["source_identity"]["tree"] == TREE, "audit source identity mismatch")
    check(audit["a0"]["queue_csv_sha256"] == hashlib.sha256(queue_path.read_bytes()).hexdigest(), "A0 CSV hash changed")
    check(audit["a0"]["audited_ids"] == IDS and len(audit["items"]) == 17, "exact 17-row ID scope missing")
    check(raw["source_parsing"]["parsing_status"] == {"complete": 2}, "expected both files to parse completely")
    run = raw["detector_runs"][0]
    check((run["tool"], run["tool_version"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", 16), "unexpected detector replay")
    diag = {(d["file"], int(d["line"])): d for d in run["diagnostics"]}
    by_id = {x["queue_id"]: x for x in audit["items"]}
    check(set(by_id) == set(IDS), "per-ID entries do not match requested IDs")
    for row in wanted:
        item = by_id.get(row["queue_id"])
        check(item is not None, f"{row['queue_id']} missing")
        if not item:
            continue
        check((row["repository"], row["commit"], row["tree"], row["path"], int(row["line"])) == ("openharmony/arkcompiler_taihe_ffi_gen", COMMIT, TREE, item["path"], item["line"]), f"{row['queue_id']} A0 identity mismatch")
        source = git("show", f"{COMMIT}:{row['path']}")
        blob = git("rev-parse", f"{COMMIT}:{row['path']}")
        data = subprocess.check_output(["git", "-C", str(SOURCE_REPO), "show", f"{COMMIT}:{row['path']}"])
        check(blob == row["blob"] == item["source"]["blob"], f"{row['queue_id']} blob mismatch")
        check(hashlib.sha256(data).hexdigest() == row["source_sha256"] == item["source"]["sha256"], f"{row['queue_id']} source hash mismatch")
        check((row["original_status"], row["queue_status"]) == ("not_testable", "paused_pending_evidence"), f"{row['queue_id']} frozen A0 state changed")
        finding = diag.get((row["path"], int(row["line"])))
        check((finding is None) == (item["cli"] is None), f"{row['queue_id']} CLI presence mapping mismatch")
        if finding:
            check(item["cli"]["diagnostic_id"] == finding["diagnostic_id"] and finding["source_sha256"] == row["source_sha256"], f"{row['queue_id']} CLI finding identity mismatch")
    build = audit["build_classification"]
    check(build["result"].startswith("BLOCK_product_target_not_bound"), "build classification must remain blocked")
    check(build["root_build_identity"]["blob"] == git("rev-parse", f"{COMMIT}:BUILD.gn"), "root BUILD identity mismatch")
    check(build["root_build_references_audited_sources"] == {"test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp": False, "test/ra_napi_image/author/include/image_source_taihe.h": False}, "unexpected source build references")
    if errors:
        print("FAIL T43 verifier")
        print("\n".join(errors))
        return 1
    print("PASS T43: 17 exact A0 rows; 16/17 CLI location mappings; both files complete parse; source/build identities and queue preservation verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
