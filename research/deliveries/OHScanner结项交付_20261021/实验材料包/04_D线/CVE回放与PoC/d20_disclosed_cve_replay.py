"""Repeatable candidate scan of disclosed-CVE source blobs from pinned G-drive Git snapshots."""
from __future__ import annotations
import argparse, hashlib, io, json, subprocess, tarfile
from pathlib import Path
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.runner import DetectorRegistry

ROOT = Path(__file__).resolve().parents[2]
MIRROR = Path("/mnt/g/OpenHarmony-GitCode-Mirror")
SPECS = (
    ("third_party_libtiff", MIRROR / "campaign-100-20261017/repos/third_party_libtiff", "d4a0516c477dfbaf1153ae295893ab75aadd63d4", ("libtiff/tif_getimage.c",)),
    ("third_party_curl", MIRROR / "campaign-100-20261017/repos/third_party_curl", "1386bb128bb060b284309397b97adcaaec21c003", ("lib/mime.c",)),
    ("third_party_cJSON", MIRROR / "repos/third_party_cJSON", "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748", ("cJSON.c", "cJSON_Utils.c")),
    ("miscservices_pasteboard", MIRROR / "campaign-100-20261017/repos/miscservices_pasteboard", "dd22c7cb5e5f207a6c38c50f45b7369ee8575840", ("services/core/src/pasteboard_service.cpp", "services/zidl/src/pasteboard_service_stub.cpp")),
)

def signature(report):
    return [(f["file"], f["line"], f["rule_id"], f["source_sha256"]) for run in report["detector_runs"] for f in run["diagnostics"]]

def replay(spec):
    name, repo, commit, paths = spec
    registry = DetectorRegistry(); registry.register(KnownDisclosedCveDetector())
    first = run_reviewed_detectors(repo, f"OpenHarmony-GitCode-Mirror/{name}", commit, paths, registry)
    second = run_reviewed_detectors(repo, f"OpenHarmony-GitCode-Mirror/{name}", commit, paths, registry)
    stable = (first["git_tree"], first["snapshot_sha256"], signature(first), first["detector_coverage"]) == (second["git_tree"], second["snapshot_sha256"], signature(second), second["detector_coverage"])
    if not stable:
        raise RuntimeError(f"pinned replay drift: {name}")
    run = first["detector_runs"][0]
    expected = {
        "third_party_libtiff": {"CVE-2025-9900"},
        "third_party_curl": {"CVE-2026-92391"},
        "third_party_cJSON": {"CVE-2026-67215", "CVE-2026-67216"},
        "miscservices_pasteboard": {"CVE-2025-25212", "CVE-2025-27247"},
    }[name]
    observed = {finding["symbol"] for finding in run["diagnostics"]}
    if not expected.issubset(observed):
        raise RuntimeError(f"expected disclosed-CVE candidate missing for {name}: {sorted(expected - observed)}")
    return {"repository": name, "commit": first["commit"], "tree": first["git_tree"], "snapshot_sha256": first["snapshot_sha256"], "paths": list(paths), "status": run["status"], "coverage": first["detector_coverage"]["detectors"][run["tool"]], "findings": [{"file": f["file"], "line": f["line"], "rule_id": f["rule_id"], "cve": f["symbol"], "source_sha256": f["source_sha256"], "message": f["message"]} for f in run["diagnostics"]], "repeat_equal": stable, "validated_vulnerability": first["validated_vulnerability"]}

def replay_libpng():
    repo = MIRROR / "campaign-100-20261017/repos/third_party_libpng"
    commit = "e57b1079564a"  # audit-report snapshot; resolved to a full commit below
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", f"{commit}^{{commit}}"], text=True).strip()
    data = subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:libpng-1.6.55.tar.gz"])
    tar_sha = hashlib.sha256(data).hexdigest()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = next(m for m in archive.getmembers() if m.isfile() and m.name.endswith("/png.h"))
        raw = archive.extractfile(member).read()
    from src.ohscanner.contracts import SourceUnit
    unit = SourceUnit(path=f"{member.name}", language="c", text=raw.decode("utf-8", errors="strict"), sha256=hashlib.sha256(raw).hexdigest(), parse_status="complete")
    request = ScanRequest(request_id="d20-libpng-"+commit[:12], repository="OpenHarmony-GitCode-Mirror/third_party_libpng", commit=commit, snapshot_sha256=snapshot_digest((unit,)), target_id="current-component:OpenHarmony-GitCode-Mirror/third_party_libpng", profile_id="d20-embedded-source-archive", provenance="fixture")
    units, ast, parsing = index_sources((GitSource(unit.path, "c", hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(), raw),))
    context = ScanContext(request, units, {"ast": ast})
    detector = KnownDisclosedCveDetector()
    a = detector.detect(context, units); b = detector.detect(context, units)
    sig = lambda result: [(f.file, f.line, f.rule_id, f.source_sha256) for f in result.findings]
    stable = sig(a) == sig(b) and a.status == b.status
    if "CVE-2026-46675" not in {finding.symbol for finding in a.findings}:
        raise RuntimeError("expected CVE-2026-46675 candidate missing from pinned libpng archive member")
    return {"repository": "third_party_libpng", "commit": commit, "source_archive_git_blob": subprocess.check_output(["git", "-C", str(repo), "rev-parse", f"{commit}:libpng-1.6.55.tar.gz"], text=True).strip(), "source_archive_sha256": tar_sha, "archive_member": member.name, "member_sha256": hashlib.sha256(raw).hexdigest(), "status": a.status, "findings": [{"file": f.file, "line": f.line, "rule_id": f.rule_id, "cve": f.symbol, "source_sha256": f.source_sha256, "message": f.message} for f in a.findings], "repeat_equal": stable, "scope_note": "The G-drive component repository embeds upstream C sources in a build tarball; this direct first-party detector invocation is pinned to the tracked tarball Git blob and member hash, not a public Runner archive scan."}

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=Path, default=ROOT/"research/data_sensitive/D20_KNOWN_CVE_REPLAY.json"); args = parser.parse_args()
    results = [replay(spec) for spec in SPECS]
    results.insert(0, replay_libpng())
    out = {"schema": 1, "experiment": "D20 pinned disclosed-CVE source replay", "detector": KnownDisclosedCveDetector.detector_id, "detector_version": KnownDisclosedCveDetector.version, "results": results, "limitations": ["All findings remain candidates; validated_vulnerability is zero.", "Replays validate rule hits on reviewed signatures, not independent recall.", "No product entry, build provenance, runtime impact or affected OpenHarmony release was proven.", "Archive member replay for embedded libpng source is not yet supported by the public repository Runner."]}
    args.output.write_text(json.dumps(out, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "cases": [{"repo": r["repository"], "findings": [(f["cve"], f["file"], f["line"]) for f in r["findings"]], "repeat_equal": r["repeat_equal"], "status": r["status"]} for r in results]}, ensure_ascii=False, indent=2))
if __name__ == "__main__": main()
