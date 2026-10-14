"""Application boundary: pinned Git, approved detectors and immutable reports."""

import hashlib
import json
from pathlib import Path
import re
from src.ohscanner.contracts import safe_relative_path
from src.ohscanner.detectors.catalog import build_registry, catalog_metadata
from src.ohscanner.git_source import _git, resolve_commit, MAX_BLOB_BYTES


def sha(data):
    return hashlib.sha256(data).hexdigest()


def engine_fingerprint():
    root = Path(__file__).resolve().parents[2]
    digest = hashlib.sha256()
    for file in sorted((root / "src").rglob("*.py")):
        if "workbench" in file.relative_to(root / "src").parts:
            continue
        digest.update(str(file.relative_to(root)).encode())
        digest.update(file.read_bytes())
    return digest.hexdigest()


def check_repository(settings, path):
    raw = Path(path).expanduser()
    if raw.is_symlink():
        raise ValueError("repository cannot be a symlink")
    resolved = raw.resolve(strict=True)
    if not any(
        resolved.is_relative_to(root) and resolved != root
        for root in settings.target_roots
    ):
        raise ValueError("repository is outside configured target roots")
    bare = _git(resolved, "rev-parse", "--is-bare-repository").strip()
    if bare not in (b"true", b"false"):
        raise ValueError("not a local Git repository")
    if (
        bare == b"false"
        and Path(
            _git(resolved, "rev-parse", "--show-toplevel").decode().strip()
        ).resolve()
        != resolved
    ):
        raise ValueError("register the repository root, not a subdirectory")
    # No network operations or working-tree source reads.
    return resolved


def revision(repo, requested):
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}", requested)
        or ".." in requested
    ):
        raise ValueError("invalid revision; select a local branch, tag or commit")
    commit = (
        _git(Path(repo["path"]), "rev-parse", "--verify", requested + "^{commit}")
        .decode()
        .strip()
    )
    commit, tree = resolve_commit(Path(repo["path"]), commit)
    return {"requested_revision": requested, "commit": commit, "git_tree": tree}


def revisions(repo):
    text = _git(
        Path(repo["path"]),
        "for-each-ref",
        "--format=%(refname) %(objectname)",
        "refs/heads",
        "refs/tags",
        "refs/remotes",
    ).decode()
    return [
        {"ref": r.split(" ", 1)[0], "object": r.split(" ", 1)[1]}
        for r in text.splitlines()
    ][:2000]


def detector_metadata():
    catalog = catalog_metadata()
    result = []
    for key, spec in catalog.items():
        if spec["kind"] == "example":
            continue
        detector = build_registry((key,)).detectors()[0]
        result.append(
            {
                "id": key,
                **spec,
                "version": detector.version,
                "supported_languages": list(detector.supported_languages),
                "evidence_level": "candidate/unassessed",
            }
        )
    return result


def make_spec(repo, requested, includes, detector_ids, timeout_seconds, memory_mb):
    if not includes or len(includes) > 100 or len(set(includes)) != len(includes):
        raise ValueError("select 1..100 distinct include paths")
    for path in includes:
        if path != ".":
            safe_relative_path(path)
    build_registry(tuple(detector_ids))
    return {
        **revision(repo, requested),
        "repository": repo["name"],
        "include_paths": includes,
        "detector_ids": detector_ids,
        "detector_versions": {
            d["id"]: d["version"]
            for d in detector_metadata()
            if d["id"] in detector_ids
        },
        "timeout_seconds": timeout_seconds,
        "memory_mb": memory_mb,
        "mode": "repository_snapshot",
        "engine_sha256": engine_fingerprint(),
    }


def artifact_dir(settings, key):
    if not re.fullmatch(r"[a-f0-9]{32}", key):
        raise KeyError("invalid job identifier")
    return settings.data_dir / "artifacts" / key


def read_report(settings, job):
    if not job["report_sha256"]:
        raise ValueError("no committed report; analysis is unknown")
    path = artifact_dir(settings, job["id"]) / "report.json"
    data = path.read_bytes()
    if sha(data) != job["report_sha256"]:
        raise ValueError("report integrity check failed")
    report = json.loads(data)
    if (
        report["commit"] != job["spec"]["commit"]
        or report["git_tree"] != job["spec"]["git_tree"]
    ):
        raise ValueError("report source binding mismatch")
    return report


def findings(report):
    result = []
    for run in report["detector_runs"]:
        info = report["detector_coverage"]["detectors"][run["tool"]]
        proof = {e["diagnostic_id"]: e for e in info["evidence_obligations"]}
        for diag in run["diagnostics"]:
            # Observation identity also includes exact run source and algorithm version.
            identity = sha(
                json.dumps(
                    [
                        report["repository"],
                        report["commit"],
                        report["snapshot_sha256"],
                        run["tool"],
                        run["tool_version"],
                        diag["diagnostic_id"],
                    ]
                ).encode()
            )
            result.append(
                {
                    **diag,
                    "id": identity,
                    "detector_id": run["tool"],
                    "detector_version": run["tool_version"],
                    "evidence": proof.get(diag["diagnostic_id"], {}),
                    "review_status": "unassessed",
                    "evidence_level": "candidate",
                }
            )
    return result


def finding_clusters(report):
    """Review-only grouping; this does not infer that observations share a root cause."""
    groups = {}
    for item in findings(report):
        bound = bool(item.get("source_sha256") and item.get("symbol"))
        key = (
            report["repository"], report["commit"], report["snapshot_sha256"],
            item["detector_id"], item["detector_version"], item["rule_id"],
            item["file"], item.get("symbol") or "", item.get("source_sha256") or "",
            "bound" if bound else item["id"],
        )
        group = groups.setdefault(key, {
            "repository": report["repository"], "commit": report["commit"],
            "snapshot_sha256": report["snapshot_sha256"],
            "detector_id": item["detector_id"], "detector_version": item["detector_version"],
            "rule_id": item["rule_id"], "file": item["file"], "symbol": item.get("symbol"),
            "source_sha256": item.get("source_sha256") or None,
            "grouping_basis": (
                "same detector/version, rule, file, symbol, and source hash"
                if bound else "unbound or symbol-less observation; kept separate"
            ),
            "root_cause_conclusion": "not_inferred", "candidates": [],
        })
        message = item.get("message", "")
        if "member write" in message:
            operation = "write"
        elif "member read" in message:
            operation = "read"
        else:
            operation = None
        group["candidates"].append({
            "id": item["id"], "line": item["line"], "column": item.get("column"),
            "operation": operation,
        })

    result = []
    for key, group in groups.items():
        group["candidates"].sort(key=lambda x: (x["line"], x.get("column") or 0, x["id"]))
        identity = json.dumps(
            ["candidate-cluster-v1", *key],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        group["cluster_id"] = hashlib.sha256(identity).hexdigest()
        group["observation_count"] = len(group["candidates"])
        result.append(group)
    return sorted(
        result,
        key=lambda x: (x["file"], x["symbol"] or "", x["rule_id"], x["cluster_id"]),
    )


def finding(report, identity):
    for item in findings(report):
        if item["id"] == identity:
            return item
    raise KeyError("candidate not found in this run")


def source(settings, store, job, file):
    safe_relative_path(file)
    report = read_report(settings, job)
    # Only serve selected source files; never arbitrary host paths or unrelated Git blobs.
    inventory = {p["file"]: p for p in report["_workbench"]["source_inventory"]}
    if file not in inventory:
        raise ValueError("file is outside the scanned source inventory")
    repo = store.repository(job["repository_id"])
    root = check_repository(settings, repo["path"])
    commit = job["spec"]["commit"]
    entry = _git(root, "ls-tree", "-z", commit, "--", file).split(b"\0")[0]
    if not entry:
        raise KeyError("source object missing")
    meta, path = entry.split(b"\t", 1)
    mode, kind, oid = meta.decode().split()
    if mode not in ("100644", "100755") or kind != "blob" or path.decode() != file:
        raise ValueError("source is not a regular tracked blob")
    size = int(_git(root, "cat-file", "-s", oid))
    if size > MAX_BLOB_BYTES:
        raise ValueError("source exceeds viewer size limit")
    data = _git(root, "cat-file", "blob", oid)
    if oid != inventory[file]["blob"] or sha(data) != inventory[file]["sha256"]:
        raise ValueError("source differs from committed scan inventory")
    return {
        "file": file,
        "commit": commit,
        "blob": oid,
        "sha256": sha(data),
        "text": data.decode("utf-8"),
    }


def review_bundle(settings, store, job):
    report = read_report(settings, job)
    return {
        "schema_version": 1,
        "kind": "workbench_review_bundle",
        "job_id": job["id"],
        "repository": report["repository"],
        "commit": report["commit"],
        "git_tree": report["git_tree"],
        "snapshot_sha256": report["snapshot_sha256"],
        "scanner_report_sha256": job["report_sha256"],
        "findings": findings(report),
        "reviews": store.reviews(job["id"]),
        "supplemental_evidence": store.source_evidence(job["id"]),
        "cases": [
            case
            for case in store.cases()
            if any(l["job_id"] == job["id"] for l in case["links"])
        ],
        "validated_vulnerability": 0,
        "limitations": [
            "Manual annotations and case links are not vulnerability confirmation.",
            "No runtime validation or product impact gate implemented in workbench v1.",
        ],
    }


def review_markdown(bundle):
    # Fence JSON avoids treating user notes/paths as report markup; web downloads as attachment.
    return (
        "# OHScanner 审计复核包\n\n候选与复核记录；不是已确认漏洞报告。\n\n"
        + "\n".join(
            [
                "- Commit: " + bundle["commit"],
                "- 原始报告 SHA-256: " + bundle["scanner_report_sha256"],
                "- 候选: " + str(len(bundle["findings"])),
                "- 确认漏洞: 0",
                "",
                "## 复核记录（结构化原文）",
                "",
                "~~~~json",
                json.dumps(bundle, indent=2, ensure_ascii=False).replace(
                    "~~~~", "\\u007e\\u007e\\u007e\\u007e"
                ),
                "~~~~",
                "",
            ]
        )
    )


def source_excerpt(settings, store, job, identity, file, start_line, end_line, note):
    report = read_report(settings, job)
    finding(report, identity)
    src = source(settings, store, job, file)
    lines = src["text"].splitlines(keepends=True)
    if not 1 <= start_line <= end_line <= len(lines) or end_line - start_line >= 100:
        raise ValueError("source excerpt must be 1..100 existing lines")
    excerpt = "".join(lines[start_line - 1 : end_line])
    if len(excerpt.encode("utf-8")) > 65536:
        raise ValueError("source excerpt exceeds 64 KiB")
    return store.add_source_evidence(
        job["id"],
        identity,
        {
            "kind": "source_excerpt",
            "interpretation": "human_selected_context_not_path_or_runtime_proof",
            "repository": report["repository"],
            "commit": src["commit"],
            "git_tree": report["git_tree"],
            "snapshot_sha256": report["snapshot_sha256"],
            "report_sha256": job["report_sha256"],
            "file": file,
            "blob": src["blob"],
            "source_sha256": src["sha256"],
            "start_line": start_line,
            "end_line": end_line,
            "text": excerpt,
            "excerpt_sha256": sha(excerpt.encode("utf-8")),
            "note": note,
        },
    )
