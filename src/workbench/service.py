"""Application boundary: pinned Git, approved detectors and immutable reports."""

import hashlib
import json
from pathlib import Path
import re
import os
import subprocess
import sys
from .triage_limits import (MAX_TRIAGE_CANDIDATES_PER_ENDPOINT,
                            R1_CANDIDATE_SELECTION_POLICY)
from src.ohscanner.contracts import safe_relative_path
from src.ohscanner.detectors.admission import pending_admissions
from src.ohscanner.detectors.catalog import build_registry, catalog_metadata
from src.ohscanner.git_source import _git, resolve_commit, MAX_BLOB_BYTES


def sha(data):
    return hashlib.sha256(data).hexdigest()


def audit_workflow_sha256(plan_sha256, audit_mode, auto_triage=False,
                          max_triage_candidates=3, max_r2_candidates=0,
                          max_cost_usd=None, progressive_policy_sha256=None):
    if audit_mode not in {"standard_review", "static_only"}:
        raise ValueError("unsupported audit workflow mode")
    if (not isinstance(auto_triage, bool)
            or not isinstance(max_triage_candidates, int)
            or isinstance(max_triage_candidates, bool)
            or not 1 <= max_triage_candidates <= MAX_TRIAGE_CANDIDATES_PER_ENDPOINT
            or not isinstance(max_r2_candidates, int)
            or isinstance(max_r2_candidates, bool)
            or not 0 <= max_r2_candidates <= max_triage_candidates):
        raise ValueError("invalid triage workflow budget")
    payload = {
        "version": 6, "plan_sha256": plan_sha256, "audit_mode": audit_mode,
        "auto_triage": auto_triage if audit_mode == "standard_review" else False,
        "max_triage_candidates": max_triage_candidates if auto_triage and audit_mode == "standard_review" else 0,
        "max_r2_candidates": (max_r2_candidates
                              if auto_triage and audit_mode == "standard_review" else 0),
        "candidate_selection_policy": R1_CANDIDATE_SELECTION_POLICY
        if auto_triage and audit_mode == "standard_review" else None,
        "candidate_max_per_endpoint": MAX_TRIAGE_CANDIDATES_PER_ENDPOINT
        if auto_triage and audit_mode == "standard_review" else 0,
        "agent_usage_policy": "no_local_cumulative_token_usd_call_or_wall_time_cap_v1"
        if auto_triage and audit_mode == "standard_review" else None,
    }
    if progressive_policy_sha256 is not None:
        if (not isinstance(progressive_policy_sha256, str)
                or not re.fullmatch(r"[a-f0-9]{64}", progressive_policy_sha256)):
            raise ValueError("invalid progressive triage policy digest")
        payload["progressive_policy_sha256"] = progressive_policy_sha256
    return sha(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def audit_workflow_summary(audit_mode, auto_triage=False,
                           max_triage_candidates=3, max_r2_candidates=0,
                           max_cost_usd=None):
    if audit_mode == "standard_review":
        return {
            "scan_stage": "fixed_static_scan",
            "triage_stage": ("task_authorized_r1_conditional_continuous_r2"
                             if auto_triage and max_r2_candidates
                             else "task_authorized_r1" if auto_triage
                             else "user_authorized_candidate_batch"),
            "automatic_model_calls": bool(auto_triage),
            "candidate_limit_per_authorized_batch": max_triage_candidates if auto_triage else 5,
            "candidate_selection_policy": R1_CANDIDATE_SELECTION_POLICY if auto_triage else None,
            "candidate_max_per_endpoint": MAX_TRIAGE_CANDIDATES_PER_ENDPOINT if auto_triage else 0,
            "conditional_r2_candidate_limit": max_r2_candidates if auto_triage else 0,
            "platform_cumulative_usage_budget": "none" if auto_triage else None,
            "provider_billing_and_quota": "provider_account" if auto_triage else None,
            "source_consent_required": True,
        }
    if audit_mode == "static_only":
        return {
            "scan_stage": "fixed_static_scan",
            "triage_stage": "not_requested",
            "automatic_model_calls": False,
            "source_consent_required": False,
        }
    raise ValueError("unsupported audit workflow mode")


ENGINE_MODEL_FILES = (
    "src/ohscanner/detectors/data/historical_profiles.json",
)  # Freeze D exact-revision profile data with the engine identity.


def engine_fingerprint():
    root = Path(__file__).resolve().parents[2]
    digest = hashlib.sha256()
    for file in sorted((root / "src").rglob("*.py")):
        relative = file.relative_to(root / "src")
        if "workbench" in relative.parts and not (
            relative.parts[:2] in (("workbench", "planning"), ("workbench", "sources"))
            or relative.as_posix() == "workbench/plan_child.py"
        ):
            continue
        digest.update(str(file.relative_to(root)).encode())
        digest.update(file.read_bytes())
    for relative in ENGINE_MODEL_FILES:
        file = root / relative
        digest.update(relative.encode())
        digest.update(file.read_bytes())
    return digest.hexdigest()


def _inside_any_root(path, roots):
    return any(path.is_relative_to(root) for root in roots)


def _git_metadata_directories(repository, roots):
    marker = repository / ".git"
    if marker.is_symlink():
        raise ValueError("repository Git metadata cannot be a symlink")
    if marker.is_dir():
        git_dir = marker.resolve(strict=True)
    elif marker.is_file():
        try:
            content = marker.read_text(encoding="utf-8")[:4096].strip()
        except (OSError, UnicodeError) as error:
            raise ValueError("repository Git directory pointer is unreadable") from error
        if not content.lower().startswith("gitdir:"):
            raise ValueError("repository Git directory pointer is invalid")
        target = Path(content.split(":", 1)[1].strip()).expanduser()
        target = target if target.is_absolute() else repository / target
        if target.is_symlink():
            raise ValueError("repository Git directory cannot be a symlink")
        git_dir = target.resolve(strict=True)
    else:
        # A bare repository stores its Git metadata in the repository directory.
        git_dir = repository

    if not _inside_any_root(git_dir, roots):
        raise ValueError("repository Git metadata is outside configured target roots")

    common_dir = git_dir
    common_file = git_dir / "commondir"
    if common_file.is_symlink():
        raise ValueError("repository Git common directory cannot be a symlink")
    if common_file.is_file():
        try:
            value = common_file.read_text(encoding="utf-8")[:4096].strip()
        except (OSError, UnicodeError) as error:
            raise ValueError("repository Git common directory pointer is unreadable") from error
        target = Path(value).expanduser()
        target = target if target.is_absolute() else git_dir / target
        if target.is_symlink():
            raise ValueError("repository Git common directory cannot be a symlink")
        common_dir = target.resolve(strict=True)
        if not _inside_any_root(common_dir, roots):
            raise ValueError("repository Git common directory is outside configured target roots")

    for object_dir in {git_dir / "objects", common_dir / "objects"}:
        if object_dir.is_symlink():
            raise ValueError("repository Git objects cannot be a symlink")
        alternates = object_dir / "info" / "alternates"
        if alternates.is_symlink():
            raise ValueError("repository Git alternates cannot be a symlink")
        if not alternates.is_file():
            continue
        try:
            entries = alternates.read_text(encoding="utf-8")[:65536].splitlines()
        except (OSError, UnicodeError) as error:
            raise ValueError("repository Git alternates are unreadable") from error
        if len(entries) > 64:
            raise ValueError("repository Git alternates exceed the safe limit")
        for entry in entries:
            if not entry.strip():
                continue
            target = Path(entry.strip()).expanduser()
            target = target if target.is_absolute() else object_dir / target
            resolved_target = target.resolve(strict=True)
            if not _inside_any_root(resolved_target, roots):
                raise ValueError("repository Git alternate objects are outside configured target roots")
    return git_dir


def check_repository(settings, path, timeout=30):
    raw = Path(path).expanduser()
    if raw.is_symlink():
        raise ValueError("repository cannot be a symlink")
    resolved = raw.resolve(strict=True)
    from .source_roots import load_managed_roots, managed_root_is_current

    roots = []
    managed = {row["path"]: row for row in load_managed_roots(settings.data_dir)}
    for configured in settings.target_roots:
        candidate = Path(configured)
        try:
            if candidate.resolve(strict=False) != candidate:
                continue
            root_record = managed.get(str(candidate))
            if root_record is not None and not managed_root_is_current(root_record):
                continue
            roots.append(candidate)
        except (OSError, RuntimeError):
            continue
    roots = tuple(roots)
    if not any(
        resolved.is_relative_to(root) and resolved != root
        for root in roots
    ):
        raise ValueError("repository is outside configured target roots")
    _git_metadata_directories(resolved, roots)
    bare = _git(resolved, "rev-parse", "--is-bare-repository", timeout=timeout).strip()
    if bare not in (b"true", b"false"):
        raise ValueError("not a local Git repository")
    if (
        bare == b"false"
        and Path(
            _git(resolved, "rev-parse", "--show-toplevel", timeout=timeout).decode().strip()
        ).resolve()
        != resolved
    ):
        raise ValueError("register the repository root, not a subdirectory")
    # No network operations or working-tree source reads.
    return resolved


def revision(repo, requested, timeout=30):
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}", requested)
        or ".." in requested
    ):
        raise ValueError("invalid revision; select a local branch, tag or commit")
    commit = (
        _git(Path(repo["path"]), "rev-parse", "--verify", requested + "^{commit}", timeout=timeout)
        .decode()
        .strip()
    )
    commit, tree = resolve_commit(Path(repo["path"]), commit)
    return {"requested_revision": requested, "commit": commit, "git_tree": tree}


def revisions(repo, timeout=30):
    text = _git(
        Path(repo["path"]),
        "for-each-ref",
        "--count=2000",
        "--format=%(refname) %(objectname)",
        "refs/heads",
        "refs/tags",
        "refs/remotes",
        timeout=timeout,
    ).decode()
    rows = [
        {"ref": r.split(" ", 1)[0], "object": r.split(" ", 1)[1]}
        for r in text.splitlines()
    ][:2000]
    available = {row["ref"] for row in rows}
    default_ref = None
    # Prefer the repository's advertised default branch. For local mirrors
    # without origin/HEAD, use the branch currently checked out at HEAD.
    for symbolic_ref in ("refs/remotes/origin/HEAD", "HEAD"):
        try:
            candidate = _git(
                Path(repo["path"]), "symbolic-ref", "--quiet", symbolic_ref,
                timeout=timeout,
            ).decode().strip()
        except (OSError, ValueError, subprocess.TimeoutExpired):
            continue
        if candidate in available:
            default_ref = candidate
            break
    return [dict(row, is_default=row["ref"] == default_ref) for row in rows]


def detector_metadata():
    catalog = catalog_metadata()
    pending_ids = {row["id"] for row in pending_admissions()}
    result = []
    for key, spec in catalog.items():
        if spec["kind"] == "example" or key in pending_ids:
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


def audit_plan(repo, requested, includes, detector_ids=None, timeout_seconds=300, memory_mb=2048):
    if not includes or len(includes) > 100 or len(set(includes)) != len(includes):
        raise ValueError("select 1..100 distinct include paths")
    for path in includes:
        if path != ".":
            safe_relative_path(path)
    if detector_ids:
        build_registry(tuple(detector_ids))
    fixed = revision(repo, requested)
    request = {"repo_dir": repo["path"], "repository": repo["name"],
               "commit": fixed["commit"], "includes": includes,
               "selected_detector_ids": detector_ids,
               "execution_budget": {
                   "timeout_seconds": timeout_seconds,
                   "memory_mb": memory_mb,
               }}
    try:
        result = subprocess.run(
            [sys.executable, "-m", "src.workbench.plan_child", str(os.getpid())],
            input=json.dumps(request), capture_output=True, text=True,
            cwd=Path(__file__).resolve().parents[2], timeout=35)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("Planning deadline exceeded; no scan was queued") from exc
    if result.returncode or len(result.stdout.encode()) > 8 * 1024 * 1024:
        raise ValueError("Planning failed within source/resource limits; no scan was queued: "
                         + result.stderr[-800:])
    plan = json.loads(result.stdout)
    if plan["source"]["commit"] != fixed["commit"] or plan["source"]["git_tree"] != fixed["git_tree"]:
        raise ValueError("planning source binding mismatch")
    return fixed, plan


def make_spec(repo, requested, includes, detector_ids, timeout_seconds, memory_mb):
    fixed, plan = audit_plan(repo, requested, includes, detector_ids, timeout_seconds, memory_mb)
    ids = list(plan["suggested_detector_ids"]) if detector_ids is None else list(detector_ids)
    if not ids:
        raise ValueError("No applicable approved detector; analysis remains unknown, no scan queued")
    build_registry(tuple(ids))
    return {
        **fixed,
        "repository": repo["name"], "include_paths": includes,
        "detector_ids": ids,
        "detector_versions": {d["id"]: d["version"] for d in detector_metadata() if d["id"] in ids},
        "audit_plan": plan, "plan_sha256": plan["plan_sha256"],
        "timeout_seconds": timeout_seconds, "memory_mb": memory_mb,
        "mode": "repository_snapshot", "engine_sha256": engine_fingerprint(),
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
                    "risk_assessment": proof.get(diag["diagnostic_id"], {}).get("risk_assessment"),
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
    if inventory[file].get("archive_binding") is not None:
        from src.ohscanner.git_source import load_git_sources
        binding = inventory[file]["archive_binding"]
        _, tree, archive_sources, archive_inventory = load_git_sources(
            root, commit, (binding["archive_path"],)
        )
        if tree != job["spec"]["git_tree"]:
            raise ValueError("source archive tree binding mismatch")
        selected = next((item for item in archive_sources if item.path == file), None)
        if selected is None or selected.archive_binding != binding:
            raise ValueError("source archive member differs from committed scan inventory")
        if sha(selected.data) != inventory[file]["sha256"]:
            raise ValueError("source archive member hash mismatch")
        return {
            "file": file, "commit": commit, "blob": None,
            "sha256": sha(selected.data), "text": selected.data.decode("utf-8"),
            "archive_binding": binding,
        }
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
