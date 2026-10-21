"""Bounded operation planning and read-only evidence tools shared by API/Workers."""
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo
from . import service
from .store import TERMINAL
from .operations_store import Operations
from .source_identity import repository_source_id


def git(repo, *args):
    done = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
                          capture_output=True, timeout=30)
    if done.returncode:
        raise ValueError(done.stderr.decode("utf-8", "replace")[:1000])
    if len(done.stdout) > 8 * 1024 * 1024:
        raise ValueError("Git response exceeds operation budget")
    return done.stdout


def approved_url(value):
    url = urlsplit(value)
    if (any(ord(ch) < 33 or ord(ch) == 127 for ch in value)
            or url.scheme != "https" or url.hostname not in {"github.com", "gitee.com", "gitcode.com"}
            or url.username or url.password or url.port or url.query or url.fragment
            or not re.fullmatch(r"/openharmony/[A-Za-z0-9_-]+(?:\.git)?", url.path)):
        raise ValueError("only explicit HTTPS OpenHarmony repositories on approved hosts are allowed")
    return value


def range_plan(settings, store, repository_id, baseline, endpoint, includes, detectors, timeout, memory):
    repo = store.repository(repository_id)
    path = service.check_repository(settings, repo["path"])
    a = service.make_spec(repo, baseline, includes, detectors, timeout, memory)
    b = service.make_spec(repo, endpoint, includes, detectors, timeout, memory)
    if subprocess.run(["git", "-C", str(path), "merge-base", "--is-ancestor", a["commit"], b["commit"]],
                      timeout=30, capture_output=True).returncode:
        raise ValueError("baseline must be an ancestor of endpoint; use version matrix otherwise")
    commits = git(path, "rev-list", "--first-parent", a["commit"] + ".." + b["commit"]).decode().splitlines()
    if len(commits) > 5000:
        raise ValueError("revision range exceeds 5000 commits")
    return repo, a, b, commits



def multimode_triage_preview(scan_specs, body, provider, nonces):
    """Build a separately consented, immutable source-egress preview per endpoint."""
    from .agent import audit_task_consent_preview
    if body.get("audit_mode") != "standard_review" or not body.get("auto_triage"):
        raise ValueError("automatic model triage requires standard review and an explicit preview")
    if len(scan_specs) != len(nonces) or not scan_specs or len(scan_specs) > 8:
        raise ValueError("invalid endpoint count or consent nonce count")
    max_candidates = body.get("max_triage_candidates", 3)
    max_r2 = body.get("max_r2_candidates", 0)
    previews = []
    for spec, nonce in zip(scan_specs, nonces):
        workflow = service.audit_workflow_sha256(
            spec["plan_sha256"], "standard_review", True, max_candidates, max_r2
        )
        preview = audit_task_consent_preview(
            spec["audit_plan"], workflow, spec["include_paths"], max_candidates,
            nonce, provider, max_r2
        )
        if not preview.get("eligible"):
            raise ValueError("endpoint automatic triage unavailable: " + preview.get("reason", "unknown"))
        previews.append({"commit": spec["commit"], "plan_sha256": spec["plan_sha256"],
                         "workflow_sha256": workflow, **preview})
    return previews


def bind_multimode_triage(settings, scan_specs, body):
    """Fail closed on every endpoint before any scan or operation is queued."""
    approvals = body.get("triage_approvals") or []
    if not body.get("auto_triage", False):
        if approvals:
            raise ValueError("model authorization submitted for a static-only operation")
        return scan_specs
    if body.get("audit_mode") != "standard_review":
        raise ValueError("automatic triage is only supported in standard review mode")
    if len(approvals) != len(scan_specs):
        raise ValueError("each fixed endpoint needs its own reviewed model consent")
    from .agent import ProviderConfig
    provider = ProviderConfig.from_env(settings.data_dir)
    if not provider.configured:
        raise ValueError("model provider not configured; static endpoint scans remain available")
    nonces = [row.get("consent_nonce") if isinstance(row, dict) else None for row in approvals]
    previews = multimode_triage_preview(scan_specs, body, provider, nonces)
    enriched = []
    for spec, approval, preview in zip(scan_specs, approvals, previews):
        if approval.get("consent_sha256") != preview["consent_sha256"]:
            raise ValueError("endpoint consent expired: source, model, policy or budget changed")
        enriched.append({
            **spec, "audit_mode": "standard_review",
            "workflow_sha256": preview["workflow_sha256"],
            "max_r2_candidates": body.get("max_r2_candidates", 0),
            "max_cost_usd": None,
            "triage_authorization": {
                "authorized": True, "consent_sha256": preview["consent_sha256"],
                "snapshot": preview["manifest"],
            },
        })
    return enriched


def enqueue_range(settings, store, ops, body):
    repo, a, b, commits = range_plan(settings, store, body["repository_id"], body["baseline"],
                                    body["endpoint"], body["include_paths"], body["detector_ids"],
                                    body["timeout_seconds"], body["memory_mb"])
    audit_mode = body.get("audit_mode", "standard_review")
    scans = bind_multimode_triage(settings, [{**a, "audit_mode": audit_mode}, {**b, "audit_mode": audit_mode}], body)
    return ops.create_with_scans("revision_range", {"repository_id": repo["id"], "baseline": a["commit"],
        "endpoint": b["commit"], "commits": commits, "audit_mode": audit_mode,
        "timeout_seconds": body["timeout_seconds"] * 2 + 60,
        "memory_mb": body["memory_mb"], "date_selection": body.get("date_selection")},
        repo["id"], scans)


def enqueue_branch_comparison(settings, store, ops, body):
    repo = store.repository(body["repository_id"])
    service.check_repository(settings, repo["path"])
    before = service.revision(repo, body["baseline_ref"])
    after = service.revision(repo, body["endpoint_ref"])
    if before["commit"] == after["commit"]:
        raise ValueError("branch comparison refs must resolve to different commits")
    specs = [service.make_spec(repo, item["commit"], body["include_paths"], body["detector_ids"],
                               body["timeout_seconds"], body["memory_mb"])
             for item in (before, after)]
    audit_mode = body.get("audit_mode", "standard_review")
    specs = bind_multimode_triage(settings, [{**spec, "audit_mode": audit_mode} for spec in specs], body)
    return ops.create_with_scans("branch_comparison", {
        "repository_id": repo["id"], "audit_mode": audit_mode,
        "baseline_ref": body["baseline_ref"], "baseline": before["commit"],
        "endpoint_ref": body["endpoint_ref"], "endpoint": after["commit"],
        "timeout_seconds": body["timeout_seconds"] * 2 + 60,
        "memory_mb": body["memory_mb"],
    }, repo["id"], specs)


def source_sync_preflight(settings, entries):
    """Describe a bounded source-sync plan without network access or filesystem writes."""
    cache_root = settings.data_dir / "repo-cache"
    base = cache_root.resolve(strict=False)
    volume_path = cache_root if cache_root.exists() else settings.data_dir
    free_bytes = shutil.disk_usage(volume_path).free
    results = []
    for entry in entries:
        name = entry["name"]
        url = approved_url(entry["url"])
        expected = "/" + name + (".git" if urlsplit(url).path.endswith(".git") else "")
        if urlsplit(url).path != expected:
            raise ValueError("repository URL path must match the approved repository name")
        source_id = repository_source_id(url)
        target = base / name.split("/", 1)[1]
        row = {
            "repository": name, "source_id": source_id,
            "action": "fetch" if target.exists() else "clone",
            "cache_state": "present" if target.exists() else "absent",
            "current_head": None, "remote_ref_count": None,
            "scan_after_sync": entry.get("scan_after_sync") is True,
            "requested_revision": entry.get("revision", "HEAD"),
            "eligible": True, "reason": "",
        }
        if target.is_symlink() or target.resolve(strict=False).parent != base:
            row.update(eligible=False, cache_state="unsafe_path", reason="缓存目录安全校验失败")
        elif target.exists():
            try:
                checked = service.check_repository(settings, str(target))
                urls = git(checked, "config", "--get-all", "remote.origin.url").decode().splitlines()
                cached_sources = {repository_source_id(value) for value in urls if value.strip()}
                if not cached_sources or cached_sources != {source_id}:
                    row.update(eligible=False, cache_state="source_conflict",
                               reason="缓存目录已绑定到不同或未知的源码地址，拒绝混合同名仓库")
                else:
                    refs = service.revisions({"path": str(checked)})
                    row["remote_ref_count"] = len(refs)
                    try:
                        row["current_head"] = service.revision({"path": str(checked)}, "HEAD")["commit"]
                    except (OSError, ValueError, subprocess.TimeoutExpired):
                        row["current_head"] = None
            except (OSError, ValueError, subprocess.TimeoutExpired):
                row.update(eligible=False, cache_state="unusable", reason="现有缓存不是可用的 Git 仓库")
        if free_bytes <= SOURCE_SYNC_MIN_FREE_BYTES:
            row.update(eligible=False, reason="可用磁盘空间不足，系统需要保留至少 512 MiB")
        results.append(row)
    return {
        "eligible": all(row["eligible"] for row in results),
        "repositories": results,
        "repository_count": len(results),
        "available_disk_bytes": free_bytes,
        "minimum_free_disk_bytes": SOURCE_SYNC_MIN_FREE_BYTES,
        "repository_size_estimate_bytes": None,
        "limitations": [
            "预览不会访问 Git 服务器或创建任务；仓库下载大小未知，下载期间仍会检查磁盘余量。",
            "目录中的组织名称和 source ID 用于定位来源，不证明官方身份或镜像关系。",
        ],
    }


def date_selection(settings, store, repository_id, branch, start, end, timezone):
    zone = ZoneInfo(timezone)
    def epoch(value):
        dt = datetime.fromisoformat(value)
        return (dt.replace(tzinfo=zone) if dt.tzinfo is None else dt).timestamp()
    first, last = epoch(start), epoch(end)
    if first >= last:
        raise ValueError("date interval must be increasing and half-open [start,end)")
    repo = store.repository(repository_id)
    path = service.check_repository(settings, repo["path"])
    tip = service.revision(repo, branch)["commit"]
    history = git(path, "log", "--first-parent", "--format=%H %ct", "-5001", tip).decode().splitlines()
    if len(history) > 5000:
        raise ValueError("date selection exceeds 5000 first-parent commits; use explicit SHAs")
    rows = [(line.split()[0], int(line.split()[1])) for line in history]
    indices = [i for i, (_, stamp) in enumerate(rows) if first <= stamp < last]
    if not indices:
        raise ValueError("no commits selected in the requested date interval")
    low, high = min(indices), max(indices)
    oldest = rows[high][0]
    parents = git(path, "rev-list", "--parents", "-n", "1", oldest).decode().split()
    if len(parents) < 2:
        raise ValueError("earliest selected commit has no baseline parent; choose explicit SHAs")
    selected = [rows[i][0] for i in indices]
    return {"branch": branch, "tip": tip, "baseline": parents[1], "endpoint": rows[low][0],
            "selected_commits": selected,
            "intervening_outside_date": [sha for sha, _ in rows[low:high + 1] if sha not in selected],
            "time_basis": "committer", "timezone": timezone, "start": start, "end": end,
            "topology": "first-parent", "boundary": "[start,end)"}


def recent_window_selections(settings, store, repository_id, branch, lookback_days,
                             reference_time, timezone):
    """Freeze disjoint N-day and latest-one-day windows using the existing date policy."""
    if not isinstance(lookback_days, int) or isinstance(lookback_days, bool) or not 2 <= lookback_days <= 90:
        raise ValueError("lookback_days must be between 2 and 90")
    zone = ZoneInfo(timezone)
    reference = datetime.fromisoformat(reference_time)
    reference = reference.replace(tzinfo=zone) if reference.tzinfo is None else reference.astimezone(zone)
    one_day_ago = reference - timedelta(days=1)
    long_start = reference - timedelta(days=lookback_days)
    older = date_selection(settings, store, repository_id, branch,
                           long_start.isoformat(timespec="seconds"),
                           one_day_ago.isoformat(timespec="seconds"), timezone)
    latest = date_selection(settings, store, repository_id, branch,
                            one_day_ago.isoformat(timespec="seconds"),
                            reference.isoformat(timespec="seconds"), timezone)
    return {"lookback_days": lookback_days, "reference_time": reference.isoformat(timespec="seconds"),
            "timezone": timezone, "long_window": older, "one_day_window": latest,
            "windows_are_disjoint": True,
            "interpretation": "two independent first-parent commit-time windows; not per-commit coverage or vulnerability-introduction proof"}


def enqueue_synced_scan(settings, store, ops, task, repo):
    """Queue an immutable scan only after an explicit sync-and-scan request."""
    spec = task["spec"]
    if not spec.get("scan_after_sync"):
        return None
    requested_revision = spec.get("revision", "HEAD")
    scan_revision = requested_revision
    if requested_revision == "HEAD":
        # Fetch updates remote-tracking refs but deliberately does not checkout
        # or move the local branch. For the default UI value, pin the freshly
        # fetched remote default branch instead of rescanning a stale local HEAD.
        default_remote = next((row["ref"] for row in service.revisions(repo)
                              if row.get("is_default")
                              and row.get("ref", "").startswith("refs/remotes/origin/")), None)
        if default_remote:
            scan_revision = default_remote
    scan_spec = service.make_spec(repo, scan_revision,
        spec.get("include_paths", ["."]), spec.get("detector_ids"),
        spec.get("scan_timeout_seconds", 600), spec.get("memory_mb", 2048))
    audit_mode = spec.get("audit_mode", "static_only")
    scan_spec["audit_mode"] = audit_mode
    scan_spec["max_r2_candidates"] = 0
    scan_spec["max_cost_usd"] = None
    scan_spec["workflow_sha256"] = service.audit_workflow_sha256(
        scan_spec["plan_sha256"], audit_mode)
    scan_spec["workflow"] = service.audit_workflow_summary(audit_mode)
    job = store.create_job(repo["id"], scan_spec)
    ops.event(task["id"], "scan_enqueued",
              "Automatic static scan queued for immutable commit " + scan_spec["commit"])
    return job


def changes(repo, baseline, endpoint):
    tokens = git(repo, "diff", "--name-status", "-M", "-z", baseline, endpoint, "--").decode().split("\0")
    rows = []
    i = 0
    while i < len(tokens) and tokens[i]:
        status = tokens[i]
        count = 2 if status.startswith(("R", "C")) else 1
        paths = tokens[i + 1:i + 1 + count]
        if len(paths) != count:
            raise ValueError("invalid Git change list")
        rows.append({"status": status, "old_path": paths[0], "new_path": paths[-1]})
        i += 1 + count
    return rows


def compare_reports(a, b, changed):
    rename = {r["old_path"]: r["new_path"] for r in changed if r["status"].startswith("R")}
    groups = []
    left, right = defaultdict(list), defaultdict(list)
    def identity(item, old=False):
        file = rename.get(item["file"], item["file"]) if old else item["file"]
        return item["detector_id"], item["rule_id"], file, item.get("symbol") or ""
    for item in service.findings(a):
        left[identity(item, True)].append(item)
    for item in service.findings(b):
        right[identity(item)].append(item)
    reverse_rename = {new: old for old, new in rename.items()}
    def complete(report, detector, file, old_side=False):
        coverage = report["detector_coverage"]["detectors"].get(detector, {})
        inventory = report.get("_workbench", {}).get("source_inventory", [])
        requested = reverse_rename.get(file, file) if old_side else file
        absent = requested not in {r["file"] for r in inventory}
        return requested in coverage.get("analyzed_files", []) or (absent and bool(inventory))
    for key in sorted(set(left) | set(right)):
        before, after = left[key], right[key]
        versions_before = {x.get("detector_version") for x in before}
        versions_after = {x.get("detector_version") for x in after}
        if len(before) == len(after) == 1 and versions_before == versions_after:
            status = "persistent_candidate"
        elif before and after:
            status = "unknown"
        elif after:
            status = "new_candidate" if complete(a, key[0], key[2], old_side=True) else "unknown"
        else:
            status = "disappeared_candidate" if complete(b, key[0], key[2]) else "unknown"
        if before and after and versions_before != versions_after:
            status = "unknown_detector_version_changed"
        groups.append({"status": status, "match_basis": "detector_rule_path_symbol",
                       "before": [{"id": x["id"], "detector_version": x.get("detector_version"), "source_sha256": x.get("source_sha256")} for x in before],
                       "after": [{"id": x["id"], "detector_version": x.get("detector_version"), "source_sha256": x.get("source_sha256")} for x in after],
                       "file": key[2], "rule_id": key[1], "detector_id": key[0],
                       "vulnerability_introduced_or_fixed": "unknown"})
    return groups


def wait_reports(settings, store, ids):
    while True:
        jobs = [store.job(key) for key in ids]
        if all(j["status"] in TERMINAL for j in jobs):
            break
        time.sleep(.2)
    return [service.read_report(settings, j) if j["report_sha256"] else None for j in jobs]


def investigation(settings, store, spec):
    job = store.job(spec["job_id"])
    report = service.read_report(settings, job)
    candidate = service.finding(report, spec["candidate_id"])
    source = service.source(settings, store, job, candidate["file"])
    line = candidate["line"]
    lines = source["text"].splitlines()
    start, end = max(1, line - 12), min(len(lines), line + 12)
    excerpt = "\n".join(lines[start - 1:end])
    repo = store.repository(job["repository_id"])
    history = git(repo["path"], "log", "-5", "--format=%H %s", report["commit"], "--", candidate["file"]).decode()
    tools = [
        {"tool": "fixed_source_excerpt", "arguments": {"file": candidate["file"], "start": start, "end": end},
         "result": {"text": excerpt, "source_sha256": source["sha256"], "blob": source["blob"]}},
        {"tool": "evidence_obligations", "arguments": {"candidate_id": candidate["id"]},
         "result": candidate["evidence"]},
        {"tool": "fixed_git_history", "arguments": {"commit": report["commit"], "file": candidate["file"]},
         "result": history},
        {"tool": "symbol_facts", "arguments": {"file": candidate["file"]},
         "result": {"symbol": candidate.get("symbol"), "parse_status": candidate["evidence"].get("analysis_status", "unknown")}},
    ]
    budget = spec.get("max_output_bytes", 65536)
    if len(json.dumps(tools, ensure_ascii=False).encode()) > budget:
        raise ValueError("read-only investigation output exceeds explicit budget")
    return {"status": "completed", "kind": "read_only_investigation", "model_called": False,
            "trace": [{**t, "evidence_sha256": service.sha(json.dumps(t["result"], sort_keys=True).encode())} for t in tools],
            "binding": {"repository": report["repository"], "commit": report["commit"],
                        "report_sha256": job["report_sha256"], "candidate_id": candidate["id"]},
            "remaining_obligations": candidate["evidence"].get("obligations", []),
            "conclusion": "No model or vulnerability promotion; human review still required",
            "validated_vulnerability": 0}


MAX_SOURCE_SYNC_BATCH_REPOSITORIES = 8
SOURCE_SYNC_MIN_FREE_BYTES = 512 * 1024 * 1024


class SourceSyncSafetyLimit(RuntimeError):
    """A batch stopped before the configured cache volume reserve was consumed."""


def _source_sync_batch_cancelled(ops, operation_id):
    return ops.source_sync_cancel_requested(operation_id)


def _ensure_source_sync_free_space(base):
    if shutil.disk_usage(base).free <= SOURCE_SYNC_MIN_FREE_BYTES:
        raise SourceSyncSafetyLimit(
            "Stopped to preserve at least 512 MiB of free space on the repository cache volume"
        )


def _start_source_sync_process(command, env):
    return subprocess.Popen(command, env=env, start_new_session=True)


def _terminate_source_sync_process(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=2)


def _acquire_source_sync_lock(lock, timeout_seconds, base, ops, operation_id):
    """Wait for the per-repository lock without making batch cancel wait indefinitely."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _source_sync_batch_cancelled(ops, operation_id):
            return False
        _ensure_source_sync_free_space(base)
        try:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return deadline - time.monotonic()
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("repository sync lock", timeout_seconds)
            time.sleep(0.1)


def _run_source_sync_process(command, env, timeout_seconds, base, ops, operation_id):
    """Run one Git transfer with timeout, cancellation and free-space checks."""
    _ensure_source_sync_free_space(base)
    process = _start_source_sync_process(command, env)
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            if _source_sync_batch_cancelled(ops, operation_id):
                _terminate_source_sync_process(process)
                return "cancelled"
            _ensure_source_sync_free_space(base)
            return_code = process.poll()
            if return_code is not None:
                if return_code:
                    raise subprocess.CalledProcessError(return_code, command)
                _ensure_source_sync_free_space(base)
                return "completed"
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            time.sleep(0.1)
    except BaseException:
        # Stop Git before the caller removes a partial clone or records failure.
        _terminate_source_sync_process(process)
        raise


def _remove_new_sync_target(target, base):
    """Remove only a partial clone path created by this operation."""
    if target.is_symlink():
        return
    try:
        if target.resolve(strict=False).parent == base and target.is_dir():
            shutil.rmtree(target)
    except (OSError, RuntimeError):
        return


def _source_sync_item_event(ops, operation_id, stage, payload):
    ops.event(operation_id, stage, json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _safe_sync_error(error, action):
    if isinstance(error, SourceSyncSafetyLimit):
        return str(error)
    if isinstance(error, subprocess.TimeoutExpired):
        return "Git " + action + " exceeded this repository's timeout"
    if isinstance(error, subprocess.CalledProcessError):
        return "Git " + action + " failed with exit status " + str(error.returncode)
    return type(error).__name__ + ": " + str(error)[:500]


def _sync_source_batch_item(settings, store, ops, task, entry, index, total):
    """Apply the single-source security checks to one batch row."""
    name = entry.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"openharmony/[A-Za-z0-9_-]{1,100}", name):
        raise ValueError("repository name is outside the OpenHarmony allowlist")
    url = approved_url(entry.get("url", ""))
    expected = "/" + name + (".git" if urlsplit(url).path.endswith(".git") else "")
    if urlsplit(url).path != expected:
        raise ValueError("repository URL path must match the approved repository name")

    base = (settings.data_dir / "repo-cache").resolve()
    base.mkdir(parents=True, exist_ok=True)
    target = base / name.split("/", 1)[1]
    if target.is_symlink() or target.resolve(strict=False).parent != base:
        raise ValueError("unsafe repository cache path")
    was_present = False
    action = "not_started"
    lockdir = settings.data_dir / "sync-locks"
    lockdir.mkdir(exist_ok=True)
    import fcntl
    clone_attempted = False
    sync_finished = False
    try:
        with (lockdir / (target.name + ".lock")).open("a") as lock:
            remaining = _acquire_source_sync_lock(
                lock, entry["timeout_seconds"], base, ops, task["id"]
            )
            if remaining is False:
                return {"repository": name, "status": "cancelled", "sync_action": action,
                        "scan_status": "not_started"}
            if target.is_symlink() or target.resolve(strict=False).parent != base:
                raise ValueError("unsafe repository cache path")
            was_present = target.exists()
            action = "fetch" if was_present else "clone"
            _source_sync_item_event(ops, task["id"], "source_sync_batch_item_started", {
                "index": index, "total": total, "repository": name, "status": "running",
                "action": action,
            })
            if task.get("kind") == "source_sync":
                ops.event(task["id"], "git_sync", "正在同步经批准的 Git HTTPS 源码")
            command = ["git", "-c", "core.hooksPath=/dev/null",
                       "-c", "http.followRedirects=false",
                       "-c", "fetch.recurseSubmodules=false",
                       "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
                       "-c", "credential.helper="]
            if was_present:
                service.check_repository(settings, str(target))
                try:
                    cached_urls = git(target, "config", "--get-all", "remote.origin.url").decode().splitlines()
                except ValueError as exc:
                    raise ValueError("cached repository has no pinned source identity") from exc
                cached_sources = {repository_source_id(value) for value in cached_urls if value.strip()}
                if cached_sources != {repository_source_id(url)}:
                    raise ValueError("cached repository source identity mismatch; refusing to mix same-named sources")
                command += ["-C", str(target), "fetch", "--no-recurse-submodules",
                            "--prune", "--tags", url, "+refs/heads/*:refs/remotes/origin/*"]
            else:
                command += ["clone", "--no-checkout", "--no-recurse-submodules",
                            "--", url, str(target)]
            env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                   "GIT_ALLOW_PROTOCOL": "https"}
            clone_attempted = not was_present
            outcome = _run_source_sync_process(
                command, env, remaining, base, ops, task["id"]
            )
            if outcome == "cancelled":
                if clone_attempted:
                    _remove_new_sync_target(target, base)
                return {"repository": name, "status": "cancelled", "sync_action": action,
                        "scan_status": "not_started"}
            if clone_attempted:
                # Persist the approved HTTPS identity even when a local transport test seam rewrites clone's URL.
                git(target, "remote", "set-url", "origin", url)
            sync_finished = True
    except Exception:
        if clone_attempted and not sync_finished:
            _remove_new_sync_target(target, base)
        raise

    # Reacquire the same lock while registering. Concurrent syncs may have
    # completed their transfer before either one reaches this point.
    with (lockdir / (target.name + ".lock")).open("a") as registration_lock:
        fcntl.flock(registration_lock, fcntl.LOCK_EX)
        checked_path = service.check_repository(settings, str(target))
        existing = next((repo for repo in store.repositories()
                         if repo["path"] == str(checked_path)), None)
        repo = existing or store.add_repository(name, str(checked_path))
    head = service.revision(repo, "HEAD")
    tree = git(checked_path, "rev-parse", head["commit"] + "^{tree}").decode().strip()
    remote_refs = [ref for ref in service.revisions(repo)
                   if ref["ref"].startswith("refs/remotes/origin/")]
    scan_job = None
    scan_error = None
    try:
        # Reuse the existing fixed-commit scan handoff with this repository's
        # own scan settings, rather than the outer batch spec.
        scan_task = {**task, "spec": entry}
        scan_job = enqueue_synced_scan(settings, store, ops, scan_task, repo)
    except Exception as exc:
        scan_error = type(exc).__name__ + ": " + str(exc)[:500]
    return {
        "repository": name,
        "source_id": repository_source_id(url),
        "repository_id": repo["id"],
        "status": "completed_with_limitations" if scan_error else "completed",
        "sync_action": action,
        "local_head_after_sync": head["commit"],
        "git_tree_after_sync": tree,
        "remote_ref_count": len(remote_refs),
        "scan_job_id": scan_job["id"] if scan_job else None,
        "scan_commit": scan_job["spec"]["commit"] if scan_job else None,
        "scan_tree": scan_job["spec"].get("git_tree") if scan_job else None,
        "scan_status": scan_job["status"] if scan_job else ("failed" if scan_error else "not_requested"),
        "error": scan_error,
        "limitations": (["Repository objects were synchronized without checkout or build."]
            + (["The queued scan is static only and does not create model-egress authorization."]
               if scan_job else [])),
    }


def execute_source_sync_batch(settings, store, ops, task):
    entries = task["spec"].get("repositories")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_SOURCE_SYNC_BATCH_REPOSITORIES:
        raise ValueError("source sync batch must contain one to eight repository entries")
    first_by_name = {}
    unique_count = 0
    unique_timeout_total = 0
    for index, entry in enumerate(entries, start=1):
        name = entry.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"openharmony/[A-Za-z0-9_-]{1,100}", name):
            raise ValueError("repository name is outside the OpenHarmony allowlist")
        url = approved_url(entry.get("url", ""))
        expected = "/" + name + (".git" if urlsplit(url).path.endswith(".git") else "")
        if urlsplit(url).path != expected:
            raise ValueError("repository URL path must match the approved repository name")
        timeout_seconds = entry.get("timeout_seconds")
        if (not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool)
                or not 10 <= timeout_seconds <= 3600):
            raise ValueError("each repository timeout must be between 10 and 3600 seconds")
        prior = first_by_name.get(name.casefold())
        if prior is None:
            first_by_name[name.casefold()] = (index, entry)
            unique_count += 1
            unique_timeout_total += timeout_seconds
        elif prior[1] != entry:
            raise ValueError("duplicate repository entries must use the same URL and scan options")
    if unique_timeout_total > 7200:
        raise ValueError("batch total Git timeout cannot exceed two hours")

    results = []
    safety_stop = False
    cancelled = False
    for index, entry in enumerate(entries, start=1):
        name = entry["name"]
        prior = first_by_name[name.casefold()][0]
        if prior != index:
            row = {"repository": name, "status": "skipped_duplicate", "duplicate_of": prior,
                   "scan_status": "not_started"}
            results.append(row)
            _source_sync_item_event(ops, task["id"], "source_sync_batch_item_skipped", {
                "index": index, "total": len(entries), "repository": name,
                "status": row["status"], "duplicate_of": prior,
            })
            continue
        if cancelled or safety_stop or _source_sync_batch_cancelled(ops, task["id"]):
            cancelled = cancelled or _source_sync_batch_cancelled(ops, task["id"])
            status = "not_started"
            row = {"repository": name, "status": status, "scan_status": "not_started"}
            results.append(row)
            _source_sync_item_event(ops, task["id"], "source_sync_batch_item_skipped", {
                "index": index, "total": len(entries), "repository": name,
                "status": status, "reason": "cancelled" if cancelled else "disk_safety_stop",
            })
            continue
        try:
            row = _sync_source_batch_item(settings, store, ops, task, entry, index, len(entries))
        except SourceSyncSafetyLimit as exc:
            safety_stop = True
            row = {"repository": name, "status": "failed", "scan_status": "not_started",
                   "error": _safe_sync_error(exc, "transfer")}
        except Exception as exc:
            row = {"repository": name, "status": "failed", "scan_status": "not_started",
                   "error": _safe_sync_error(exc, "transfer")}
        results.append(row)
        stage = ("source_sync_batch_item_cancelled" if row["status"] == "cancelled"
                 else "source_sync_batch_item_failed" if row["status"] == "failed"
                 else "source_sync_batch_item_completed")
        _source_sync_item_event(ops, task["id"], stage, {
            "index": index, "total": len(entries), **row,
        })
        if row["status"] == "cancelled":
            cancelled = True

    if _source_sync_batch_cancelled(ops, task["id"]):
        cancelled = True
    if cancelled:
        # Scans already queued by this batch are owned by the batch. Request
        # cancellation for any that have not finished; terminal scans stay intact.
        for row in results:
            scan_job_id = row.get("scan_job_id")
            if not scan_job_id:
                continue
            try:
                scan_job = store.cancel(scan_job_id)
                row["scan_status"] = scan_job["status"]
            except Exception as exc:
                row["scan_cancellation_error"] = type(exc).__name__
    succeeded = sum(row["status"] in {"completed", "completed_with_limitations"} for row in results)
    failed = sum(row["status"] == "failed" for row in results)
    duplicates = sum(row["status"] == "skipped_duplicate" for row in results)
    not_started = sum(row["status"] == "not_started" for row in results)
    scans_enqueued = sum(bool(row.get("scan_job_id")) for row in results)
    scans_cancelled = sum(row.get("scan_status") == "cancelled" for row in results)
    if cancelled:
        status = "cancelled"
    elif succeeded == 0 and failed:
        status = "failed"
    elif failed or any(row.get("scan_status") == "failed" for row in results):
        status = "completed_with_limitations"
    else:
        status = "completed"
    return {
        "status": status,
        "repositories": results,
        "summary": {
            "requested": len(entries), "unique": unique_count, "succeeded": succeeded,
            "failed": failed, "duplicates_skipped": duplicates,
            "not_started": not_started, "static_scans_enqueued": scans_enqueued,
            "static_scans_cancelled": scans_cancelled,
            "disk_safety_stop": safety_stop, "cancellation_requested": cancelled,
        },
        "limits": {"max_repositories": MAX_SOURCE_SYNC_BATCH_REPOSITORIES,
                   "maximum_total_git_timeout_seconds": 7200,
                   "minimum_free_disk_bytes": SOURCE_SYNC_MIN_FREE_BYTES},
        "limitations": ["Repositories are synchronized serially; no checkout, submodule, hook or build is run.",
                        "Each auto-queued scan pins its own immutable commit/tree and is static only; no model consent is added."],
    }


def execute(settings, store, ops, task):
    spec, kind = task["spec"], task["kind"]
    if kind == "source_sync_batch":
        return execute_source_sync_batch(settings, store, ops, task)
    if kind == "source_sync":
        url = approved_url(spec["url"])
        entry = {**spec, "url": url}
        try:
            row = _sync_source_batch_item(settings, store, ops, task, entry, 1, 1)
        except Exception as exc:
            return {
                "status": "failed", "repository": None, "url": url,
                "error": _safe_sync_error(exc, "transfer"),
                "limitations": ["源码同步失败；请检查公开仓库 URL、网络连接和可用磁盘空间。"],
            }
        repository = None
        remote_refs = []
        if row.get("repository_id"):
            try:
                repository = store.repository(row["repository_id"])
                remote_refs = [ref for ref in service.revisions(repository)
                               if ref["ref"].startswith("refs/remotes/origin/")]
            except (KeyError, OSError, ValueError):
                repository = None
        scan_job_id = row.get("scan_job_id")
        if _source_sync_batch_cancelled(ops, task["id"]):
            if scan_job_id:
                try:
                    scan = store.cancel(scan_job_id)
                    row["scan_status"] = scan["status"]
                except Exception as exc:
                    row["scan_cancellation_error"] = type(exc).__name__
            row["status"] = "cancelled"
            row["cancellation_requested"] = True
        return {
            "status": row.get("status", "failed"),
            "repository": repository,
            "url": url,
            "source_id": row.get("source_id", repository_source_id(url)),
            "sync_action": row.get("sync_action"),
            "local_head_after_sync": row.get("local_head_after_sync"),
            "git_tree_after_sync": row.get("git_tree_after_sync"),
            "advertised_remote_refs": remote_refs,
            "scan_job_id": scan_job_id,
            "scan_commit": row.get("scan_commit"),
            "scan_tree": row.get("scan_tree"),
            "scan_status": row.get("scan_status", "not_started"),
            "error": row.get("error"),
            "limitations": row.get("limitations", []),
        }
    if kind == "investigation":
        return investigation(settings, store, spec)
    if kind == "agent_investigation":
        from .agent import execute_agent
        return execute_agent(settings, store, ops, task)
    if kind == "version_candidate_comparison":
        from .joint_candidate_comparison_runtime import execute_joint_comparison
        return execute_joint_comparison(settings, store, ops, task)
    if kind == "validation":
        from .validation import execute_validation
        return execute_validation(settings, store, ops, task)
    reports = wait_reports(settings, store, spec["scan_ids"])
    if any(r is None for r in reports):
        if kind == "recent_window_comparison":
            return {"status": "blocked", "scan_ids": spec["scan_ids"],
                    "windows": [{"status": "unknown", "candidate_comparison": [
                        {"status": "unknown", "vulnerability_introduced_or_fixed": "unknown"}]}],
                    "impact": "unknown", "validated_vulnerability": 0,
                    "reason": "A fixed endpoint scan failed or was cancelled; both time windows remain unknown."}
        if kind == "branch_comparison":
            return {"status": "blocked", "baseline_ref": spec["baseline_ref"],
                    "baseline": spec["baseline"], "endpoint_ref": spec["endpoint_ref"],
                    "endpoint": spec["endpoint"], "scan_ids": spec["scan_ids"],
                    "candidate_comparison": [{"status": "unknown", "vulnerability_introduced_or_fixed": "unknown"}],
                    "impact": "unknown", "validated_vulnerability": 0,
                    "reason": "An endpoint scan failed or was cancelled; branch comparison remains unknown."}
        return {"status": "blocked", "scan_ids": spec["scan_ids"], "reason": "Endpoint scan failed/cancelled; comparison unknown"}
    if kind == "recent_window_comparison":
        repo = store.repository(spec["repository_id"])
        window_rows = []
        for index, window in enumerate(spec["windows"]):
            before, after = reports[index * 2:index * 2 + 2]
            delta = changes(repo["path"], before["commit"], after["commit"])
            window_rows.append({"label": str(window["start"]) + " to " + str(window["end"]),
                "selection": window, "baseline": before["commit"], "endpoint": after["commit"],
                "selected_commit_count": len(window.get("selected_commits", [])),
                "changes": delta, "candidate_comparison": compare_reports(before, after, delta),
                "validated_vulnerability": 0})
        older_endpoint = reports[1]
        latest_endpoint = reports[3]
        between_delta = changes(repo["path"], older_endpoint["commit"], latest_endpoint["commit"])
        return {"status": "completed_with_limitations", "repository_id": repo["id"],
            "branch": spec["branch"], "lookback_days": spec["lookback_days"],
            "reference_time": spec["reference_time"], "timezone": spec["timezone"],
            "windows": window_rows, "between_window_endpoints": {
                "from": older_endpoint["commit"], "to": latest_endpoint["commit"],
                "changes": between_delta,
                "candidate_comparison": compare_reports(older_endpoint, latest_endpoint, between_delta),
                "impact": "unknown"},
            "scan_ids": spec["scan_ids"], "impact": "unknown",
            "validated_vulnerability": 0,
            "limitations": spec.get("limitations", [])}
    if kind == "revision_range":
        repo = store.repository(spec["repository_id"])
        change = changes(repo["path"], spec["baseline"], spec["endpoint"])
        pairs = compare_reports(reports[0], reports[1], change)
        return {"status": "completed_with_limitations", "baseline": spec["baseline"],
                "endpoint": spec["endpoint"], "scan_ids": spec["scan_ids"], "commits": spec["commits"],
                "date_selection": spec.get("date_selection"), "changes": change, "candidate_comparison": pairs,
                "validated_vulnerability": 0,
                "limitations": ["Candidate changes do not prove vulnerability introduction or remediation."]}
    if kind == "version_matrix":
        repo = store.repository(spec["repository_id"])
        comparisons = []
        for i in range(len(reports)):
            for j in range(i + 1, len(reports)):
                try:
                    delta = changes(repo["path"], reports[i]["commit"], reports[j]["commit"])
                    compared = compare_reports(reports[i], reports[j], delta)
                except (ValueError, subprocess.SubprocessError):
                    delta, compared = [], [{"status": "unknown", "reason": "comparison unavailable",
                                            "vulnerability_introduced_or_fixed": "unknown"}]
                comparisons.append({"from": reports[i]["commit"], "to": reports[j]["commit"],
                                    "changes": delta, "candidate_comparison": compared,
                                    "impact": "unknown"})
        return {"status": "completed_with_limitations", "case_id": spec["case_id"], "scan_ids": spec["scan_ids"],
                "versions": [{"commit": r["commit"], "candidate_count": r["diagnostic_count"],
                              "impact": "unknown", "reason": "Static observations are not product impact proof",
                              "source_snapshot_sha256": r["snapshot_sha256"]} for r in reports],
                "comparisons": comparisons, "validated_vulnerability": 0,
                "limitations": ["Version association is a candidate-level observation; affected/fixed requires bound evidence and review."]}
    if kind == "branch_comparison":
        repo = store.repository(spec["repository_id"])
        try:
            delta = changes(repo["path"], spec["baseline"], spec["endpoint"])
            compared = compare_reports(reports[0], reports[1], delta)
        except (ValueError, subprocess.SubprocessError):
            delta, compared = [], [{"status": "unknown", "reason": "comparison unavailable",
                                    "vulnerability_introduced_or_fixed": "unknown"}]
        return {"status": "completed_with_limitations", "repository_id": repo["id"],
                "baseline_ref": spec["baseline_ref"], "baseline": spec["baseline"],
                "endpoint_ref": spec["endpoint_ref"], "endpoint": spec["endpoint"],
                "scan_ids": spec["scan_ids"], "changes": delta,
                "candidate_comparison": compared, "impact": "unknown",
                "versions": [{"ref": ref, "commit": report["commit"],
                              "candidate_count": report["diagnostic_count"],
                              "impact": "unknown", "source_snapshot_sha256": report["snapshot_sha256"]}
                             for ref, report in ((spec["baseline_ref"], reports[0]),
                                                 (spec["endpoint_ref"], reports[1]))],
                "validated_vulnerability": 0,
                "limitations": ["Branch endpoint comparison is candidate-level observation; it does not prove vulnerability introduction, remediation, affected versions, or product impact."]}
    raise ValueError("unimplemented operation")
