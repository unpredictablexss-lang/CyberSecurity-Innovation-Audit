"""Bounded operation planning and read-only evidence tools shared by API/Workers."""
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo
from . import service
from .store import TERMINAL
from .operations_store import Operations


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


def enqueue_range(settings, store, ops, body):
    repo, a, b, commits = range_plan(settings, store, body["repository_id"], body["baseline"],
                                    body["endpoint"], body["include_paths"], body["detector_ids"],
                                    body["timeout_seconds"], body["memory_mb"])
    return ops.create_with_scans("revision_range", {"repository_id": repo["id"], "baseline": a["commit"],
        "endpoint": b["commit"], "commits": commits,
        "timeout_seconds": body["timeout_seconds"] * 2 + 60,
        "memory_mb": body["memory_mb"], "date_selection": body.get("date_selection")},
        repo["id"], (a, b))


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
    return {"tip": tip, "baseline": parents[1], "endpoint": rows[low][0],
            "selected_commits": selected,
            "intervening_outside_date": [sha for sha, _ in rows[low:high + 1] if sha not in selected],
            "time_basis": "committer", "timezone": timezone, "start": start, "end": end,
            "topology": "first-parent", "boundary": "[start,end)"}


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


def execute(settings, store, ops, task):
    spec, kind = task["spec"], task["kind"]
    if kind == "source_sync":
        url = approved_url(spec["url"])
        base = (settings.data_dir / "repo-cache").resolve()
        base.mkdir(parents=True, exist_ok=True)
        target = base / spec["name"].split("/")[1]
        if target.is_symlink() or target.resolve().parent != base:
            raise ValueError("unsafe repository cache path")
        lockdir = settings.data_dir / "sync-locks"
        lockdir.mkdir(exist_ok=True)
        import fcntl
        with (lockdir / (target.name + ".lock")).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
                       "-c", "protocol.ext.allow=never", "-c", "credential.helper="]
            if target.exists():
                service.check_repository(settings, str(target))
                command += ["-C", str(target), "fetch", "--prune", "--tags", url, "+refs/heads/*:refs/remotes/origin/*"]
            else:
                command += ["clone", "--no-checkout", "--", url, str(target)]
            env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                   "GIT_ALLOW_PROTOCOL": "https"}
            ops.event(task["id"], "git_sync", "Explicit approved clone/fetch, no checkout/build")
            subprocess.run(command, env=env, check=True, timeout=spec["timeout_seconds"])
        existing = next((r for r in store.repositories() if r["path"] == str(target)), None)
        repo = existing or store.add_repository(spec["name"], str(target))
        remote_refs = [r for r in service.revisions(repo) if r["ref"].startswith("refs/remotes/origin/")]
        return {"status": "completed", "repository": repo, "url": url,
                "local_head_after_sync": service.revision(repo, "HEAD")["commit"],
                "advertised_remote_refs": remote_refs, "command": command,
                "limitations": ["No checkout or scan was performed; choose a returned immutable commit explicitly."]}
    if kind == "investigation":
        return investigation(settings, store, spec)
    if kind == "validation":
        from .validation import execute_validation
        return execute_validation(settings, store, ops, task)
    reports = wait_reports(settings, store, spec["scan_ids"])
    if any(r is None for r in reports):
        return {"status": "blocked", "scan_ids": spec["scan_ids"], "reason": "Endpoint scan failed/cancelled; comparison unknown"}
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
    raise ValueError("unimplemented operation")
