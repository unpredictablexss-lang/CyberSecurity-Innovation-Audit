"""Audit one pinned OpenHarmony component: production scope, sharding, review digest.

Scope planning, sharding, coverage reporting and candidate rendering are
detector-agnostic; only the pass table below names this line's detectors. It is
kept in the interface module rather than the shared bridge on purpose: the
shared entry point (frontend/registry/ToolRunResult) is owned by the project
owner, and promoting this there is an owner decision, not a unilateral one.

Why this exists
---------------
The shared entry point (`ohscanner.execution.run_reviewed_detectors`) takes a
scope as a tuple of include prefixes and refuses a scope above the core bounds
(2000 files / 32 MiB). Auditing a real component needs three things that entry
point does not provide:

  1. a production-code scope derived from the pinned tree -- test, mock and
     sample trees excluded by rule rather than by hand (a hand-written `SKIP`
     list that spelled `/test/` but not `/tests/` already counted 629 test-tree
     files as production code once);
  2. a deterministic sharding of components larger than the core bounds, so a
     51 MiB component can be audited at all;
  3. a report that keeps coverage depth legible: which files were walked, which
     had a partial parse, which candidates came from where, and what was never
     looked at.

This module adds those three on top of the shared entry point. It is not a
second scanner: source pinning, detector execution and the immutability re-read
all remain `run_reviewed_detectors`. Generated artifacts belong outside Git.

Two passes per shard
--------------------
`IpcInterfaceDetector` walks partial and complete parses alike and reports the
whole run as `blocked` when any unit's parse is incomplete. A blocked run still
records `scope_files`/`scope_loc` as 0, so each shard is run twice:

  * `complete-ast` - the runner selects complete-AST units only, so the run
    completes: real counters, and per-candidate obligations recorded;
  * `all-files`   - partial trees included, so recall is kept; the run is
    `blocked` and its two scope counters read 0, which is reported as such and
    never as "nothing was analyzed". Its per-candidate obligations are recorded
    as for any other run, so a candidate only this pass can see keeps its proof
    obligations instead of losing them along with the counters.

The merge keys candidates on `CANDIDATE_IDENTITY_FIELDS` -- repository, commit,
rule id, rule version, file, line, source hash -- and records which passes saw
each one, so a candidate visible in both is counted once. Seeing a candidate in
both passes is the same interpretation applied twice to the same file, not two
independent sources of evidence; the report says so rather than calling it
corroboration. Per-source obligations are unioned, never overwritten by a later
pass, so a second analysis adds evidence instead of replacing the first.

A candidate whose obligations the shared runner did not record is not printed as
an empty list -- which reads as "nothing left to prove". The driver attaches the
standing questions for that rule with status `unknown` and marks each one
`origin: audit_driver`, and it does so only where the record is absent: an
obligation the runner did record is never duplicated or replaced by the driver's
own. An obligation is a question, not a claim, so a partial file's candidate can
carry one; the driver never invents an AST fact for it.

Nothing is promoted: every row stays a candidate, `validated_vulnerability`
stays 0.

Honest boundaries this driver keeps
-----------------------------------
- Excluded, oversize, non-UTF8, symlink, submodule and unreadable entries are
  counted with their reasons and never counted as examined.
- Planned files are accounted for in closed buckets (complete / partial / failed
  / unclaimed-by-detector / dropped-by-loader / not-run). A residual is printed
  as `files_unaccounted` instead of being rounded into another bucket.
- A shard that raises is reported `not_analyzed` for that shard and pass; other
  shards still run. A failure is never converted into "no candidates".
- Zero candidates prints as "not proof of safety", never as clean.
- Source excerpts are read from the pinned Git blob, never from the working tree.
- Sharding is deterministic, and one component was checked under one alternative
  shard configuration. Invariance under arbitrary sharding is NOT claimed: a rule
  with a component-global view would have to be evaluated on the whole component.

Report format is `schema_version` 2 (was 1): candidates carry their source
binding, rule/detector version and per-source obligations.

Usage:
  .venv/bin/python -m src.ohscanner.detectors.interface.audit \
      --repo-dir ~/openharmony-audit/perf-corpus/communication_dsoftbus \
      --repository openharmony/communication_dsoftbus \
      --commit 652f88e0261ce4d0610f73cc451c26b84d2597af \
      --out-dir outputs/reports
"""
import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ...contracts import safe_relative_path
from ...execution import run_reviewed_detectors
from ...git_source import (
    MAX_BLOB_BYTES,
    MAX_SOURCE_FILES,
    MAX_TOTAL_BYTES,
    SOURCE_LANGUAGES,
    resolve_commit,
)
from ...runner import DetectorRegistry
from .detector import IpcInterfaceCompleteAstDetector, IpcInterfaceDetector

# Directory names that hold tests, mocks, samples or vendored code. Matched as a
# whole path segment, so `testing/` and `protest.cpp` are not excluded by
# accident and `/tests/` is not missed the way a substring list misses it.
PRODUCTION_EXCLUDED_SEGMENTS = (
    "test", "tests", "unittest", "unittests", "fuzztest", "fuzz",
    "mock", "mocks", "sample", "samples", "example", "examples",
    "demo", "demos", "benchmark", "benchmarks",
    "third_party", "thirdparty", "3rdparty",
)

PASS_DETECTORS = {
    "complete-ast": IpcInterfaceCompleteAstDetector,
    "all-files": IpcInterfaceDetector,
}

# Every scope decision that drops an entry gets a name, so the report can show
# why a file is missing instead of leaving the reader to guess.
SKIPPED_EXAMPLE_LIMIT = 200

# Pre-seeded so a report carries a zero for a reason that did not occur. A
# missing key and a zero are different statements, and a reader must be able to
# tell "no file was oversize" from "oversize was not counted".
COUNT_KEYS = (
    "tracked_entries", "out_of_scope", "excluded_pattern", "non_source",
    "symlinks", "submodules", "oversize", "unreadable",
    "selected_files", "selected_bytes", "shards",
)

SCHEMA_VERSION = 2

# The identity of a candidate for de-duplication. Within one audit the first two
# fields are constant, so this is the same decision the earlier four-field key
# made; across persisted audits they are what keeps two candidates from different
# experiments apart instead of silently fusing them by file path. The rule
# version is in the key because a rule change can move a finding without moving
# the file.
CANDIDATE_IDENTITY_FIELDS = (
    "repository", "commit", "rule_id", "rule_version",
    "file", "line", "source_sha256",
)

# Obligations a candidate carries when the shared runner recorded none for it.
# These state what still has to be proven, at status `unknown`: an obligation is
# a question, not a claim, so a candidate from a partially parsed file can carry
# one. They are marked `origin: audit_driver` and are never rendered as runner
# evidence, and no AST fact is invented for the file they describe. They are not
# attached to a candidate the runner did record, so they never duplicate
# recorded evidence. The old name was `PARTIAL_ONLY_OBLIGATIONS`, from when the
# only way to reach this branch was a pass that could see partial files.
DRIVER_STANDING_OBLIGATIONS = (
    ("entry_reachability",
     "Verify the entry is reachable by a caller and under which product build and "
     "macro conditions."),
    ("caller_identity_conditions",
     "Establish the caller identity and the permission conditions the modelled "
     "operation requires."),
    ("guard_effectiveness",
     "Establish whether an effective check protects the modelled operation on the "
     "reaching path."),
    ("parse_completeness_impact",
     "Establish whether the partial parse of this file affects the judgement this "
     "candidate rests on. A partial AST can hide statements, so the candidate is "
     "kept, not cleared."),
    ("configuration_path_existence",
     "Establish whether a corresponding path exists under the current, unexpanded "
     "preprocessor configuration."),
)

DRIVER_OBLIGATION_ORIGIN = "audit_driver"
RUNNER_OBLIGATION_ORIGIN = "shared_runner"

# The bucket identity every planned file must satisfy. A residual is reported,
# never folded into another bucket.
BUCKET_IDENTITY = (
    "files_selected = parse_complete + parse_partial + parse_failed "
    "+ unclaimed_by_detector + dropped_by_loader + not_run_files"
)


def _detector_meta(pass_name):
    """Identity of the detector behind a pass, read off the class, never guessed.

    `interpretation_id` is what a candidate's identity uses, and it is NOT the
    variant's `detector_id`: two passes that apply the same interpretation at
    different scope limits are one interpretation, and giving them separate
    identities would split one candidate into two rows (the failure mode this
    avoids). A pass that used a genuinely different algorithm must declare a
    different `interpretation_id` so the driver keeps them apart instead of
    fusing them.
    """
    cls = PASS_DETECTORS[pass_name]
    detector_version = getattr(cls, "version", None)
    model_version = getattr(cls, "model_version", None)
    interpretation_id = (getattr(cls, "interpretation_id", None)
                         or getattr(cls, "detector_id", None))
    return {
        "detector_id": getattr(cls, "detector_id", None),
        "detector_version": detector_version,
        "model_version": model_version,
        "interpretation_id": interpretation_id,
        "interpretation_version": "+".join(
            part for part in (detector_version, model_version) if part) or "unversioned",
    }


def _rule_version(meta):
    """The interpretation revision a candidate's identity is bound to."""
    interpretation = meta.get("interpretation_id") or "unknown"
    return interpretation + "@" + (meta.get("interpretation_version") or "unversioned")


def candidate_identity(item):
    """The de-duplication key, including the fields that survive persistence."""
    return tuple(item.get(field) for field in CANDIDATE_IDENTITY_FIELDS)


def _driver_obligations(reason):
    return [
        {
            "kind": kind,
            "description": description,
            "status": "unknown",
            "origin": DRIVER_OBLIGATION_ORIGIN,
            "reason": reason,
        }
        for kind, description in DRIVER_STANDING_OBLIGATIONS
    ]


@dataclass(frozen=True)
class TreeEntry:
    """One pinned source blob: the unit an audit shard is built from."""
    path: str
    oid: str
    size: int


@dataclass(frozen=True)
class ScopePlan:
    """The pinned, sharded, reason-annotated scope an audit will run over."""
    repository: str
    commit: str
    git_tree: str
    includes: tuple
    excludes: tuple
    production_only: bool
    selected: tuple
    shards: tuple
    counts: dict
    skipped_examples: tuple
    plan_sha256: str

    def to_dict(self, include_files=True):
        return {
            "repository": self.repository,
            "commit": self.commit,
            "git_tree": self.git_tree,
            "includes": list(self.includes),
            "excludes": list(self.excludes),
            "production_only": self.production_only,
            "plan_sha256": self.plan_sha256,
            "counts": dict(self.counts),
            "shards": [
                {
                    "shard_id": index,
                    "files": len(entries),
                    "bytes": sum(item.size for item in entries),
                    "first_path": entries[0].path,
                    "last_path": entries[-1].path,
                    "shard_sha256": shard_digest(entries),
                    "paths": [item.path for item in entries] if include_files else [],
                }
                for index, entries in enumerate(self.shards)
            ],
            "skipped_examples": list(self.skipped_examples),
        }


def _git_bytes(repo, *args, timeout=120):
    """Read-only Git call with the shared reader's discipline.

    `git_source._git` is not exported, so the same call is repeated here rather
    than imported: same repository check, same timeout, and no fetch.
    """
    repo = Path(repo)
    if repo.is_symlink() or not repo.is_dir():
        raise ValueError("source repository must be an existing non-symlink directory")
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, timeout=timeout
    )
    if done.returncode != 0:
        raise ValueError(
            "git command failed: git -C <repo> " + " ".join(args) + ": "
            + done.stderr.decode("utf-8", "replace").strip()
        )
    return done.stdout


def shard_digest(entries):
    """Stable identity of a shard's exact content (paths bound to blob IDs)."""
    digest = hashlib.sha256()
    for item in entries:
        digest.update((item.path + ":" + item.oid + "\n").encode("utf-8"))
    return digest.hexdigest()


def plan_digest(commit, shards):
    digest = hashlib.sha256()
    digest.update(("plan:" + commit + "\n").encode("utf-8"))
    for entries in shards:
        digest.update((shard_digest(entries) + "\n").encode("utf-8"))
    return digest.hexdigest()


def read_tree(repo, commit):
    """Every tracked entry of the pinned commit: mode, kind, oid, size, path.

    Sizes come from `ls-tree -l` without reading a single blob, so planning stays
    cheap on a large component; the run itself re-reads and re-verifies the
    objects through the shared loader.
    """
    _resolved, tree = resolve_commit(repo, commit)
    raw_entries = _git_bytes(repo, "ls-tree", "-r", "-z", "-l", commit).split(b"\x00")
    entries = []
    seen = set()
    for raw in raw_entries:
        if not raw:
            continue
        try:
            metadata, path_bytes = raw.split(b"\t", 1)
            mode, kind, oid, size = metadata.decode("ascii").split()
            path = safe_relative_path(path_bytes.decode("utf-8"))
        except (ValueError, UnicodeError) as error:
            raise ValueError("malformed or unsafe Git tree entry") from error
        if path in seen:
            raise ValueError("duplicate Git tree entry: " + path)
        seen.add(path)
        entries.append((path, mode, kind, oid, size))
    return tree, tuple(entries)


def _excluded_by(path, segments):
    """True when a whole path segment is an excluded directory name."""
    return any(part in segments for part in Path(path).parts[:-1])


def plan_scope(
    repo,
    repository,
    commit,
    includes=(".",),
    excludes=(),
    production_only=True,
    max_files=MAX_SOURCE_FILES,
    max_bytes=MAX_TOTAL_BYTES,
):
    """Derive a pinned, sharded production scope with a reason for every drop.

    Order of decisions follows `git_source.load_git_sources` so the two agree:
    scope prefix, then excludes, then entry kind, then language, then size.
    """
    if not includes or len(set(includes)) != len(includes):
        raise ValueError("include paths must be nonempty and distinct")
    for include in includes:
        if include != ".":
            safe_relative_path(include)
    for exclude in excludes:
        safe_relative_path(exclude)
    segments = tuple(PRODUCTION_EXCLUDED_SEGMENTS) if production_only else ()
    tree, raw_entries = read_tree(repo, commit)

    counts = Counter({key: 0 for key in COUNT_KEYS})
    skipped = []
    selected = []
    effective_excludes = list(excludes) + (
        ["//production-segment:" + name for name in segments] if production_only else []
    )

    for path, mode, kind, oid, size in raw_entries:
        counts["tracked_entries"] += 1
        if not any(item == "." or path == item or path.startswith(item + "/")
                   for item in includes):
            counts["out_of_scope"] += 1
            continue
        if excludes and any(path == item or path.startswith(item + "/")
                            for item in excludes):
            counts["excluded_pattern"] += 1
            skipped.append({"file": path, "reason": "explicit_exclude"})
            continue
        if segments and _excluded_by(path, segments):
            counts["excluded_pattern"] += 1
            segment = next(part for part in Path(path).parts[:-1] if part in segments)
            skipped.append({"file": path, "reason": "production_exclude:" + segment})
            continue
        if kind == "commit" or mode == "160000":
            counts["submodules"] += 1
            skipped.append({"file": path, "reason": "submodule"})
            continue
        if mode == "120000":
            counts["symlinks"] += 1
            skipped.append({"file": path, "reason": "symlink"})
            continue
        language = SOURCE_LANGUAGES.get(Path(path).suffix.lower())
        if language is None or kind != "blob":
            counts["non_source"] += 1
            continue
        if size in ("-", "BAD"):
            # `ls-tree -l` prints '-' (some versions 'BAD') for a promisor blob
            # that is not local. The shared loader fails on these; the audit
            # records the file as unreadable and keeps going.
            counts["unreadable"] += 1
            skipped.append({"file": path, "reason": "missing_local_blob"})
            continue
        if not size.isdecimal():
            raise ValueError("invalid blob size in Git tree: " + path)
        size_bytes = int(size)
        if size_bytes > MAX_BLOB_BYTES:
            counts["oversize"] += 1
            skipped.append({"file": path, "reason": "oversize"})
            continue
        selected.append(TreeEntry(path, oid, size_bytes))

    selected.sort(key=lambda item: item.path)
    shards = plan_shards(selected, max_files=max_files, max_bytes=max_bytes)
    counts["selected_files"] = len(selected)
    counts["selected_bytes"] = sum(item.size for item in selected)
    counts["shards"] = len(shards)
    if not selected:
        raise ValueError("no supported UTF-8 source outside the excluded scope")
    return ScopePlan(
        repository=repository,
        commit=commit,
        git_tree=tree,
        includes=tuple(includes),
        excludes=tuple(effective_excludes),
        production_only=production_only,
        selected=tuple(selected),
        shards=shards,
        counts=dict(counts),
        skipped_examples=tuple(skipped[:SKIPPED_EXAMPLE_LIMIT]),
        plan_sha256=plan_digest(commit, shards),
    )


def plan_shards(entries, max_files=MAX_SOURCE_FILES, max_bytes=MAX_TOTAL_BYTES):
    """Split a sorted entry list into shards inside the core loader's bounds.

    Deterministic: paths stay in sorted order and a file never moves to a later
    shard to make room for another, so the same component and commit always give
    the same shard membership. Shard boundaries are reported, not hidden: a shard
    is a budget boundary, not a security boundary.
    """
    if max_files < 1 or max_bytes < 1:
        raise ValueError("shard bounds must be positive")
    shards = []
    current = []
    current_bytes = 0
    for entry in entries:
        if entry.size > max_bytes:
            raise ValueError("single source exceeds the shard byte bound: " + entry.path)
        if current and (len(current) + 1 > max_files
                        or current_bytes + entry.size > max_bytes):
            shards.append(tuple(current))
            current = []
            current_bytes = 0
        current.append(entry)
        current_bytes += entry.size
    if current:
        shards.append(tuple(current))
    return tuple(shards)


def _run_shard(repo_dir, repository, commit, entries, pass_name):
    """Run one pass over one shard through the shared, reviewed entry point."""
    registry = DetectorRegistry()
    registry.register(PASS_DETECTORS[pass_name]())
    started = time.monotonic()
    report = run_reviewed_detectors(
        repo_dir, repository, commit, tuple(item.path for item in entries), registry
    )
    return {"status": "ran", "error": "", "report": report,
            "elapsed_seconds": round(time.monotonic() - started, 3)}


def run_audit(repo_dir, repository, commit, plan, passes=("complete-ast", "all-files")):
    """Run every pass over every shard; a failing shard never stops the audit."""
    for name in passes:
        if name not in PASS_DETECTORS:
            raise ValueError("unknown pass: " + str(name))
    shard_runs = []
    for index, entries in enumerate(plan.shards):
        record = {
            "shard_id": index,
            "files": len(entries),
            "bytes": sum(item.size for item in entries),
            "first_path": entries[0].path,
            "last_path": entries[-1].path,
            "shard_sha256": shard_digest(entries),
            "passes": {},
        }
        for pass_name in passes:
            try:
                record["passes"][pass_name] = _run_shard(
                    repo_dir, repository, commit, entries, pass_name
                )
            except Exception as error:  # report the failure; never convert it to clean
                record["passes"][pass_name] = {
                    "status": "error",
                    "error": type(error).__name__ + ": " + str(error),
                    "report": None,
                    "elapsed_seconds": None,
                }
        shard_runs.append(record)
    return shard_runs


def _pass_view(shard_run, pass_name):
    """Flatten one pass of one shard into the numbers a report can show."""
    record = shard_run["passes"].get(pass_name)
    view = {
        "shard_id": shard_run["shard_id"],
        "pass": pass_name,
        "run_state": record["status"],
        "error": record["error"],
        "elapsed_seconds": record["elapsed_seconds"],
        "detector_status": None,
        "applicable_files": 0,
        "analyzed_files": 0,
        "unexamined_reasons": {},
        "scope_files": 0,
        "scope_loc": 0,
        "diagnostics": 0,
        "parse_status": {},
        "report_status": None,
        # What the plan asked for versus what the shared loader actually read.
        # A gap here means a planned file was not read, and it is reported rather
        # than assumed read.
        "planned_files": shard_run["files"],
        "loaded_files": 0,
        "loaded_bytes": 0,
        "dropped_by_loader": 0,
    }
    report = record.get("report")
    if not report:
        return view, None, {}
    loaded = report.get("scope", {})
    view["loaded_files"] = loaded.get("selected_source_files", 0)
    view["loaded_bytes"] = loaded.get("selected_source_bytes", 0)
    view["dropped_by_loader"] = loaded.get("binary_or_non_utf8", 0)
    run = report["detector_runs"][0]
    coverage = report["detector_coverage"]["detectors"][run["tool"]]
    view["report_status"] = report["status"]
    view["detector_status"] = run["status"]
    view["scope_files"] = run["scope_files"]
    view["scope_loc"] = run["scope_loc"]
    view["diagnostics"] = run["diagnostic_count"]
    view["applicable_files"] = coverage["applicable_files"]
    view["analyzed_files"] = len(coverage["analyzed_files"])
    view["unexamined_reasons"] = dict(
        Counter(item["reason"] for item in coverage["unexamined"])
    )
    view["parse_status"] = dict(Counter(item["status"] for item in run["parsing"]))
    return view, run, {
        "obligations": {
            item["diagnostic_id"]: item["obligations"]
            for item in coverage.get("evidence_obligations", [])
        },
    }


def merge_shard_runs(shard_runs, passes, repository=None, commit=None):
    """Merge shard results into one audit view without double counting.

    Candidates keep per-source provenance and per-source obligations; a later
    pass adds to them rather than replacing them.
    """
    runs = []
    parse_map = {}
    candidates = {}
    shard_errors = []

    for shard_run in shard_runs:
        for pass_name in passes:
            view, run, extra = _pass_view(shard_run, pass_name)
            runs.append(view)
            if view["run_state"] == "error":
                shard_errors.append({
                    "shard_id": shard_run["shard_id"],
                    "pass": pass_name,
                    "error": view["error"],
                    "files_not_analyzed": shard_run["files"],
                })
                continue
            if not run:
                continue
            # Per-file, not per-pass: a file interpreted by either pass was
            # interpreted. Recording the blocked pass last would otherwise report
            # a component as entirely unexamined while its candidates sit in the
            # same report. Each pass's own reason is kept so the reviewer can see
            # which scope skipped the file and why.
            for item in run["parsing"]:
                entry = parse_map.get(item["file"])
                if entry is None:
                    entry = {"file": item["file"], "status": item["status"],
                             "issues": list(item.get("issues", [])),
                             "analyzed_by": [], "reasons_by_pass": {}}
                    parse_map[item["file"]] = entry
                elif entry["status"] != item["status"]:
                    # Parse status is a property of the pinned file, so two
                    # passes should agree. If they ever do not, report the worse
                    # of the two rather than the more favourable one.
                    if "partial" in (entry["status"], item["status"]):
                        entry["status"] = "partial"
                entry["reasons_by_pass"][pass_name] = item["analysis_reason"]
                if (item["analysis_status"] == "analyzed"
                        and pass_name not in entry["analyzed_by"]):
                    entry["analyzed_by"].append(pass_name)
            for entry in parse_map.values():
                entry["analysis_status"] = (
                    "analyzed" if entry["analyzed_by"] else "not_analyzed"
                )
                reasons = [reason for reason in entry["reasons_by_pass"].values() if reason]
                # A specific reason ("incomplete_ast:partial") tells the reviewer
                # more than the run-level "blocked" that a wider pass records.
                entry["analysis_reason"] = next(
                    (reason for reason in reasons if reason != "blocked"),
                    reasons[0] if reasons else "",
                )
            for diagnostic in run["diagnostics"]:
                meta = _detector_meta(pass_name)
                rule_version = _rule_version(meta)
                key = (repository, commit, diagnostic["rule_id"], rule_version,
                       diagnostic["file"], diagnostic["line"],
                       diagnostic.get("source_sha256", ""))
                entry = candidates.get(key)
                if entry is None:
                    parsed = parse_map.get(diagnostic["file"], {})
                    entry = {
                        "file": diagnostic["file"],
                        "line": diagnostic["line"],
                        "rule_id": diagnostic["rule_id"],
                        "repository": repository,
                        "commit": commit,
                        "rule_version": rule_version,
                        "interpretation_id": meta["interpretation_id"],
                        "observed_detector_versions": [],
                        "observed_detector_ids": [],
                        "symbol": diagnostic.get("symbol"),
                        "severity": diagnostic.get("severity"),
                        "confidence": diagnostic.get("confidence"),
                        "evidence_type": diagnostic.get("evidence_type"),
                        "candidate_cwe": diagnostic.get("candidate_cwe"),
                        "consequence_impact": diagnostic.get("consequence_impact"),
                        "consequence_cwe": diagnostic.get("consequence_cwe"),
                        "source_sha256": diagnostic.get("source_sha256", ""),
                        "source_binding": diagnostic.get("source_binding"),
                        "message": diagnostic.get("message", ""),
                        "shard_id": shard_run["shard_id"],
                        "passes": [],
                        "sources": [],
                        "obligations": [],
                        "obligations_by_source": {},
                        "obligations_source": None,
                        "obligations_recorded_by_runner": False,
                        "file_parse_status": parsed.get("status", "unknown"),
                        "file_analysis_status": parsed.get("analysis_status", "unknown"),
                        "file_analysis_reason": parsed.get("analysis_reason", ""),
                    }
                    candidates[key] = entry
                if pass_name not in entry["passes"]:
                    entry["passes"].append(pass_name)
                obligations = extra["obligations"].get(diagnostic["diagnostic_id"])
                source = {
                    "pass": pass_name,
                    "shard_id": shard_run["shard_id"],
                    "diagnostic_id": diagnostic.get("diagnostic_id"),
                    "source_binding": diagnostic.get("source_binding"),
                    "obligations_recorded": bool(obligations),
                    "detector_id": meta["detector_id"],
                    "detector_version": meta["detector_version"],
                    "model_version": meta["model_version"],
                }
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                if rule_version not in entry["observed_detector_versions"]:
                    entry["observed_detector_versions"].append(rule_version)
                if meta["detector_id"] and meta["detector_id"] not in entry["observed_detector_ids"]:
                    entry["observed_detector_ids"].append(meta["detector_id"])
                if obligations:
                    # Union, never overwrite: a second pass's obligations are added
                    # to the first pass's, so no evidence source replaces another.
                    entry["obligations_by_source"][pass_name] = obligations
                    entry["obligations_recorded_by_runner"] = True
                    for obligation in obligations:
                        marker = (obligation.get("kind"), obligation.get("description"),
                                  obligation.get("status"))
                        if not any(
                            (kept.get("kind"), kept.get("description"), kept.get("status"))
                            == marker for kept in entry["obligations"]
                        ):
                            entry["obligations"].append(dict(
                                obligation,
                                origin=RUNNER_OBLIGATION_ORIGIN,
                                source_pass=pass_name,
                            ))

    ordered = sorted(candidates.values(),
                     key=lambda item: (item["file"], item["line"], item["rule_id"]))
    for entry in ordered:
        entry["passes"].sort()
        entry["sources"].sort(key=lambda item: item["pass"])
        entry["observed_detector_versions"].sort()
        entry["observed_detector_ids"].sort()
        # The variant named here is the primary (first by pass name) one; every
        # variant that saw the candidate is listed in observed_detector_ids.
        primary = entry["sources"][0]
        entry["detector_id"] = primary["detector_id"]
        entry["detector_version"] = primary["detector_version"]
        entry["model_version"] = primary["model_version"]
        if not entry["obligations"]:
            entry["obligations_source"] = "driver_synthesized_unknown"
            entry["obligations"] = _driver_obligations(
                "No obligation was recorded by the shared runner for this candidate: the "
                "coverage sidecar returned for its pass names none for this diagnostic. The "
                "items below are the audit driver's standing questions for this rule, "
                "initialised to unknown. An empty list was never a statement that nothing "
                "needs proving."
            )
        else:
            entry["obligations_source"] = RUNNER_OBLIGATION_ORIGIN
    return {
        "pass_runs": runs,
        "parse_map": parse_map,
        "candidates": ordered,
        "shard_errors": shard_errors,
    }


def coverage_depth(merged, plan, passes):
    """The three-part split: run state, analysis coverage, root-cause intersection.

    Kept separate on purpose. One ratio over these hides the difference between
    "this file was read and interpreted", "this file was read with an incomplete
    parse" and "this file was never opened".
    """
    parse_distribution = Counter(item["status"] for item in merged["parse_map"].values())
    # A planned file can be missing from the parse map for two very different
    # reasons: no selected detector declares its language, or the file was never
    # read. Only the first is "unclaimed"; the second belongs in
    # dropped_by_loader / not_run_files. Naming the declared languages keeps the
    # two apart instead of counting a dropped C++ file as one nobody claims --
    # which would double-count it and break the closure identity below.
    errored_shards = {item["shard_id"] for item in merged["shard_errors"]}
    reachable = set()
    for index, entries in enumerate(plan.shards):
        if index not in errored_shards:
            reachable.update(item.path for item in entries)
    declared_languages = set()
    for pass_name in passes:
        declared_languages.update(
            getattr(PASS_DETECTORS[pass_name], "supported_languages", ()))
    outside_language = Counter()
    outside_language_files = []
    for entry in plan.selected:
        if entry.path in reachable and entry.path not in merged["parse_map"]:
            language = SOURCE_LANGUAGES.get(Path(entry.path).suffix.lower(), "unknown")
            if language in declared_languages:
                continue  # claimed but not parsed: a load/run gap, not an unclaimed file
            outside_language[language] += 1
            if len(outside_language_files) < SKIPPED_EXAMPLE_LIMIT:
                outside_language_files.append({"file": entry.path, "language": language})
    analyzed = sum(1 for item in merged["parse_map"].values()
                   if item["analysis_status"] == "analyzed")
    unexamined = Counter(
        item["analysis_reason"] for item in merged["parse_map"].values()
        if item["analysis_status"] != "analyzed"
    )
    candidate_parse = Counter(item["file_parse_status"] for item in merged["candidates"])
    blocked_with_candidates = [
        view for view in merged["pass_runs"]
        if view["detector_status"] == "blocked" and view["diagnostics"] > 0
    ]
    notes = []
    if blocked_with_candidates:
        notes.append(
            "A blocked run records scope_files and scope_loc as 0 even though it emitted "
            "candidates; its per-candidate evidence obligations are recorded as for any "
            "other run. Read the applicable/analyzed counts for those shards, not the zero."
        )
    # The plan and the loader are two independent decisions. Where they disagree,
    # a planned file was not read, and saying so is the difference between a
    # coverage claim and a coverage measurement.
    plan_vs_load = {
        "mismatches": [
            {
                "shard_id": view["shard_id"],
                "pass": view["pass"],
                "planned_files": view["planned_files"],
                "loaded_files": view["loaded_files"],
                "dropped_by_loader": view["dropped_by_loader"],
            }
            for view in merged["pass_runs"]
            if view["run_state"] == "ran" and view["loaded_files"] != view["planned_files"]
        ],
    }
    if plan_vs_load["mismatches"]:
        notes.append(
            f"{len(plan_vs_load['mismatches'])} pass run(s) read fewer files than the plan "
            "selected. The shared loader drops non-UTF8 blobs from its own budget; every "
            "such file is listed under plan_vs_load.mismatches and was not analyzed."
        )
    if outside_language:
        notes.append(
            f"{sum(outside_language.values())} planned file(s) are in a language no selected "
            "detector declares ("
            + ", ".join(f"{name}: {count}" for name, count in sorted(outside_language.items()))
            + "). They were in scope and no detector claims them, so they are neither a miss "
            "nor an examined clean file."
        )
    # Closure of the file accounting. Every planned file must land in exactly one
    # bucket. A residual means the report does not add up, and it is printed
    # rather than folded into whichever bucket is nearest.
    planned_by_shard = Counter()
    loaded_by_shard = {}
    for view in merged["pass_runs"]:
        shard_id = view["shard_id"]
        planned_by_shard[shard_id] = max(planned_by_shard[shard_id], view["planned_files"])
        if view["run_state"] == "ran":
            loaded_by_shard[shard_id] = max(loaded_by_shard.get(shard_id, 0),
                                            view["loaded_files"])
    not_run_files = 0
    dropped_by_loader = 0
    for shard_id, planned in planned_by_shard.items():
        if shard_id not in loaded_by_shard:
            not_run_files += planned
        else:
            dropped_by_loader += planned - loaded_by_shard[shard_id]
    parse_failed = sum(count for status, count in parse_distribution.items()
                       if status not in ("complete", "partial"))
    bucket_closure = {
        "identity": BUCKET_IDENTITY,
        "files_selected": plan.counts["selected_files"],
        "parse_complete": parse_distribution.get("complete", 0),
        "parse_partial": parse_distribution.get("partial", 0),
        "parse_failed": parse_failed,
        "unclaimed_by_detector": sum(outside_language.values()),
        "dropped_by_loader": dropped_by_loader,
        "not_run_files": not_run_files,
    }
    bucket_closure["files_unaccounted"] = plan.counts["selected_files"] - sum(
        bucket_closure[key] for key in (
            "parse_complete", "parse_partial", "parse_failed",
            "unclaimed_by_detector", "dropped_by_loader", "not_run_files",
        )
    )
    bucket_closure["closed"] = bucket_closure["files_unaccounted"] == 0
    if not bucket_closure["closed"]:
        notes.append(
            f"The file accounting does not close: {bucket_closure['files_unaccounted']} of "
            f"{plan.counts['selected_files']} planned file(s) fall in no bucket. That is a "
            "reporting defect, not a coverage claim; treat these coverage numbers as "
            "unverified until it is explained."
        )
    runner_obligations = sum(1 for item in merged["candidates"]
                             if item["obligations_recorded_by_runner"])
    return {
        "run_state": {
            "shards": len(plan.shards),
            "passes": list(passes),
            "shards_with_errors": len(merged["shard_errors"]),
            "pass_runs": merged["pass_runs"],
        },
        "analysis_coverage": {
            "files_selected": plan.counts["selected_files"],
            "bytes_selected": plan.counts["selected_bytes"],
            "parse_status": dict(parse_distribution),
            "parse_complete": parse_distribution.get("complete", 0),
            "parse_partial": parse_distribution.get("partial", 0),
            "files_in_scope_without_a_claiming_detector": dict(outside_language),
            "files_in_scope_without_a_claiming_detector_examples": outside_language_files,
            "files_analyzed": analyzed,
            "files_not_analyzed_by_reason": dict(unexamined),
            "candidates": len(merged["candidates"]),
            "candidate_files": len({item["file"] for item in merged["candidates"]}),
            "candidates_by_file_parse_status": dict(candidate_parse),
            "candidates_with_runner_obligations": runner_obligations,
            "candidates_with_driver_synthesized_obligations":
                len(merged["candidates"]) - runner_obligations,
            "bucket_closure": bucket_closure,
            "plan_vs_load": plan_vs_load,
            "notes": notes,
        },
        "root_cause_intersection": {
            "state": "not_measured",
            "reason": (
                "No labelled root-cause set is bound to this component. The curated "
                "historical pairs are measured by measure_entry_coverage.py; a component "
                "audit reports candidates and coverage only."
            ),
        },
    }


def _excerpt(repo_dir, entry, line, context):
    """Lines around a candidate, read from the pinned blob (not the worktree)."""
    if entry is None:
        return None
    data = _git_bytes(repo_dir, "cat-file", "blob", entry.oid)
    lines = data.decode("utf-8", "replace").splitlines()
    start = max(1, line - context)
    end = min(len(lines), line + context)
    return {
        "start_line": start,
        "end_line": end,
        "blob_oid": entry.oid,
        "lines": [
            {"number": number, "text": lines[number - 1], "candidate": number == line}
            for number in range(start, end + 1)
        ],
    }


def audit_component(
    repo_dir,
    repository,
    commit,
    *,
    includes=(".",),
    excludes=(),
    production_only=True,
    max_files=MAX_SOURCE_FILES,
    max_bytes=MAX_TOTAL_BYTES,
    passes=("complete-ast", "all-files"),
    excerpt_context=4,
):
    """Plan, run and merge one component audit. Returns the report dict."""
    repo_dir = Path(repo_dir)
    started = time.monotonic()
    plan = plan_scope(
        repo_dir, repository, commit, includes=includes, excludes=excludes,
        production_only=production_only, max_files=max_files, max_bytes=max_bytes,
    )
    shard_runs = run_audit(repo_dir, repository, commit, plan, passes=passes)
    merged = merge_shard_runs(shard_runs, passes, repository=repository, commit=commit)
    by_path = {item.path: item for item in plan.selected}
    if excerpt_context > 0:
        for entry in merged["candidates"]:
            entry["excerpt"] = _excerpt(
                repo_dir, by_path.get(entry["file"]), entry["line"], excerpt_context
            )
    depth = coverage_depth(merged, plan, passes)
    snapshot = None
    for shard_run in shard_runs:
        for record in shard_run["passes"].values():
            if record.get("report"):
                snapshot = record["report"]["snapshot_sha256"]
                break
        if snapshot:
            break
    analysis = depth["analysis_coverage"]
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment_kind": "component_audit",
        "repository": repository,
        "commit": commit,
        "git_tree": plan.git_tree,
        "snapshot_sha256": snapshot,
        "plan_sha256": plan.plan_sha256,
        "provenance": "local_git_objects",
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "validated_vulnerability": 0,
        # Three different counts, kept apart on purpose: a passing test suite says
        # nothing about detection quality, and a candidate count is not a finding
        # count. Confirmed vulnerabilities stays 0 until the evidence gate is met.
        "counts": {
            "source_files_audited": analysis["files_selected"],
            "candidates": len(merged["candidates"]),
            "candidates_with_runner_obligations":
                analysis["candidates_with_runner_obligations"],
            "candidates_with_driver_synthesized_obligations":
                analysis["candidates_with_driver_synthesized_obligations"],
            "confirmed_vulnerabilities": 0,
            "false_positives_reviewed": 0,
        },
        "scope": plan.to_dict(),
        "passes": list(passes),
        "coverage": depth,
        "candidates": merged["candidates"],
        "shard_errors": merged["shard_errors"],
        "limitations": [
            "Candidates are unverified syntax evidence, not vulnerabilities.",
            "Zero candidates does NOT mean the component is free of vulnerabilities.",
            "The declared repository is user input; source is pinned local Git objects, "
            "not an OpenHarmony product build.",
            "Excluded, oversize, non-UTF8, symlink, submodule and unreadable entries are "
            "outside the audited scope; their counts are reported, not hidden.",
            "No compilation flags, macro configuration, symbolic execution or reachability "
            "proof. Preprocessor-conditional code is parsed as written.",
            "Candidates from a partially parsed file carry a partial AST; the finding is "
            "kept but its parse depth is reported per row.",
            "Where the shared runner recorded no obligations for a candidate, the driver "
            "attaches its standing questions at status unknown and marks them "
            "origin: audit_driver. That is a gap in the recorded evidence, not an absence of "
            "obligations, and not runner-produced evidence. Where the record is present the "
            "driver adds nothing of its own.",
            "A candidate seen by both passes is one interpretation applied twice to the same "
            "file, not two independent sources of evidence.",
            "Sharding is deterministic and the candidate set matched on one component under "
            "one alternative shard configuration. Invariance under arbitrary sharding is not "
            "claimed: a rule with a component-global view would need whole-component "
            "evaluation, which no pass here performs.",
        ],
    }


def merge_audit_reports(reports):
    """Merge persisted audit reports into one candidate view.

    Candidates are merged on `CANDIDATE_IDENTITY_FIELDS` -- repository, commit,
    rule id and version, file, line and source hash -- so two experiments over the
    same file at different revisions stay separate rows instead of fusing by path
    alone. Per-source obligations are unioned, so a second experiment adds
    evidence rather than replacing the first.

    `seen_in_reports` records every report a candidate appeared in. That is
    repetition of the same interpretation, NOT independent corroboration, and it
    is not a promotion: the merged view still holds candidates only.
    """
    merged = {}
    for index, report in enumerate(reports):
        for item in report.get("candidates", []):
            key = candidate_identity(item)
            entry = merged.get(key)
            if entry is None:
                entry = json.loads(json.dumps(item))
                entry["seen_in_reports"] = []
                merged[key] = entry
            entry["seen_in_reports"].append({
                "index": index,
                "repository": report.get("repository"),
                "commit": report.get("commit"),
                "passes": list(item.get("passes", [])),
            })
            target = entry.setdefault("obligations_by_source", {})
            for source_pass, obligations in (item.get("obligations_by_source") or {}).items():
                kept = target.setdefault(source_pass, [])
                for obligation in obligations:
                    if obligation not in kept:
                        kept.append(obligation)
    return {
        "experiment_kind": "component_audit_merge",
        "reports": [
            {
                "index": index,
                "repository": report.get("repository"),
                "commit": report.get("commit"),
                "plan_sha256": report.get("plan_sha256"),
                "candidates": len(report.get("candidates", [])),
            }
            for index, report in enumerate(reports)
        ],
        "candidate_identity_fields": list(CANDIDATE_IDENTITY_FIELDS),
        "candidates": sorted(
            merged.values(),
            key=lambda item: (item.get("file", ""), item.get("line", 0),
                              item.get("rule_id", "")),
        ),
        "limitations": [
            "A candidate present in several reports is one interpretation repeated, "
            "not independent corroboration.",
            "Merging candidates does not merge coverage: each report's coverage stands "
            "for its own scope and commit.",
        ],
    }


def render_markdown(report):
    """Human view: binding, run state, analysis coverage, candidates, gaps."""
    scope = report["scope"]
    coverage = report["coverage"]
    analysis = coverage["analysis_coverage"]
    counts = scope["counts"]
    lines = [
        "# Component audit: " + report["repository"],
        "",
        "> Candidate evidence and coverage. Not a validated vulnerability list, and a",
        "> zero-candidate audit is not a clean component.",
        "",
        f"- Pinned commit: `{report['commit']}`",
        f"- Git tree: `{report['git_tree']}`",
        f"- Source snapshot SHA-256: `{report['snapshot_sha256']}`",
        f"- Scope plan SHA-256: `{report['plan_sha256']}`",
        f"- Passes: {', '.join('`' + name + '`' for name in report['passes'])}",
        f"- Wall clock: {report['elapsed_seconds']}s",
        "- Validated vulnerabilities: **0** (static candidates only)",
        "",
        "## 1. Run state",
        "",
        "| Shard | Pass | Detector status | Planned | Loaded | Applicable | Analyzed | Diagnostics | Scope files | Seconds |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for view in coverage["run_state"]["pass_runs"]:
        lines.append(
            f"| {view['shard_id']} | `{view['pass']}` | "
            f"{view['detector_status'] or view['run_state']} "
            f"| {view['planned_files']} | {view['loaded_files']} "
            f"| {view['applicable_files']} | {view['analyzed_files']} | {view['diagnostics']} "
            f"| {view['scope_files']} | {view['elapsed_seconds']} |"
        )
    for mismatch in analysis["plan_vs_load"]["mismatches"]:
        lines.append(
            f"- shard {mismatch['shard_id']} / `{mismatch['pass']}`: "
            f"{mismatch['planned_files']} files planned, {mismatch['loaded_files']} read "
            f"({mismatch['dropped_by_loader']} dropped by the loader as non-UTF8)"
        )
    if report["shard_errors"]:
        lines.extend(["", "Failed shards (never converted into \"no candidates\"):", ""])
        for item in report["shard_errors"]:
            lines.append(
                f"- shard {item['shard_id']} / `{item['pass']}`: "
                f"{item['files_not_analyzed']} files not analyzed — {item['error']}"
            )
    lines.extend([
        "",
        "## 2. Analysis coverage",
        "",
        "### Scope actually derived from the pinned tree",
        "",
        "| Measure | Count |",
        "|---|---:|",
        f"| Tracked entries | {counts.get('tracked_entries', 0)} |",
        f"| Out of the requested include prefixes | {counts.get('out_of_scope', 0)} |",
        f"| Excluded as test/mock/sample/vendored | {counts.get('excluded_pattern', 0)} |",
        f"| Non-source | {counts.get('non_source', 0)} |",
        f"| Symlinks / submodules | {counts.get('symlinks', 0)} / {counts.get('submodules', 0)} |",
        f"| Oversize (> 1 MiB blob) | {counts.get('oversize', 0)} |",
        f"| Unreadable (blob not local) | {counts.get('unreadable', 0)} |",
        f"| **Audited source files** | **{counts.get('selected_files', 0)}** |",
        f"| **Audited source bytes** | **{counts.get('selected_bytes', 0)}** |",
        f"| Shards | {counts.get('shards', 0)} |",
        "",
        "### Parse depth of the audited scope",
        "",
        f"- Parse status: `{json.dumps(analysis['parse_status'], sort_keys=True)}`",
        f"- Files analyzed: {analysis['files_analyzed']} of {analysis['files_selected']}",
        "- In scope but in a language no selected detector declares: "
        f"`{json.dumps(analysis['files_in_scope_without_a_claiming_detector'], sort_keys=True)}`",
        "- Not analyzed, by reason: "
        f"`{json.dumps(analysis['files_not_analyzed_by_reason'], sort_keys=True)}`",
        f"- Candidates: {analysis['candidates']} in {analysis['candidate_files']} files",
        "- Candidates by the parse status of their file: "
        f"`{json.dumps(analysis['candidates_by_file_parse_status'], sort_keys=True)}`",
        f"- Candidates with runner-recorded obligations: "
        f"{analysis['candidates_with_runner_obligations']}",
        f"- Candidates with driver-synthesized unknown obligations: "
        f"{analysis['candidates_with_driver_synthesized_obligations']}",
        "",
        "### File accounting (must close)",
        "",
    ])
    closure = analysis["bucket_closure"]
    lines.extend([
        f"- {closure['files_selected']} selected = {closure['parse_complete']} complete "
        f"+ {closure['parse_partial']} partial + {closure['parse_failed']} failed "
        f"+ {closure['unclaimed_by_detector']} unclaimed-by-detector "
        f"+ {closure['dropped_by_loader']} dropped-by-loader "
        f"+ {closure['not_run_files']} not-run",
        f"- Identity: `{closure['identity']}`",
        f"- Closed: **{closure['closed']}**"
        + ("" if closure["closed"]
           else f" — {closure['files_unaccounted']} file(s) fall in no bucket"),
    ])
    for note in analysis["notes"]:
        lines.append(f"- NOTE: {note}")
    lines.extend([
        "", "## 3. Candidates for review", "",
        "> A candidate seen by both passes is one interpretation applied twice to the same",
        "> file — repetition, not independent corroboration, and not a promotion.",
        "",
    ])
    if not report["candidates"]:
        lines.extend([
            "No candidate was reported. **This is not proof of safety**: the parse depth",
            "and exclusion counts above bound what was actually read.",
            "",
        ])
    else:
        lines.extend([
            "| # | File:line | Symbol | Rule | Mechanism CWE | Consequence | Parse | Obligations |",
            "|---:|---|---|---|---|---|---|---|",
        ])
        for index, item in enumerate(report["candidates"], start=1):
            consequence = item["consequence_impact"] or "—"
            if item["consequence_cwe"]:
                consequence += " " + item["consequence_cwe"]
            obligations = f"{len(item['obligations'])} ({item['obligations_source']})"
            lines.append(
                f"| {index} | `{item['file']}:{item['line']}` | `{item['symbol']}` "
                f"| `{item['rule_id']}` | {item['candidate_cwe'] or '—'} | {consequence} "
                f"| {item['file_parse_status']} | {obligations} |"
            )
        lines.append("")
        for index, item in enumerate(report["candidates"], start=1):
            lines.extend([
                f"### Candidate {index}: `{item['rule_id']}` at `{item['file']}:{item['line']}`",
                "",
                f"- Symbol: `{item['symbol']}`",
                f"- Seen by passes: {', '.join('`' + name + '`' for name in item['passes'])}",
                f"- File parse status: `{item['file_parse_status']}` "
                f"(analysis status `{item['file_analysis_status']}`"
                + (f", reason `{item['file_analysis_reason']}`" if item["file_analysis_reason"] else "")
                + ")",
                f"- Source binding: `{item['source_binding']}` "
                f"(`{(item['source_sha256'] or '')[:16]}…`)",
                f"- Mechanism CWE: {item['candidate_cwe'] or '—'}; "
                f"possible consequence: {item['consequence_impact'] or '—'} "
                f"{item['consequence_cwe'] or ''}",
                "",
                f"  {item['message']}",
                "",
            ])
            excerpt = item.get("excerpt")
            if excerpt:
                lines.append(
                    f"  Pinned source `{excerpt['blob_oid'][:12]}…`, lines "
                    f"{excerpt['start_line']}-{excerpt['end_line']}:"
                )
                lines.extend(["", "  ```c++"])
                for row in excerpt["lines"]:
                    marker = ">" if row["candidate"] else " "
                    lines.append(f"  {marker} {row['number']:>6}  {row['text']}")
                lines.extend(["  ```", ""])
            lines.extend(["  Still unproven before any claim:", ""])
            for obligation in item["obligations"]:
                lines.append(
                    f"  - `{obligation['kind']}` [{obligation['status']}] "
                    f"(origin `{obligation.get('origin', 'unknown')}`) — "
                    f"{obligation['description']}"
                )
            if item["obligations_source"] == "driver_synthesized_unknown":
                lines.extend([
                    "",
                    "  NOTE: these are the driver's standing questions for this rule at "
                    "status `unknown`, attached because the shared runner recorded no "
                    "obligation for this candidate. They are not runner-produced "
                    "evidence, and they assert nothing about this file's AST.",
                ])
            lines.append("")
    lines.extend([
        "## 4. Not audited",
        "",
        "- Include prefixes: "
        + (", ".join('`' + item + '`' for item in scope["includes"]) or "—"),
        "- Exclusions applied: "
        + (", ".join('`' + item + '`' for item in scope["excludes"]) or "—"),
        "",
        "| File | Reason |",
        "|---|---|",
    ])
    if scope["skipped_examples"]:
        lines.append(
            f"| Showing at most {SKIPPED_EXAMPLE_LIMIT} of the "
            f"{sum(counts.get(key, 0) for key in ('excluded_pattern', 'submodules', 'symlinks', 'oversize', 'unreadable'))} "
            "skipped entries; the counts above are complete. | |"
        )
        for item in scope["skipped_examples"]:
            lines.append(f"| `{item['file']}` | {item['reason']} |")
    else:
        lines.append("| — | nothing was dropped outside the include prefixes |")
    lines.extend([
        "",
        "## 5. Root-cause intersection",
        "",
        f"- State: `{coverage['root_cause_intersection']['state']}`",
        f"- {coverage['root_cause_intersection']['reason']}",
        "",
        "## 6. Limitations",
        "",
    ])
    lines.extend(["- " + item for item in report["limitations"]])
    lines.append("")
    return "\n".join(lines)


def component_slug(repository):
    """A filesystem-safe component name derived from the repository declaration."""
    name = (repository or "component").rstrip("/").split("/")[-1]
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return slug or "component"


def _file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_version(repo_dir):
    try:
        result = subprocess.run(
            ["git", "version"], cwd=str(repo_dir), capture_output=True, text=True,
            timeout=30, check=False,
        )
        return result.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def write_manifest(out_dir, report, json_path, md_path, argv, repo_dir):
    """Provenance for one persisted audit: what was run, where, on what, and hashes.

    Written next to the JSON artifact it describes, so the manifest and the report
    it covers cannot drift apart. The artifact lives outside Git (outputs/reports
    is ignored), so this manifest is what keeps a later review from having to
    guess the command, the source revision or the environment that produced it.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    analysis = report["coverage"]["analysis_coverage"]
    manifest = {
        "experiment_kind": "component_audit_manifest",
        "schema_version": report["schema_version"],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repository": report["repository"],
        "commit": report["commit"],
        "git_tree": report["git_tree"],
        "snapshot_sha256": report["snapshot_sha256"],
        "plan_sha256": report["plan_sha256"],
        "passes": report["passes"],
        "source_repo_path": str(repo_dir),
        "command": list(argv),
        "working_directory": os.getcwd(),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "git": _git_version(repo_dir),
        },
        "counts": report["counts"],
        "bucket_closure": analysis["bucket_closure"],
        "coverage": {
            "files_selected": analysis["files_selected"],
            "bytes_selected": analysis["bytes_selected"],
            "parse_complete": analysis["parse_complete"],
            "parse_partial": analysis["parse_partial"],
            "files_analyzed": analysis["files_analyzed"],
        },
        "artifacts": {
            "json": {"path": str(json_path), "sha256": _file_sha256(json_path)},
            "markdown": {"path": str(md_path), "sha256": _file_sha256(md_path)},
        },
        "limitations": [
            "The artifact is a single run's output; regenerating it at the same commit "
            "with the same command should reproduce the plan and candidate digests.",
            "The declared repository is a declaration, not a verified identity; the "
            "verified identity is the pinned commit and the local Git objects.",
        ],
    }
    manifest_path = out_dir / (component_slug(report["repository"]) + ".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest_path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit one pinned component: scope, shards, coverage, candidates."
    )
    parser.add_argument("--repo-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True,
                        help="Owner/repository declaration, recorded as given")
    parser.add_argument("--commit", required=True, help="Full lowercase commit SHA")
    parser.add_argument("--include", action="append", default=None,
                        help="Repository-relative path or prefix; repeatable")
    parser.add_argument("--exclude", action="append", default=None,
                        help="Repository-relative path or prefix to drop; repeatable")
    parser.add_argument("--include-tests", action="store_true",
                        help="Do not exclude test/mock/sample/vendored trees")
    parser.add_argument("--max-files", type=int, default=MAX_SOURCE_FILES)
    parser.add_argument("--max-bytes", type=int, default=MAX_TOTAL_BYTES)
    parser.add_argument("--passes", default="complete-ast,all-files")
    parser.add_argument("--excerpt-context", type=int, default=4)
    parser.add_argument("--out-dir", default="outputs/reports",
                        help="Persistent artifact directory (default: outputs/reports)")
    parser.add_argument("--json-out", default=None,
                        help="Override the JSON path (default: <out-dir>/<component>.json)")
    parser.add_argument("--md-out", default=None,
                        help="Override the Markdown path (default: <out-dir>/<component>.md)")
    parser.add_argument("--plan-only", action="store_true",
                        help="Derive and print the scope plan without running detectors")
    args = parser.parse_args(argv)

    passes = tuple(item.strip() for item in args.passes.split(",") if item.strip())
    out_dir = Path(args.out_dir)
    slug = component_slug(args.repository)
    json_out = Path(args.json_out) if args.json_out else out_dir / (slug + ".json")
    md_out = Path(args.md_out) if args.md_out else out_dir / (slug + ".md")
    if json_out.resolve() == md_out.resolve():
        raise SystemExit("JSON and Markdown output paths must differ")

    if args.plan_only:
        plan = plan_scope(
            args.repo_dir, args.repository, args.commit,
            includes=tuple(args.include or ["."]), excludes=tuple(args.exclude or []),
            production_only=not args.include_tests,
            max_files=args.max_files, max_bytes=args.max_bytes,
        )
        print(json.dumps(plan.to_dict(include_files=False), indent=2))
        return 0

    report = audit_component(
        args.repo_dir, args.repository, args.commit,
        includes=tuple(args.include or ["."]), excludes=tuple(args.exclude or []),
        production_only=not args.include_tests,
        max_files=args.max_files, max_bytes=args.max_bytes,
        passes=passes, excerpt_context=args.excerpt_context,
    )
    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    md_out.write_text(render_markdown(report), encoding="utf-8")
    manifest_path = write_manifest(
        json_out.parent, report, json_out, md_out,
        [Path(sys.argv[0]).name] + list(argv if argv is not None else sys.argv[1:]),
        args.repo_dir,
    )
    analysis = report["coverage"]["analysis_coverage"]
    closure = analysis["bucket_closure"]
    counts = report["counts"]
    print("[OK] component audit; candidates are unverified evidence, NOT vulnerabilities")
    print(f"[OK] commit: {report['commit']}")
    print(f"[OK] audited files: {analysis['files_selected']} "
          f"({analysis['bytes_selected']} bytes, "
          f"{report['scope']['counts'].get('shards', 0)} shards)")
    print(f"[OK] parse: {json.dumps(analysis['parse_status'], sort_keys=True)}")
    print(f"[OK] file accounting closed: {closure['closed']} "
          f"(unaccounted {closure['files_unaccounted']})")
    # Three counts, reported apart: tests passing, candidates found and
    # vulnerabilities confirmed are three different statements.
    print(f"[OK] candidates: {counts['candidates']} "
          f"(runner obligations {counts['candidates_with_runner_obligations']}, "
          f"driver-synthesized unknown obligations "
          f"{counts['candidates_with_driver_synthesized_obligations']})")
    print(f"[OK] confirmed vulnerabilities: {counts['confirmed_vulnerabilities']}")
    print(f"[OK] JSON report: {json_out}")
    print(f"[OK] Markdown report: {md_out}")
    print(f"[OK] Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
