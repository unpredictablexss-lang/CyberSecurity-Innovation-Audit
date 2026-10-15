"""Reproduce the owner IPC identity baseline from fixed local Git objects.

The checked-in JSON is a compact historical identity baseline, not a replacement
for the original ignored report bytes.  It preserves the pre-M1 diagnostic IDs,
derived Workbench candidate IDs, milestone membership and published hash
prefixes.  The scan path remains the ordinary allowlisted ohscan-run command.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

from src.ohscanner.contracts import safe_relative_path
from src.ohscanner.git_source import (
    MAX_BLOB_BYTES,
    MAX_SOURCE_FILES,
    MAX_TOTAL_BYTES,
    SOURCE_LANGUAGES,
)

PRODUCTION_EXCLUDED_SEGMENTS = frozenset((
    "test", "tests", "unittest", "unittests", "fuzztest", "fuzz",
    "mock", "mocks", "sample", "samples", "example", "examples",
    "demo", "demos", "benchmark", "benchmarks",
    "third_party", "thirdparty", "3rdparty",
))
BASELINE_PATH = Path("outputs/reports/m1_descriptor_identity/historical_identity_baseline.json")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    done = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
        capture_output=True,
        timeout=120,
    )
    if done.returncode:
        raise ValueError(done.stderr.decode("utf-8", "replace")[:1000])
    return done.stdout


def read_tree(repo, commit):
    raw_entries = git(repo, "ls-tree", "-r", "-z", "-l", commit).split(b"\x00")
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
    return tuple(entries)


def shard_digest(entries):
    digest = hashlib.sha256()
    for path, oid in entries:
        digest.update((path + ":" + oid + "\n").encode("utf-8"))
    return digest.hexdigest()


def plan_digest(commit, shards):
    digest = hashlib.sha256()
    digest.update(("plan:" + commit + "\n").encode("utf-8"))
    for shard in shards:
        digest.update((shard_digest(shard) + "\n").encode("utf-8"))
    return digest.hexdigest()


def plan_scope(repo, commit):
    """Reproduce audit.py@f077e85:plan_scope for the pinned baseline."""
    selected = []
    for path, mode, kind, oid, size in read_tree(repo, commit):
        if any(part in PRODUCTION_EXCLUDED_SEGMENTS for part in Path(path).parts[:-1]):
            continue
        if kind == "commit" or mode == "160000" or mode == "120000":
            continue
        if SOURCE_LANGUAGES.get(Path(path).suffix.lower()) is None or kind != "blob":
            continue
        if size in {"-", "BAD"} or not size.isdecimal():
            raise ValueError("missing or invalid local blob size: " + path)
        size_bytes = int(size)
        if size_bytes > MAX_BLOB_BYTES:
            continue
        selected.append((path, oid, size_bytes))
    selected.sort(key=lambda item: item[0])
    shards = []
    current = []
    current_bytes = 0
    for path, oid, size in selected:
        if current and (len(current) + 1 > MAX_SOURCE_FILES
                        or current_bytes + size > MAX_TOTAL_BYTES):
            shards.append(tuple(current))
            current = []
            current_bytes = 0
        current.append((path, oid, size))
        current_bytes += size
    if current:
        shards.append(tuple(current))
    digest_shards = [tuple((path, oid) for path, oid, _ in shard) for shard in shards]
    return {
        "paths": tuple(path for path, _, _ in selected),
        "selected_files": len(selected),
        "selected_bytes": sum(size for _, _, size in selected),
        "shards": [
            {
                "files": len(shard),
                "bytes": sum(size for _, _, size in shard),
                "shard_sha256": shard_digest(items),
            }
            for shard, items in zip(shards, digest_shards)
        ],
        "plan_sha256": plan_digest(commit, digest_shards),
        "sorted_paths_sha256": sha256(
            "".join(path + "\n" for path in sorted(item[0] for item in selected)).encode("utf-8")
        ),
    }


def identity_rows(report):
    run = report["detector_runs"][0]
    coverage = report["detector_coverage"]["detectors"][run["tool"]]
    source_hashes = coverage["source_sha256"]
    proofs = {item["diagnostic_id"]: item for item in coverage["evidence_obligations"]}
    rows = {}
    for diagnostic in run["diagnostics"]:
        proof = proofs[diagnostic["diagnostic_id"]]
        source_sha256 = diagnostic.get("source_sha256") or proof["source_sha256"]
        key = (diagnostic["file"], diagnostic["line"], diagnostic["rule_id"], source_sha256)
        if key in rows:
            raise ValueError("duplicate candidate comparison identity: " + repr(key))
        candidate_identity = sha256(json.dumps([
            report["repository"], report["commit"], report["snapshot_sha256"],
            run["tool"], run["tool_version"], diagnostic["diagnostic_id"],
        ]).encode("utf-8"))
        rows[key] = {
            "diagnostic_id": diagnostic["diagnostic_id"],
            "candidate_id": candidate_identity,
            "source_sha256": source_sha256,
            "source_map_matches": source_hashes.get(diagnostic["file"]) == source_sha256,
        }
    return rows


def baseline_rows(component):
    rows = {}
    for row in component["candidates"]:
        key = (row["file"], row["line"], row["rule_id"], row["source_sha256"])
        if key in rows:
            raise ValueError("duplicate baseline identity: " + repr(key))
        rows[key] = row
    return rows


def validate_baseline(data):
    if data.get("kind") != "ohscanner.m1-descriptor-identity-historical-baseline-v1":
        raise ValueError("unsupported historical baseline kind")
    if data.get("schema_version") != 1:
        raise ValueError("unsupported historical baseline schema")
    components = data.get("components", [])
    if len(components) != 5:
        raise ValueError("baseline must contain five components")
    totals = {"pre_m1": 0, "post_m1": 0, "expected_current": 0, "m1_removed": 0, "m2_removed": 0}
    seen = set()
    for component in components:
        name = component["component"]
        if name in seen:
            raise ValueError("duplicate component: " + name)
        seen.add(name)
        rows = baseline_rows(component)
        pre = [row for row in rows.values() if "pre_m1" in row["milestones"]]
        post = [row for row in rows.values() if "post_m1" in row["milestones"]]
        current = [row for row in rows.values() if "expected_current" in row["milestones"]]
        m1_removed = [row for row in pre if "post_m1" not in row["milestones"]]
        m2_removed = [row for row in post if "expected_current" not in row["milestones"]]
        if len(rows) != len(pre):
            raise ValueError(name + " contains rows outside the pre-M1 baseline")
        if not all("current_diagnostic_id" in row and "current_candidate_id" in row for row in current):
            raise ValueError(name + " lost current diagnostic/candidate identity")
        if any("current_diagnostic_id" in row for row in rows.values() if row not in current):
            raise ValueError(name + " assigns current identity to a removed candidate")
        counts = {
            "pre_m1": len(pre), "post_m1": len(post), "expected_current": len(current),
            "m1_removed": len(m1_removed), "m2_removed": len(m2_removed),
        }
        for key, value in counts.items():
            totals[key] += value
        expected = component["milestone_deltas"]
        if counts["m1_removed"] != expected["m1_removed_count"] or counts["m2_removed"] != expected["m2_removed_count"]:
            raise ValueError(name + " milestone counts do not match")
        if counts["expected_current"] != component["expected_current"]["candidate_count"]:
            raise ValueError(name + " current count does not match")
    if totals != data["counts"] | {"added": 0, "confirmed_vulnerabilities": 0}:
        # Compare only the five milestone fields; the two zero-valued policy
        # counters are validated separately so schema evolution stays explicit.
        expected = {key: data["counts"][key] for key in totals}
        if totals != expected:
            raise ValueError("baseline aggregate counts do not match: " + repr((totals, expected)))
    if data["counts"]["added"] != 0 or data["counts"]["confirmed_vulnerabilities"] != 0:
        raise ValueError("baseline must not invent additions or confirmed vulnerabilities")
    return totals


def run_component(project, source_root, out_dir, component):
    name = component["component"]
    repo = source_root / name
    if repo.is_symlink() or not repo.is_dir():
        raise ValueError(name + ": source repository must be an existing non-symlink directory")
    commit = git(repo, "rev-parse", component["commit"]).decode().strip()
    tree = git(repo, "rev-parse", commit + "^{tree}").decode().strip()
    if commit != component["commit"] or tree != component["git_tree"]:
        raise ValueError(name + ": pinned commit/tree mismatch")
    planned = plan_scope(repo, commit)
    expected_scope = component["source_scope"]
    for field in ("selected_files", "selected_bytes", "plan_sha256", "sorted_paths_sha256"):
        if planned[field] != expected_scope[field]:
            raise ValueError(name + ": source scope drift in " + field)
    if planned["shards"] != expected_scope["shards"]:
        raise ValueError(name + ": source shard drift")
    output = out_dir / (name + ".json")
    markdown = out_dir / (name + ".md")
    command = [sys.executable, "-m", "src.cli", "ohscan-run", "--repo-dir", str(repo),
               "--repository", component["repository"], "--commit", commit,
               "--detector", "ohscanner.interface.ipc", "--json-out", str(output),
               "--md-out", str(markdown)]
    for path in planned["paths"]:
        command.extend(("--include", path))
    print("START", name, "files=", len(planned["paths"]), flush=True)
    started = time.perf_counter()
    done = subprocess.run(command, cwd=project, text=True, capture_output=True)
    (out_dir / (name + ".terminal.txt")).write_text(done.stdout + done.stderr, encoding="utf-8")
    if done.returncode:
        raise RuntimeError(name + ": " + done.stderr[-2000:])
    report = json.loads(output.read_text(encoding="utf-8"))
    actual = identity_rows(report)
    expected_rows = baseline_rows(component)
    expected = {
        key: row for key, row in expected_rows.items()
        if "expected_current" in row["milestones"]
    }
    missing = sorted(set(expected) - set(actual))
    added = sorted(set(actual) - set(expected))
    identity_mismatches = []
    for key in sorted(set(actual) & set(expected)):
        if (actual[key]["diagnostic_id"] != expected[key]["current_diagnostic_id"]
                or actual[key]["candidate_id"] != expected[key]["current_candidate_id"]
                or not actual[key]["source_map_matches"]):
            identity_mismatches.append(key)
    summary = {
        "component": name,
        "repository": report["repository"],
        "commit": report["commit"],
        "git_tree": report["git_tree"],
        "snapshot_sha256": report["snapshot_sha256"],
        "indexed_files": report["scope"]["selected_source_files"],
        "source_parsing": report["source_parsing"],
        "candidate_count": len(actual),
        "expected_candidate_count": len(expected),
        "candidate_set_equal": not missing and not added,
        "identity_mismatches": identity_mismatches,
        "removed": [list(key) for key in missing],
        "added": [list(key) for key in added],
        "validated_vulnerability": report["validated_vulnerability"],
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "command": command,
        "artifacts": {
            "report.json": sha256(output.read_bytes()),
            "report.md": sha256(markdown.read_bytes()),
        },
    }
    print("RESULT", name, "candidates=", len(actual), "same=", summary["candidate_set_equal"],
          "identity_mismatches=", len(identity_mismatches), flush=True)
    if not summary["candidate_set_equal"] or identity_mismatches:
        raise AssertionError(name + ": candidate identity regression; investigate, do not adjust expectations")
    if summary["indexed_files"] != expected_scope["selected_files"]:
        raise AssertionError(name + ": source scope drift")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path,
                        help="Directory containing the five fixed component Git checkouts")
    parser.add_argument("--baseline-json", type=Path,
                        default=Path(__file__).resolve().parents[1] / BASELINE_PATH)
    parser.add_argument("--out-dir", type=Path, default=Path("outputs/reports/owner_ipc_integration"))
    parser.add_argument("--validate-baseline-only", action="store_true")
    args = parser.parse_args()
    baseline = json.loads(args.baseline_json.read_text(encoding="utf-8"))
    totals = validate_baseline(baseline)
    if args.validate_baseline_only:
        print(json.dumps({"baseline": str(args.baseline_json), "counts": totals}, sort_keys=True))
        return 0
    if args.source_root is None:
        parser.error("--source-root is required unless --validate-baseline-only is used")
    project = Path(__file__).resolve().parents[1]
    implementation_files = sorted((project / "src/ohscanner").rglob("*.py")) + [project / "src/cli/main.py"]
    implementation_hashes = {
        str(path.relative_to(project)): sha256(path.read_bytes())
        for path in implementation_files
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "implementation_hashes.json").write_text(
        json.dumps(implementation_hashes, indent=2) + "\n", encoding="utf-8"
    )
    summaries = []
    for component in baseline["components"]:
        summary = run_component(project, args.source_root.resolve(), args.out_dir, component)
        summaries.append(summary)
        (args.out_dir / "verification.json").write_text(
            json.dumps({
                "baseline_sha256": sha256(args.baseline_json.read_bytes()),
                "historical_original_report_hashes_verified": False,
                "historical_hash_limitation": baseline["historical"]["published_record"]["full_original_report_hashes"],
                "counts": totals,
                "components": summaries,
            }, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if implementation_hashes != {
        str(path.relative_to(project)): sha256(path.read_bytes())
        for path in implementation_files
    }:
        raise AssertionError("implementation changed during experiment; rerun on stable code")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
