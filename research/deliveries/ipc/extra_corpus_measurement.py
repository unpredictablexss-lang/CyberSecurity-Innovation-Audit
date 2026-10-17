"""Turn the seven new components' saved runs into one evidence document.

Read-only. Three sources per component, all produced in the same session against
the same pinned clone:

  audit    <audit-root>/<component>/report.json       -- the detector's own result
  roots    <root-root>/<component>/roots.json         -- entry roots the walk had
  probe    <probe-root>/<component>/predicates.jsonl  -- what the interpreter
                                                          attributed to each policy
                                                          predicate it evaluated

The point of putting `roots` beside the candidate count is that zero candidates
has two readings -- "the walk never had an entry in this component" and "it had
entries and traversed them, but no rule's conjunction was satisfied". A component
with zero roots cannot distinguish them; one with roots can. `zero_reason` names
which reading applies, and only the third value is a statement about the rules.

The document follows the shape of
`research/evidence/interface/ipc/component_audit_bline_20261017/components.json`
so the two batches can be read by the same code. Nothing here writes into a
corpus clone; every hash is computed from files on disk, and the report's own
`commit`/`git_tree` are carried through rather than re-derived, so a row stays
bound to the tree its report says it read.

Usage:

  python research/deliveries/ipc/extra_corpus_measurement.py \
      --audit-root  /home/audit/wtmp/ipc-audit-extra \
      --root-root   /home/audit/wtmp/ipc-root-extra \
      --probe-root  /home/audit/wtmp/ipc-probe-extra \
      --out         research/evidence/interface/ipc/extra_corpus_20261017/components.json
"""
import argparse
import collections
import hashlib
import json
import os

RULES = (
    "ipc.relay.descriptor-boundary",
    "ipc.auth.missing",
    "ipc.auth.guard-coverage",
    "ipc.auth.caller-class",
    "ipc.auth.object-owner",
    "ipc.auth.identity-domain",
    "ipc.auth.service-identity",
    "ipc.auth.request-identity",
    "ipc.capability.export",
    "ipc.parcel.copy-range",
    "ipc.parcel.position-underflow",
)

DETECTOR = {
    "path": "src/ohscanner/detectors/interface",
    "version": "0.8.0",
    "model_version": "oh-ipc-2026.10-v6",
    "source": "read-only pinned tree of the interface branch",
    "source_commit": "635b3e0449c552f0ccc25118850d245962845568",
    "driver": "src/ohscanner/detectors/interface/audit.py",
    "passes": ["complete-ast", "all-files"],
}

NOTE = ("Candidates are unverified static evidence, not vulnerabilities; "
        "validated_vulnerability is 0 in every report and confirmed_vulnerabilities "
        "is 0 by construction. A zero in a component is not a statement that the "
        "component is free of findings: read `zero_reason` first. "
        "'no_entry_roots' means the walk had nowhere to start in this component; "
        "'mock_only_entry_roots' means every entry it found sits under a path segment "
        "named mock; only 'entry_roots_walked_no_rule_conjunction' attributes the "
        "zero to the rules. Raw reports stay outside Git; report_sha256 binds each "
        "row to the report it came from.")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path, default=None):
    try:
        with open(path) as handle:
            return json.load(handle)
    except OSError:
        return default


def load_jsonl(path):
    try:
        with open(path) as handle:
            return [json.loads(line) for line in handle if line.strip()]
    except OSError:
        return []


def is_mock_path(path):
    """Whether a root file or one of its directories is named as mock.

    Deliberately generous: 'mock' as a whole segment, a segment ending in 'mock'
    (preferencesmock/), or a basename starting with 'mock_'. This classifies the
    corpus location only; it makes no claim about what the code does.
    """
    segments = path.replace("\\", "/").split("/")
    for index, segment in enumerate(segments):
        if segment == "mock" or segment.endswith("mock"):
            return True
        if index == len(segments) - 1 and segment.startswith("mock_"):
            return True
    return False


def zero_reason(candidate_count, roots):
    """Name which of the three readings a zero candidate count has."""
    if candidate_count:
        return None
    if not roots.get("n_distinct_roots"):
        return "no_entry_roots"
    files = roots.get("distinct_root_files") or []
    if files and all(is_mock_path(path) for path in files):
        return "mock_only_entry_roots"
    return "entry_roots_walked_no_rule_conjunction"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--root-root", required=True)
    parser.add_argument("--probe-root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    components = sorted(name for name in os.listdir(args.audit_root)
                        if os.path.isdir(os.path.join(args.audit_root, name)))
    rows = []
    totals = collections.Counter()
    per_rule = collections.defaultdict(dict)
    for name in components:
        report_path = os.path.join(args.audit_root, name, "report.json")
        report = load_json(report_path)
        if report is None:
            rows.append({"component": name, "status": "no_report"})
            continue
        roots = load_json(os.path.join(args.root_root, name, "roots.json"), {}) or {}
        records = load_jsonl(os.path.join(args.probe_root, name, "predicates.jsonl"))
        coverage = report["coverage"]["analysis_coverage"]
        counts = collections.Counter(c.get("rule_id")
                                     for c in report.get("candidates") or [])
        by_subject = collections.Counter(str(r.get("subject")) for r in records
                                         if r.get("bucket", "identity") == "identity")
        caller_class = collections.Counter(
            "class_set" if r.get("caller_class_set") else "no_class"
            for r in records if r.get("bucket") == "caller_class")
        candidate_map = {rule: counts[rule] for rule in RULES if counts.get(rule)}
        row = {
            "component": name,
            "repository": report.get("repository"),
            "commit": report.get("commit"),
            "git_tree": report.get("git_tree"),
            "snapshot_sha256": report.get("snapshot_sha256"),
            "plan_sha256": report.get("plan_sha256"),
            "scope": {
                "selected_files": coverage["files_selected"],
                "selected_bytes": coverage["bytes_selected"],
            },
            "analysis": {
                "parsed_complete": coverage.get("parse_complete"),
                "parsed_partial": coverage.get("parse_partial"),
                "analyzed_files": coverage.get("files_analyzed"),
                "unexamined_reasons": coverage.get("files_not_analyzed_by_reason") or {},
                "files_in_scope_without_a_claiming_detector":
                    coverage.get("files_in_scope_without_a_claiming_detector") or {},
                "bucket_closure_closed": coverage["bucket_closure"]["closed"],
            },
            "zero_reason": zero_reason(sum(counts.values()), roots),
            "candidates": candidate_map,
            "candidates_total": sum(counts.values()),
            "candidate_sites": [
                {"file": c.get("file"), "line": c.get("line"),
                 "rule_id": c.get("rule_id"), "symbol": c.get("symbol"),
                 "passes": c.get("passes"),
                 "file_parse_status": c.get("file_parse_status"),
                 "file_analysis_status": c.get("file_analysis_status"),
                 "source_sha256": c.get("source_sha256")}
                for c in report.get("candidates") or []],
            "candidates_with_runner_obligations":
                coverage.get("candidates_with_runner_obligations"),
            "confirmed_vulnerabilities": 0,
            "validated_vulnerability": report.get("validated_vulnerability"),
            "elapsed_seconds": report.get("elapsed_seconds"),
            "report_sha256": sha256(report_path),
            "root_probe": {
                "distinct_roots": roots.get("n_distinct_roots"),
                "distinct_root_files": roots.get("n_distinct_root_files"),
                "value_calls": roots.get("value_calls"),
                "distinct_functions": roots.get("n_distinct_functions"),
                "root_files": (roots.get("distinct_root_files") or [])[:8],
            },
            "predicate_probe": {
                "records": len(records),
                "evaluations_by_subject": dict(sorted(by_subject.items())),
                "caller_class_evaluations": dict(sorted(caller_class.items())),
            },
        }
        for rule in RULES:
            if counts.get(rule):
                per_rule[rule][name] = counts[rule]
        totals["selected_files"] += row["scope"]["selected_files"]
        totals["selected_bytes"] += row["scope"]["selected_bytes"]
        totals["parsed_complete"] += row["analysis"]["parsed_complete"] or 0
        totals["parsed_partial"] += row["analysis"]["parsed_partial"] or 0
        totals["candidates"] += row["candidates_total"]
        totals["value_calls"] += roots.get("value_calls") or 0
        rows.append(row)

    document = {
        "schema_version": 1,
        "kind": "ipc_component_audit_measurement",
        "batch": "B-line corpus extension (7 repositories added 2026-10-17)",
        "generated": "2026-10-17 Asia/Shanghai",
        "detector": DETECTOR,
        "instruments": {
            "root_probe": "research/deliveries/ipc/root_probe_site/sitecustomize.py",
            "predicate_probe": "research/deliveries/ipc/probe_site/sitecustomize.py",
            "mechanism": "PYTHONPATH sitecustomize wrappers over the pinned Interpreter; "
                         "the driver argv is otherwise unchanged and neither wrapper "
                         "changes a computed value.",
            "attribution": "research/evidence/interface/ipc/extra_corpus_20261017/"
                           "attribution.json",
        },
        "totals": dict(sorted(totals.items())),
        "per_rule": {rule: per_rule[rule] for rule in RULES if per_rule.get(rule)},
        "components": rows,
        "refused_runs": [row["component"] for row in rows
                         if row.get("status") == "no_report"],
        "note": NOTE,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps(document["totals"], ensure_ascii=False))
    for row in rows:
        if row.get("status") == "no_report":
            print("%-34s NO REPORT" % row["component"])
            continue
        print("%-34s roots=%-3s analyzed=%-4s cand=%-2d %-32s %s" % (
            row["component"], row["root_probe"]["distinct_roots"],
            row["analysis"]["analyzed_files"], row["candidates_total"],
            row["zero_reason"] or "-",
            " ".join("%s=%d" % (k.split(".")[-1], v)
                     for k, v in row["candidates"].items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
