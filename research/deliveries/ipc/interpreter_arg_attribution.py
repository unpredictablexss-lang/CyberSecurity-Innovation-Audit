r"""Turn a recording of the interpreter's own attributions into the evidence JSON.

The companion instrument is `probe_site/sitecustomize.py`: put that directory on
PYTHONPATH and the driver records, for every permission-predicate call it
evaluates, the `subject` the analysis itself computed (`analysis.py:1364-1378`)
and how many identity issues the call recorded. This script reads those records
plus the reports produced in the same runs and writes one JSON document.

Every number is derived here or hashed live from a pinned corpus file; nothing is
typed in. Read-only: it opens no repository for writing and changes no state.

Usage (paths are the caller's; nothing is defaulted):

  python research/deliveries/ipc/interpreter_arg_attribution.py \
      --probe-root  <dir with <component>/predicates.jsonl per component> \
      --audit-root  <dir with <component>/report.json per component> \
      --corpus-root <repo root>            (repeatable) \
      --probe-site  <path to the sitecustomize.py that made the recording> \
      --out         <path to write the JSON to>
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import subprocess

# The three AUTH-03 rules whose only precondition is the argument a permission
# predicate is handed. Their candidate counts are read out of the reports, and the
# conjunction they additionally need is entailed by those counts -- see
# `conjunction_counts_by_entailment` in the output.
IDENTITY_RULES = ("ipc.auth.identity-domain", "ipc.auth.service-identity",
                  "ipc.auth.request-identity")
CALLER_CLASS_RULE = "ipc.auth.caller-class"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_records(root):
    """{component: [record, ...]} from the JSONL the probe wrote per component."""
    out = {}
    for path in sorted(glob.glob(os.path.join(root, "*", "predicates.jsonl"))):
        component = os.path.basename(os.path.dirname(path))
        with open(path) as handle:
            out[component] = [json.loads(line) for line in handle if line.strip()]
    return out


def rule_counts(audit_root):
    """{rule_id: candidate_count} over every report in the audit root."""
    counts = collections.Counter()
    components = 0
    for path in sorted(glob.glob(os.path.join(audit_root, "*", "report.json"))):
        report = json.load(open(path))
        components += 1
        for candidate in report.get("candidates") or []:
            counts[candidate.get("rule_id")] += 1
    return components, counts


def locate(corpus_roots, component, relative):
    """(repository root, file path) for a corpus-relative file, or (None, None)."""
    for root in corpus_roots:
        repo = os.path.join(root, component)
        path = os.path.join(repo, relative)
        if os.path.isfile(path):
            return repo, path
    return None, None


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True,
                          text=True, check=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-root", required=True)
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--corpus-root", action="append", required=True)
    parser.add_argument("--probe-site", default="")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    document = {
        "what": "What the interpreter attributed to every permission-predicate call it "
                "evaluated. Detector-internal: the wrapper reads the value the analysis "
                "computed and re-evaluates nothing.",
        "instrument": {
            "sitecustomize": args.probe_site,
            "sitecustomize_sha256": sha256(args.probe_site) if args.probe_site else "",
            "mechanism": "A PYTHONPATH sitecustomize wraps Interpreter.value in the pinned "
                         "read-only tree; the driver's argv is otherwise unchanged.",
        },
    }

    records = read_records(args.probe_root)
    by_subject = collections.Counter()
    sites = collections.defaultdict(set)
    per_component = {}
    errors = []
    component_of_file = {}
    for component, rows in records.items():
        for row in rows:
            if "name" not in row:
                errors.append({"component": component, "record": row})
                continue
            subject = str(row.get("subject"))
            by_subject[subject] += 1
            sites[subject].add((row["file"], row["line"], row["name"]))
            component_of_file[row["file"]] = component
            per_component.setdefault(component, collections.Counter())[subject] += 1

    def described(subject):
        out = []
        for relative, line, name in sorted(sites[subject]):
            component = component_of_file[relative]
            repo, path = locate(args.corpus_root, component, relative)
            entry = {"component": component, "file": relative, "line": line,
                     "predicate": name}
            if path:
                entry["source_sha256"] = sha256(path)
                entry["git_commit"] = git(repo, "rev-parse", "HEAD")
            out.append(entry)
        return out

    document["value_attribution"] = {
        "components_probed": len(records),
        "components_that_evaluated_any_predicate":
            sum(1 for rows in records.values() if rows),
        "records_reported_as_errors": errors,
        "evaluations_by_subject": dict(sorted(by_subject.items())),
        "distinct_sites_by_subject": {k: len(v) for k, v in sorted(sites.items())},
        "per_component_evaluations": {k: dict(v) for k, v in sorted(per_component.items())},
        "sites": {subject: described(subject)
                  for subject in ("caller_uid", "self", "request")},
    }

    components, counts = rule_counts(args.audit_root)
    document["components_with_reports"] = components
    document["candidates_by_rule"] = dict(counts.most_common())
    # emit() (analysis.py:612-631) appends to observations unconditionally and
    # detector.py:98-113 maps observations to findings one-to-one, so a rule with
    # zero candidates is a rule that emitted nothing -- its conjunction was never
    # satisfied. The two counts below are read off the reports rather than
    # re-derived by a second pass over the same corpus.
    document["conjunction_counts_by_entailment"] = {
        "how": "Zero candidates for a rule implies zero emissions for that rule "
               "(emit() appends unconditionally; observation->finding is one-to-one), "
               "so these are read from the reports, not from a second instrumented run.",
        "identity_rules_whose_conjunction_was_satisfied":
            sum(counts[rule] for rule in IDENTITY_RULES),
        "caller_class_sensitive_calls_reached_without_a_caller_class":
            counts[CALLER_CLASS_RULE],
        "rules_read": list(IDENTITY_RULES) + [CALLER_CLASS_RULE],
    }

    with open(args.out, "w") as handle:
        json.dump(document, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("wrote", args.out)
    print("evaluations_by_subject",
          json.dumps(document["value_attribution"]["evaluations_by_subject"],
                     sort_keys=True))
    print("distinct_sites_by_subject",
          json.dumps(document["value_attribution"]["distinct_sites_by_subject"],
                     sort_keys=True))


if __name__ == "__main__":
    main()
