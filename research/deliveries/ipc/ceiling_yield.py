r"""What the two coverage fixes would actually yield, per rule, per reading.

Read-only. Reads the baseline reports (the detector as it stands) and one or more
*counterfactual* report sets produced by `ceiling_probe_site`, and reports the
per-rule candidate delta. Nothing here is a detector result -- every number is
"what the same detector would emit if these extra functions were entry roots".

A delta is only meaningful when it is attributed, so for every new candidate the
tool keeps the file, the line and the `Entry=` symbol parsed out of the message.
In the reports this reads, those candidates carry the root they came from only in
the message (AUTH-02/03/04 have no named per-candidate mechanism field there), so
that parse is disclosed rather than hidden; the `symbol` field is reported
untouched alongside it. The reports come from the pinned detector `0.8.0` /
`oh-ipc-2026.10-v6`; a later detector in the same tree adds a per-family mechanism
CWE to every finding, which these reports predate. The parse is therefore a
property of the pinned evidence, not a gap in the current detector.

Usage (paths are the caller's; nothing is defaulted):

  python research/deliveries/ipc/ceiling_yield.py \
      --baseline-root <dir with <component>/report.json> \
      --reading all=<dir> --reading services=<dir> --reading interfaces=<dir> \
      --instrument research/deliveries/ipc/ceiling_probe_site/sitecustomize.py \
      --out <path to write the JSON to>
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import re

ENTRY_RE = re.compile(r"Entry=([^;]+);")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def by_rule(report):
    return collections.Counter(c["rule_id"] for c in report.get("candidates") or [])


def identity(candidate):
    return (candidate["rule_id"], candidate["file"], candidate.get("line"))


def entry_of(candidate):
    match = ENTRY_RE.search(candidate.get("message") or "")
    return match.group(1).strip() if match else ""


def owner_of(entry):
    return entry.split("::")[0] if "::" in entry else ""


def read_reports(root):
    reports = {}
    for path in sorted(glob.glob(os.path.join(root, "*", "report.json"))):
        reports[os.path.basename(os.path.dirname(path))] = json.load(open(path))
    return reports


def read_logs(root):
    logs = {}
    for path in sorted(glob.glob(os.path.join(root, "*", "ceiling.json"))):
        logs[os.path.basename(os.path.dirname(path))] = json.load(open(path))
    return logs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-root", required=True)
    parser.add_argument("--reading", action="append", required=True,
                        help="NAME=DIR, repeatable")
    parser.add_argument("--instrument", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    baseline = read_reports(args.baseline_root)
    base_rule = collections.Counter()
    for report in baseline.values():
        base_rule.update(by_rule(report))

    readings = {}
    for item in args.reading:
        name, _, root = item.partition("=")
        reports = read_reports(root)
        logs = read_logs(root)
        rule = collections.Counter()
        for report in reports.values():
            rule.update(by_rule(report))
        # A reading covers a subset of the baseline. Comparing it against the whole
        # baseline would report the components it does not contain as a loss, so the
        # comparison is restricted to the components the reading actually ran on.
        covered = sorted(set(reports) & set(baseline))
        restricted = collections.Counter()
        for component in covered:
            restricted.update(by_rule(baseline[component]))

        new_candidates = []
        for component, report in reports.items():
            seen = {identity(c) for c in (baseline.get(component, {}).get("candidates") or [])}
            for candidate in report.get("candidates") or []:
                if identity(candidate) not in seen:
                    entry = entry_of(candidate)
                    new_candidates.append({
                        "component": component,
                        "rule_id": candidate["rule_id"],
                        "file": candidate["file"],
                        "line": candidate.get("line"),
                        "symbol": candidate.get("symbol"),
                        "entry": entry,
                        "entry_owner": owner_of(entry),
                        "candidate": candidate.get("confidence"),
                    })

        added = [r for log in logs.values() for r in log["added_roots"]]
        readings[name] = {
            "root": root,
            "components": len(reports),
            "components_compared_against_baseline": covered,
            "components_in_the_reading_but_not_the_baseline":
                sorted(set(reports) - set(baseline)),
            "components_with_a_log": len(logs),
            "candidates": sum(rule.values()),
            "candidates_by_rule": dict(rule),
            "baseline_candidates_over_the_same_components": sum(restricted.values()),
            "baseline_candidates_by_rule_over_the_same_components": dict(restricted),
            "delta_by_rule": {k: rule.get(k, 0) - restricted.get(k, 0)
                              for k in sorted(set(rule) | set(restricted))
                              if rule.get(k, 0) != restricted.get(k, 0)},
            "delta_total": sum(rule.values()) - sum(restricted.values()),
            "added_roots": len(added),
            "added_roots_by_side": dict(collections.Counter(r.get("side", "?") for r in added)),
            "added_roots_by_owner_suffix": dict(collections.Counter(
                (r["function"].split("::")[0][-8:] if "::" in r["function"] else "(free)")
                for r in added)),
            "new_candidates": len(new_candidates),
            "new_candidates_by_rule": dict(collections.Counter(
                c["rule_id"] for c in new_candidates)),
            "new_candidates_by_component": dict(collections.Counter(
                c["component"] for c in new_candidates)),
            "new_candidates_detail": sorted(
                new_candidates, key=lambda c: (c["rule_id"], c["file"], c["line"] or 0)),
        }

    document = {
        "what": "Per-rule candidate delta between the detector as it stands and the "
                "same detector with counterfactual entry roots. Every delta is an "
                "upper bound on a coverage fix, not a candidate the detector makes.",
        "instrument": args.instrument,
        "instrument_sha256": sha256(args.instrument),
        "baseline_root": args.baseline_root,
        "baseline_components": len(baseline),
        "baseline_candidates": sum(base_rule.values()),
        "baseline_candidates_by_rule": dict(base_rule),
        "readings": readings,
        "how_to_read": "Each reading differs only in which counterfactual roots were "
                       "added: `all` = every function naming a policy predicate, "
                       "`services` = only methods of a `*Service`/`*Stub` class, "
                       "`interfaces` = the client-side tree. `new_candidates_detail` "
                       "carries the file, line and `Entry=` root of every added "
                       "candidate so each one can be read against its source; the "
                       "candidate count is not evidence that any of them is real. The "
                       "`Entry=` field is parsed out of the message because the pinned "
                       "reports carry no per-candidate mechanism field; a later detector "
                       "in the same tree adds a per-family mechanism CWE that these "
                       "reports predate.",
    }
    with open(args.out, "w") as handle:
        json.dump(document, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("wrote", args.out)
    print("baseline", sum(base_rule.values()), dict(base_rule))
    for name, reading in readings.items():
        print("%-12s components %d  candidates %4d (baseline over the same components %4d)  delta %s" % (
            name, reading["components"], reading["candidates"],
            reading["baseline_candidates_over_the_same_components"],
            json.dumps(reading["delta_by_rule"], sort_keys=True)))


if __name__ == "__main__":
    main()
