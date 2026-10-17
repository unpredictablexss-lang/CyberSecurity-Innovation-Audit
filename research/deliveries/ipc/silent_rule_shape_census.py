"""Count, over the files an audit actually scanned, the shapes a rule keys on.

A rule that never fired has two very different explanations -- it cannot fire, or
nothing in the corpus looks like what it keys on -- and the two are told apart by
counting the shape rather than by adding components. The shapes are the policy's
own named constants (read here, not retyped), and the files are the shard path
lists in the component reports, so the census is on the same scope as the
candidate counts it explains.

Read-only: opens the scoped files and matches text. Writes nothing.

Usage:
  python silent_rule_shape_census.py --audit-root <dir of per-component reports> \
      --corpus-root <root> [--corpus-root <root>]

Each report directory is `<audit-root>/<component>/report.json`; the component's
sources are found under whichever corpus root holds it.
"""
import argparse
import collections
import json
import os
import re
import sys

def repository_root(start):
    """Walk up until the package the policy lives in is importable.

    Counting levels above this file would break the moment the script moves, and
    the script has to be runnable from the repository root like every other
    experiment here.
    """
    here = os.path.dirname(os.path.abspath(start))
    while here != os.path.dirname(here):
        if os.path.isdir(os.path.join(here, "src", "ohscanner")):
            return here
        here = os.path.dirname(here)
    raise SystemExit("repository root not found above " + start)


sys.path.insert(0, repository_root(__file__))

from src.ohscanner.detectors.interface.models import IpcPolicy

POLICY = IpcPolicy()


def shapes():
    """(label, regex) for the shapes of the rules that stayed silent.

    Written against the policy constants so a name added to the model shows up
    here as a shape to count, instead of leaving a rule silently unmeasured.
    """
    def calls(names):
        return r"\b(" + "|".join(sorted(names)) + r")\s*\("

    return {
        "AUTH-03 caller-class: caller_class_sensitive_calls": re.compile(
            calls(POLICY.caller_class_sensitive_calls)),
        "AUTH-03 identity-domain: Verify*Token(caller UID)": re.compile(
            r"\b(" + "|".join(sorted(POLICY.result_permissions)) + r")\s*\([^;)]*("
            + "|".join(sorted(POLICY.caller_uid_calls)) + r")"),
        "AUTH-03 identity-domain: any result_permission call": re.compile(
            calls(POLICY.result_permissions)),
        "DATA-01 position-underflow: RewindRead(...)": re.compile(r"\bRewindRead\s*\("),
        # `[^)]*` cannot cross the `)` of a nested call, so the first version of
        # this pattern scored `RewindRead(data.GetDataSize() - X)` -- the shape the
        # rule actually keys on -- as absent. Scan to the end of the statement
        # instead: this over-approximates, and the hits are read one by one.
        "DATA-01 position-underflow: RewindRead(<minus in args>)": re.compile(
            r"\bRewindRead\s*\([^;]{0,300}-"),
        "DATA-01 copy-range: copy_calls": re.compile(calls(POLICY.copy_calls)),
        # The rule needs the length argument to come out of the request; a copy
        # whose length is a local string length is not its shape.
        "DATA-01 copy-range: copy call with a parcel read in its args": re.compile(
            r"\b(" + "|".join(sorted(POLICY.copy_calls)) + r")\s*\([^;]{0,300}\bRead[A-Za-z]*\s*\("),
        "AUTH-03 object-owner: owner_calls": re.compile(calls(POLICY.owner_calls)),
    }


def is_measurement(report):
    """A rejected run writes a zero-count report too; see the lane delivery record."""
    return not report.get("shard_errors") and "/" in (report.get("repository") or "")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-root", action="append", required=True)
    parser.add_argument("--corpus-root", action="append", required=True)
    parser.add_argument("--top", type=int, default=6)
    parser.add_argument("--detail", default=None,
                        help="print every hit whose label contains this text, "
                             "as component relative-path:line")
    args = parser.parse_args()

    counts = collections.defaultdict(collections.Counter)
    examples = collections.defaultdict(dict)
    sites = collections.defaultdict(list)
    fired = collections.Counter()
    components = 0

    seen = set()
    reports = []
    for root in args.audit_root:
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name, "report.json")
            if not os.path.exists(path):
                continue
            if name in seen:
                print("  duplicate report for %s ignored" % name, file=sys.stderr)
                continue
            seen.add(name)
            reports.append((name, path))
    for name, path in reports:
        report = json.load(open(path))
        if not is_measurement(report):
            continue
        components += 1
        fired.update(c.get("rule_id") for c in (report.get("candidates") or []))

        repo_dir = next((os.path.join(r, name) for r in args.corpus_root
                         if os.path.isdir(os.path.join(r, name))), None)
        if repo_dir is None:
            print("  no corpus for %s, skipped" % name, file=sys.stderr)
            continue
        paths = []
        for shard in ((report.get("scope") or {}).get("shards") or []):
            paths.extend(shard.get("paths") or [])

        for rel in paths:
            try:
                text = open(os.path.join(repo_dir, rel), encoding="utf-8",
                            errors="replace").read()
            except OSError:
                continue
            for label, pattern in shapes().items():
                hits = pattern.findall(text)
                if hits:
                    counts[label][name] += len(hits)
                    examples[label].setdefault(name, rel)
                    if args.detail and args.detail in label:
                        for match in pattern.finditer(text):
                            sites[label].append("%s %s:%d" % (
                                name, rel, text.count("\n", 0, match.start()) + 1))

    print("components measured: %d" % components)
    for label in shapes():
        total = sum(counts[label].values())
        print("\n%s\n  total=%d  in %d components" % (label, total, len(counts[label])))
        for comp, n in counts[label].most_common(args.top):
            print("     %-42s %4d   e.g. %s" % (comp, n, examples[label][comp]))

    if args.detail:
        for label in shapes():
            if args.detail in label:
                print("\n%s -- every hit (%d)" % (label, len(sites[label])))
                for site in sorted(sites[label]):
                    print("   ", site)

    print("\n\ncandidates actually raised, for contrast:")
    for rule, n in fired.most_common():
        print("  %-34s %d" % (rule, n))


if __name__ == "__main__":
    main()
