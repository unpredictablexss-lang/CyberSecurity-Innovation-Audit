r"""Did the walk reach a caller-class sensitive call, and if not, where were the roots?

Read-only. Three independent readings of the same corpus are put side by side:

  text    every occurrence of a policy `caller_class_sensitive_calls` name in the
          files the component actually audited, split into declaration and call
  walk    how many such calls the interpreter's own wrapper evaluated
          (`probe_site`, the same instrument that answered the AUTH-03 question)
  roots   which files the walk's entry roots lived in and how much it traversed
          (`root_probe_site`, a second instrument for the "did the walk run at
          all" question that an empty record cannot answer on its own)

A call site is reported as *in a root file* when its file is one of the files the
entry roots were found in. That is the reachability question these rules turn on
given a same-file walk; it is not a call-graph proof and is not presented as one.

Usage (paths are the caller's; nothing is defaulted):

  python research/deliveries/ipc/caller_class_walk.py \
      --audit-root <dir with <component>/report.json> \
      --walk-root  <dir with <component>/predicates.jsonl> \
      --roots-root <dir with <component>/roots.json> \
      --corpus-root <repo root>        (repeatable) \
      --out <path to write the JSON to>
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import re

NAMES = ("GetReqPermissions", "StartUsingPermissionCallback",
         "RemovePermissionUsedRecords", "GetPermissionUsedRecordsAsync",
         "IsAllowedUsingPermission", "SetMutePolicy")
NAME_RE = re.compile(r"\b(" + "|".join(NAMES) + r")\b")
KEYWORDS = {"return", "if", "while", "for", "switch", "sizeof", "new",
            "delete", "throw", "case", "and", "or", "not"}


def classify(line, start):
    """Whether the occurrence at line[start:] declares the name or calls it."""
    stripped = line.lstrip()
    if stripped.startswith(("//", "*", "/*")):
        return "comment"
    if 0 <= line.find("//") < start:
        return "comment"
    prefix = line[:start].strip()
    if not prefix:
        return "call"
    words = prefix.split()
    tail = words[-1]
    if tail in KEYWORDS or tail.endswith((".", "->", "(", ",", "=", "::")):
        return "call"
    before = words[-2] if len(words) >= 2 else ""
    if "(" not in prefix and re.match(r"^[\w:<>,*&\s]+$", prefix):
        if before.endswith("::") or re.match(r"^[A-Za-z_]\w*$", before):
            return "decl"
    return "call"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def scoped_paths(report_path):
    report = json.load(open(report_path))
    paths = []
    for shard in (report.get("scope") or {}).get("shards") or []:
        paths.extend(shard.get("paths") or [])
    return report.get("repository", ""), report.get("commit", ""), paths


def find_repo(corpus_roots, component):
    for root in corpus_roots:
        candidate = os.path.join(root, component)
        if os.path.isdir(candidate):
            return candidate
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--walk-root", required=True)
    parser.add_argument("--roots-root", required=True)
    parser.add_argument("--corpus-root", action="append", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    walked = collections.Counter()
    per_component = {}
    for path in sorted(glob.glob(os.path.join(args.walk_root, "*", "predicates.jsonl"))):
        component = os.path.basename(os.path.dirname(path))
        counter = collections.Counter()
        for line in open(path):
            if not line.strip():
                continue
            row = json.loads(line)
            bucket = row.get("bucket", "identity")
            counter[bucket] += 1
            walked[bucket] += 1
            if bucket == "caller_class":
                counter["caller_class_without_a_class"] += (
                    0 if row.get("caller_class_set") else 1)
        per_component[component] = dict(counter)

    components = {}
    for report_path in sorted(glob.glob(os.path.join(args.audit_root, "*", "report.json"))):
        component = os.path.basename(os.path.dirname(report_path))
        repository, commit, paths = scoped_paths(report_path)
        repo = find_repo(args.corpus_root, component)
        if repo is None:
            continue
        roots_path = os.path.join(args.roots_root, component, "roots.json")
        roots = json.load(open(roots_path)) if os.path.isfile(roots_path) else None
        root_files = set(roots["distinct_root_files"]) if roots else set()

        split = collections.Counter()
        in_a_root_file = []
        for relative in paths:
            path = os.path.join(repo, relative)
            if not os.path.isfile(path):
                continue
            for index, line in enumerate(open(path, errors="replace").read().splitlines()):
                for match in NAME_RE.finditer(line):
                    kind = classify(line, match.start())
                    split[kind] += 1
                    if kind == "call" and relative in root_files:
                        in_a_root_file.append((relative, index + 1, match.group(1)))
        components[component] = {
            "repository": repository,
            "pinned_commit": commit,
            "scoped_files": len(paths),
            "occurrences": dict(split),
            # Only meaningful where the root probe ran: with no root set, this is
            # zero by construction rather than by measurement.
            "root_probe_run": bool(roots),
            "calls_in_a_root_file": in_a_root_file,
            "walk": per_component.get(component, {}),
        }
        if roots:
            components[component]["entry_roots"] = {
                "n_distinct_roots": roots["n_distinct_roots"],
                "n_distinct_root_files": roots["n_distinct_root_files"],
                "n_distinct_functions": roots["n_distinct_functions"],
                "value_calls": roots["value_calls"],
                "call_expressions": roots["call_expressions"],
                "sample": roots["distinct_roots"][:6],
            }

    document = {
        "what": "Whether the walk ever reached a caller_class_sensitive_call, read three "
                "ways over the components that were actually audited.",
        "instrument": {
            "walk": "research/deliveries/ipc/probe_site/sitecustomize.py",
            "walk_sha256": sha256("research/deliveries/ipc/probe_site/sitecustomize.py"),
            "roots": "research/deliveries/ipc/root_probe_site/sitecustomize.py",
            "roots_sha256": sha256("research/deliveries/ipc/root_probe_site/sitecustomize.py"),
        },
        "names": list(NAMES),
        "walked_by_bucket": dict(walked),
        "components_with_a_root_probe_run": sorted(
            os.path.basename(os.path.dirname(p))
            for p in glob.glob(os.path.join(args.roots_root, "*", "roots.json"))),
        "components": components,
        "how_to_read": "`walked_by_bucket.caller_class` is the number of caller-class "
                       "sensitive calls the interpreter itself evaluated. A missing key "
                       "means zero, and it is zero for every component, so the rule's zero "
                       "candidates are not a conjunction that failed -- they are a call the "
                       "walk never made. The `entry_roots` block is what tells the two "
                       "readings of an empty record apart: the walk ran, and it ran where "
                       "it did. `calls_in_a_root_file` is only a measurement on components "
                       "with `root_probe_run: true`; elsewhere the root set is empty and the "
                       "figure is zero by construction, not by measurement.",
    }
    probed = [c for c in components.values() if c["root_probe_run"]]
    document["root_probe_coverage"] = {
        "components_with_a_root_probe_run": len(probed),
        "components_without": len(components) - len(probed),
        "text_call_sites_in_the_probed_components":
            sum(c["occurrences"].get("call", 0) for c in probed),
        "of_those_sitting_in_a_root_file":
            sum(len(c["calls_in_a_root_file"]) for c in probed),
    }
    with open(args.out, "w") as handle:
        json.dump(document, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("wrote", args.out)
    print("walked_by_bucket", json.dumps(dict(walked), sort_keys=True))
    total_calls = sum(c["occurrences"].get("call", 0) for c in components.values())
    print("text call sites over the same components:", total_calls)
    print("call sites sitting in a root file:",
          json.dumps(document["root_probe_coverage"], sort_keys=True))


if __name__ == "__main__":
    main()
