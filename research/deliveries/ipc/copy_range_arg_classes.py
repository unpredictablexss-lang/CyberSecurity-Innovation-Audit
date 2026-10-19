"""Classify the length argument of every copy call the 18 components contain.

`ipc.parcel.copy-range` fires only when the copy length comes out of the request
(`args[index].kind == "request"` in `analysis.py`) and lacks a matched bound. A
text count of `copy_calls` therefore over-states the shape by however many copies
take their length from a local string, a constant or a struct field. This splits
the 665 matches by what the length argument actually is, and follows the one case
this text method can follow: a bare identifier assigned from a parcel read in the
same file.

A regex cannot see a length that travels through a container or a function, so the
"unresolved" bucket is reported rather than guessed at. Read-only.

Usage:
  python copy_range_arg_classes.py --audit-root <dir> --corpus-root <root> ...
"""
import argparse
import collections
import json
import os
import re

CALL = re.compile(r"\b(memcpy|memmove|memcpy_s|memmove_s|ReadRawData|ReadBuffer)\s*\(")
WIDE = ("memcpy_s", "memmove_s")
READ_ASSIGN = re.compile(r"\bRead[A-Za-z]*\s*\(")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NUMBER = re.compile(r"^(0[xX][0-9a-fA-F]+|[0-9]+[uUlL]*)$")
SIZEOF = re.compile(r"^sizeof\s*\(")
CHOMP = re.compile(r"^\s*(?:static_cast\s*<[^>]*>|\([^()]*\))\s*")


def call_arguments(text, opening):
    """The top-level comma-separated arguments of the call whose `(` is at `opening`."""
    depth, index, args, current = 0, opening, [], []
    while index < len(text):
        char = text[index]
        if char == "(":
            depth += 1
            if depth == 1:
                index += 1
                continue
        elif char == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(current))
                return args, index
        if depth >= 1:
            if char == "," and depth == 1:
                args.append("".join(current))
                current = []
            else:
                current.append(char)
        index += 1
    return None, index


def classify(argument):
    text = CHOMP.sub("", argument).strip()
    if not text:
        return "empty"
    if NUMBER.match(text):
        return "number"
    if SIZEOF.match(text):
        return "sizeof"
    if IDENT.match(text):
        return "identifier"
    if "(" in text:
        return "call/expression"
    return "expression"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--corpus-root", action="append", required=True)
    parser.add_argument("--list-identifiers", action="store_true",
                        help="print every identifier-length copy whose file also "
                             "assigns that identifier from a Read*() call")
    args = parser.parse_args()

    classes = collections.Counter()
    by_component = collections.defaultdict(collections.Counter)
    by_call = collections.defaultdict(collections.Counter)
    raw_arity = collections.defaultdict(collections.Counter)
    raw_first = collections.defaultdict(collections.Counter)
    raw_derived = []
    unresolved, resolved = [], []
    components = 0

    for name in sorted(os.listdir(args.audit_root)):
        report_path = os.path.join(args.audit_root, name, "report.json")
        if not os.path.exists(report_path):
            continue
        report = json.load(open(report_path))
        if report.get("shard_errors") or "/" not in (report.get("repository") or ""):
            continue
        repo_dir = next((os.path.join(root, name) for root in args.corpus_root
                         if os.path.isdir(os.path.join(root, name))), None)
        if repo_dir is None:
            continue
        components += 1
        paths = []
        for shard in ((report.get("scope") or {}).get("shards") or []):
            paths.extend(shard.get("paths") or [])

        for rel in paths:
            try:
                text = open(os.path.join(repo_dir, rel), encoding="utf-8",
                            errors="replace").read()
            except OSError:
                continue
            for match in CALL.finditer(text):
                name_of_call = match.group(1)
                arguments, _ = call_arguments(text, match.end() - 1)
                if arguments is None:
                    classes["unterminated"] += 1
                    continue
                if name_of_call in ("ReadRawData", "ReadBuffer"):
                    raw_arity[name_of_call][len(arguments)] += 1
                    if arguments:
                        first = classify(arguments[0])
                        raw_first[name_of_call][first] += 1
                        if first == "identifier":
                            identifier = CHOMP.sub("", arguments[0]).strip()
                            assignment = re.search(
                                r"\b" + re.escape(identifier) + r"\s*=(?!=)([^;]{0,300});",
                                text)
                            if assignment and READ_ASSIGN.search(assignment.group(1)):
                                raw_derived.append((
                                    name, rel, text.count("\n", 0, match.start()) + 1,
                                    name_of_call, identifier, arguments[0].strip()))
                index = 3 if name_of_call in WIDE else 2
                if len(arguments) <= index:
                    classes["too few arguments"] += 1
                    by_call[name_of_call]["too few arguments"] += 1
                    continue
                length = classify(arguments[index])
                classes[length] += 1
                by_component[name][length] += 1
                by_call[name_of_call][length] += 1
                if length == "identifier":
                    identifier = CHOMP.sub("", arguments[index]).strip()
                    assignment = re.search(
                        r"\b" + re.escape(identifier) + r"\s*=(?!=)([^;]{0,300});", text)
                    derived = bool(assignment) and bool(READ_ASSIGN.search(assignment.group(1)))
                    line = text.count("\n", 0, match.start()) + 1
                    record = (name, rel, line, name_of_call, identifier)
                    (resolved if derived else unresolved).append(record)

    print("length argument of every copy call, %d components" % components)
    for kind, count in classes.most_common():
        print("  %-22s %d" % (kind, count))
    print("\nwhere the length actually sits in ReadRawData/ReadBuffer:")
    for call in ("ReadRawData", "ReadBuffer"):
        parts = ", ".join("%s=%d" % item for item in raw_arity[call].most_common())
        print("  %-12s arity: %s" % (call, parts or "none"))
        parts = ", ".join("%s=%d" % item for item in raw_first[call].most_common())
        print("  %-12s first argument: %s" % ("", parts or "none"))
    print("  first arguments that reach a parcel read in the same file: %d"
          % len(raw_derived))
    for record in raw_derived:
        print("   ", record)

    print("\nby call:")
    for call in sorted(by_call):
        parts = ", ".join("%s=%d" % item for item in by_call[call].most_common())
        print("  %-12s %s" % (call, parts))

    print("\nper component (identifier lengths only):")
    for name in sorted(by_component):
        if by_component[name]["identifier"]:
            print("  %-42s %d" % (name, by_component[name]["identifier"]))

    print("\nidentifier lengths traceable to a parcel read in the same file: %d"
          % len(resolved))
    for record in resolved if args.list_identifiers else resolved[:20]:
        print("   ", record)
    print("identifier lengths not traceable by this text method: %d"
          % len(unresolved))
    if args.list_identifiers:
        for record in unresolved:
            print("   ", record)


if __name__ == "__main__":
    main()
