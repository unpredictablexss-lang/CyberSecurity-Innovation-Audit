"""Classify what every permission-predicate call is handed, over the whole corpus.

Three AUTH-03 rules fire on the *argument* a permission predicate receives, not on
the predicate itself (`analysis.py`):

  ipc.auth.identity-domain   a `result_permissions` call handed a caller UID
  ipc.auth.service-identity  a permission call whose subject resolves to `self`
                             (the caller-calls read as `self` once identity was reset)
  ipc.auth.request-identity  a permission call handed a request-derived value

So a count of the predicates over-states the shape unless the arguments are split.
This does that split per call and per argument, following the one step a text
method can follow reliably: a bare identifier assigned, in the same file, from a
call of the relevant class. Anything travelling through a container, a member or a
function is reported as unresolved, not guessed at. Read-only.

Usage:
  python permission_arg_classes.py --audit-root <dir> --corpus-root <root> [...]
"""
import argparse
import collections
import json
import os
import re

PREDICATE = re.compile(
    r"\b(VerifyAccessToken|VerifyNativeToken|CheckPermission|VerifyPermission"
    r"|CheckCallerPermission)\s*\(")
SOURCE = re.compile(r"\.(?:cpp|cc|cxx|h|hpp)$")

RESULT_PERMISSIONS = ("VerifyAccessToken", "VerifyNativeToken")
BOOLEAN_PERMISSIONS = ("CheckPermission", "VerifyPermission", "CheckCallerPermission")

# The classes the interpreter distinguishes, keyed on the policy's own names.
CLASSES = (
    ("caller_uid", r"(?:IPCSkeleton::)?GetCallingU?ID"),
    ("caller_token", r"(?:IPCSkeleton::)?(?:GetCallingTokenID|GetCallingFullTokenID"
                     r"|GetFirstTokenID|GetFirstCallerTokenID)"),
    ("self", r"\b(?:getuid|geteuid|GetSelfTokenID|GetSelfTokenId)\s*\("),
    ("request", r"\bRead[A-Za-z]*\s*\("),
)
CLASS_PATTERNS = [(name, re.compile(pattern)) for name, pattern in CLASSES]
RESET = re.compile(r"\bResetCallingIdentity\s*\(")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CHOMP = re.compile(r"^\s*(?:static_cast\s*<[^>]*>|\([^()]*\))\s*")
PERMISSION_LITERAL = re.compile(r"\"[^\"]*PERMISSION[^\"]*\"|\"ohos\.[^\"]*\"")


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


def classify(text, argument):
    """The identity class of one argument, resolving one local-assignment hop."""
    body = CHOMP.sub("", argument).strip()
    for name, pattern in CLASS_PATTERNS:
        if pattern.search(body):
            return name, "direct"
    if PERMISSION_LITERAL.search(body):
        return "permission-literal", "direct"
    if IDENT.match(body):
        assignment = re.search(r"\b" + re.escape(body) + r"\s*=(?!=)([^;]{0,300});", text)
        if assignment:
            for name, pattern in CLASS_PATTERNS:
                if pattern.search(assignment.group(1)):
                    return name, "via local " + body
        return "identifier", "unresolved"
    if "(" in body:
        return "call/expression", "unresolved"
    return "other", "unresolved"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--corpus-root", action="append", required=True)
    parser.add_argument("--list-sites", action="store_true",
                        help="print every argument classified as caller_uid, self or request")
    args = parser.parse_args()

    per_class = collections.Counter()
    per_predicate = collections.defaultdict(collections.Counter)
    per_component = collections.defaultdict(collections.Counter)
    sites = []
    shape = collections.Counter()
    sites_with_reset = 0
    files_with_predicate = 0
    files_with_reset = []

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
        paths = []
        for shard in ((report.get("scope") or {}).get("shards") or []):
            paths.extend(shard.get("paths") or [])

        for rel in paths:
            if not SOURCE.search(rel):
                continue
            try:
                text = open(os.path.join(repo_dir, rel), encoding="utf-8",
                            errors="replace").read()
            except OSError:
                continue
            if not PREDICATE.search(text):
                continue
            files_with_predicate += 1
            reset = bool(RESET.search(text))
            if reset:
                files_with_reset.append((name, rel))
            for match in PREDICATE.finditer(text):
                predicate = match.group(1)
                arguments, _ = call_arguments(text, match.end() - 1)
                line = text.count("\n", 0, match.start()) + 1
                if arguments is None:
                    per_predicate[predicate]["unterminated"] += 1
                    continue
                for position, argument in enumerate(arguments):
                    kind, how = classify(text, argument)
                    per_class[kind] += 1
                    per_predicate[predicate][kind] += 1
                    per_component[name][kind] += 1
                    if kind == "caller_uid" and predicate in RESULT_PERMISSIONS:
                        shape["identity-domain"] += 1
                    elif kind == "request":
                        shape["request-identity"] += 1
                    elif kind == "self":
                        shape["service-identity (self argument)"] += 1
                        if reset:
                            shape["  ... in a file that also resets identity"] += 1
                            sites_with_reset += 1
                    if kind in ("caller_uid", "caller_token", "self", "request"):
                        sites.append((kind, name, rel, line, predicate, position,
                                      how, " ".join(argument.split())[:70],
                                      "reset" if reset else ""))

    print("permission-predicate arguments across the audited components")
    print("  files with at least one predicate: %d" % files_with_predicate)
    print("\n== every argument, by identity class ==")
    for kind, count in per_class.most_common():
        print("  %-22s %d" % (kind, count))

    print("\n== by predicate and class ==")
    for predicate in sorted(per_predicate):
        parts = ", ".join("%s=%d" % item for item in per_predicate[predicate].most_common())
        print("  %-22s %s" % (predicate, parts))

    print("\n== the three rule shapes ==")
    for key in ("identity-domain", "request-identity", "service-identity (self argument)",
                "  ... in a file that also resets identity"):
        print("  %-46s %d" % (key, shape[key]))
    print("  files containing ResetCallingIdentity             : %d"
          % len(files_with_reset))
    for record in files_with_reset[:15]:
        print("    ", record)

    print("\n== classified arguments, by component ==")
    for name in sorted(per_component):
        row = per_component[name]
        interesting = {k: v for k, v in row.items()
                       if k in ("caller_uid", "caller_token", "self", "request")}
        if interesting:
            print("  %-42s %s" % (name, ", ".join(
                "%s=%d" % item for item in sorted(interesting.items()))))

    print("\n== sites ==")
    for record in sites if args.list_sites else sites[:40]:
        print("   %-12s %-38s %s:%d  %s(arg %d)  [%s]  %s" % (
            record[0], record[1], record[2], record[3], record[4], record[5],
            record[6], record[7]))
    print("  total classified sites: %d" % len(sites))


if __name__ == "__main__":
    main()
