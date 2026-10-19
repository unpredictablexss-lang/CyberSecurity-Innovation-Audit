"""The AUTH-01 precision screen, applied unchanged to every rule that emits.

交付项 10 §6 screened one rule -- `ipc.relay.descriptor-boundary` -- with modes
read off the report's own fields, and had to read the pinned blobs separately
because it only used `symbol` and the `path=` list inside `message`. Two facts
make the same treatment available to the other rules:

  * every candidate of every rule carries `path=((line, 'cond'), ...)` in its
    `message`, in one identical format -- so the modes that need no rule-specific
    grammar apply uniformly; and
  * every candidate carries a structured `excerpt` with a `blob_oid`, i.e. the
    pinned source window at the site, so a claim can be checked against the
    source the report was produced from without any second lookup.

Modes, all decided from the report's own fields:

  empty_path      the message claims a path and records `path=()`
  line_is_guard   the flagged line ITSELF is an enforcement call -- read from the
                  candidate's own pinned `excerpt`, so this needs no symbol table
  enforced_path   the recorded path contains a condition that NAMES an
                  enforcement call and held -- i.e. the boundary the rule says is
                  missing is recorded as having been enforced on that path
  bound_recorded  the recorded path contains the very comparison the message says
                  is missing, on the length the message names

`empty_path` is deliberately NOT a defect count. Reading all eleven of its rows
showed ten where `path=()` is accurate -- six straight-line handlers with no branch
to record, and four where the guard is the function's first branch -- and exactly one
where it is not: `pasteboard_disposable_observer_stub.cpp:48` has three guards above
it, written as the macro `PASTEBOARD_CHECK_AND_RETURN_RET_LOGE`, and records `path=()`.
(Of the 591 recorded path conditions across all 179 candidates, none is a macro-shaped
identifier, while a literal `if (descriptor != token)` elsewhere IS recorded -- so
macro-mediated guards going unrecorded is consistent with the evidence, not proven by
it.) It is kept as a mode because it is what routes a row to a read, and because
presenting it as a defect would have inflated the flagged fraction by more than half.

A mode match is not a verdict either. Each match is shown against its own pinned
`excerpt`, and the excerpt's `blob_oid` is checked against `git rev-parse
<commit>:<path>` so "read the pinned source" is verified rather than assumed.
Nothing is deleted, withheld or re-scored; the candidates stay candidates.

Usage: python3 -I rule_precision_screen.py [--json OUT]
"""
import argparse
import collections
import json
import os
import re
import subprocess

AUDIT_ROOTS = ["/home/audit/wtmp/ipc-audit", "/home/audit/wtmp/ipc-audit-bline"]
CORPORA = ["/home/audit/openharmony-audit/perf-corpus", "/home/audit/corpus-ipc-widen",
           "/home/audit/corpus-ipc-shape", "/home/audit/openharmony-audit/gitcode-corpus",
           "/home/audit/corpus-ipc-bline"]
DEST = ("/home/audit/ohscanner/worktrees/parallel-ipc-20261017/research/evidence/"
        "interface/ipc/rule_precision_screen_20261017")

# Copied verbatim from auth01_precision_probe.py so the two screens agree on what
# counts as an enforcement call rather than drifting apart.
ENFORCE = re.compile(r"(Check|Enforce|Verify|Validate)[A-Za-z]*(Descriptor|InterfaceToken|Token|Permission)")
EMPTY = re.compile(r"path=\(\)")
PATHITEM = re.compile(r"\((\d+), '(.*?)'\)")
# A recorded condition that names a bound comparison. The DATA-01 candidate's
# message says the length lacks nonnegative/destination bounds while its own path
# records `cfgLen <= 0 => False` and `cfgLen > 1024 => False`. The claim has to be
# a missing-bound claim AND the comparison has to be on the length the claim names:
# an earlier version searched the whole message, and "boundary" contains "bound",
# so two AUTH-01 rows whose path held `uid < 0 => False` matched a mode about copy
# lengths. Keying on the named operand removes that class of false match.
BOUND_CLAIM = re.compile(r"copy length (\w+) lacks .*bound")
BOUND_CMP = re.compile(r"(<=|>=|<|>)")
# For the shape census: what does the recorder put in `path=`? A macro-mediated guard
# is the one shape that matters here -- see the `empty_path` note in the docstring.
MACRO = re.compile(r"^[A-Z][A-Z0-9_]{3,}$")
CALL = re.compile(r"^[A-Za-z_][\w:]*\s*\(")


def cond_shapes(reps):
    """Census of every recorded path condition, by shape. No judgment, just counts."""
    buckets, examples, total, empty = collections.Counter(), {}, 0, 0
    for _name, rep in sorted(reps.items()):
        for c in (rep.get("candidates") or []):
            items = PATHITEM.findall(c.get("message", ""))
            if not items:
                empty += 1
            for _line, cond in items:
                total += 1
                kind = "macro" if MACRO.match(cond) else ("call" if CALL.match(cond) else "other")
                buckets[kind] += 1
                examples.setdefault(kind, [])
                if len(examples[kind]) < 5:
                    examples[kind].append(cond)
    return {"path_conditions": total, "candidates_with_empty_path": empty,
            "buckets": dict(buckets), "examples": examples}


def components():
    seen = {}
    for root in AUDIT_ROOTS:
        for name in sorted(os.listdir(root)):
            rp = os.path.join(root, name, "report.json")
            if os.path.isfile(rp):
                seen[name] = json.load(open(rp))
    return seen


def repo_for(name, commit):
    """The clone that actually holds this report's commit, by object presence."""
    for c in CORPORA:
        p = os.path.join(c, name)
        if os.path.isdir(p) and not subprocess.run(
                ["git", "-C", p, "cat-file", "-e", commit + "^{commit}"],
                capture_output=True).returncode:
            return p
    return None


def screen():
    reps = components()
    rows, blob_checked, blob_bad, blob_none = [], 0, 0, 0
    per_rule = collections.defaultdict(collections.Counter)

    for name, rep in sorted(reps.items()):
        commit = rep["commit"]
        repo = repo_for(name, commit)
        for c in (rep.get("candidates") or []):
            msg = c.get("message", "")
            items = PATHITEM.findall(msg)
            ex = c.get("excerpt") or {}
            own = [l["text"] for l in (ex.get("lines") or [])
                   if l.get("candidate") or l.get("number") == c["line"]]
            modes = []
            if EMPTY.search(msg):
                modes.append("empty_path")
            if any(ENFORCE.search(t) for t in own):
                modes.append("line_is_guard")
            for line, cond in items:
                if ENFORCE.search(cond):
                    modes.append("enforced_path")
                    break
            claim = BOUND_CLAIM.search(msg)
            if claim and any(BOUND_CMP.search(cond) and claim.group(1) in cond
                             for _line, cond in items):
                modes.append("bound_recorded")
            rec = {"component": name, "rule_id": c["rule_id"], "file": c["file"],
                   "line": c["line"], "symbol": c.get("symbol"), "modes": modes,
                   "path_items": [[int(l), x] for l, x in items]}
            per_rule[c["rule_id"]][tuple(modes) or ("-",)] += 1

            # Verify the excerpt really is the pinned blob, not the worktree.
            oid = ex.get("blob_oid")
            if not oid or repo is None:
                blob_none += 1
            else:
                got = subprocess.run(["git", "-C", repo, "rev-parse",
                                      "%s:%s" % (commit, c["file"])],
                                     capture_output=True, text=True).stdout.strip()
                blob_checked += 1
                if got != oid:
                    blob_bad += 1
                    rec["blob_mismatch"] = {"report": oid, "pinned": got}
            if modes:
                rec["excerpt"] = [l["text"] for l in (ex.get("lines") or [])]
                rec["excerpt_blob_oid"] = oid
                rows.append(rec)

    return {"rows": rows, "per_rule": {k: {"/".join(m): n for m, n in v.items()}
                                       for k, v in per_rule.items()},
            "blob_checked": blob_checked, "blob_mismatch": blob_bad,
            "blob_unchecked": blob_none, "cond_shapes": cond_shapes(reps)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", help="write the full result here")
    a = ap.parse_args()
    r = screen()
    total = sum(sum(v.values()) for v in r["per_rule"].values())
    print("candidates screened:", total)
    print("excerpt blob_oid checked against the pinned commit:path: %d  "
          "mismatches: %d  unchecked: %d"
          % (r["blob_checked"], r["blob_mismatch"], r["blob_unchecked"]))
    cs = r["cond_shapes"]
    print("recorded path conditions: %d (%d candidates record path=()) -- shapes: %s"
          % (cs["path_conditions"], cs["candidates_with_empty_path"],
             "  ".join("%s=%d" % kv for kv in sorted(cs["buckets"].items()))))
    print()
    print("%-32s %-5s %s" % ("rule_id", "n", "mode -> count"))
    for rid, mv in sorted(r["per_rule"].items(), key=lambda kv: -sum(kv[1].values())):
        print("%-32s %-5d %s" % (rid, sum(mv.values()),
                                 "  ".join("%s=%d" % (m, n) for m, n in sorted(mv.items()))))
    print("\nflagged rows:", len(r["rows"]))
    for row in r["rows"]:
        print("  %-30s %-28s %s:%s  %s" % (row["rule_id"], row["symbol"],
                                           row["file"].split("/")[-1], row["line"],
                                           ",".join(row["modes"])))
    if a.json:
        os.makedirs(os.path.dirname(a.json), exist_ok=True)
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(r, fh, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
