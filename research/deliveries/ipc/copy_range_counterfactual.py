"""Why `ipc.parcel.copy-range` flagged a correct copy, and what removing the
cause does to the rest of the corpus.

`communication_wifi`'s `wifi_p2p_callback_stub.cpp:385` is

    int cfgLen = data.ReadInt32();
    if (cfgLen <= 0)       { ...; return; }        // lower bound
    if (cfgLen > MAX_LEN)  { ...; return; }        // upper bound, MAX_LEN == 1024
    char *cfgData = new (std::nothrow) char[cfgLen];
    memcpy_s(cfgData, cfgLen, dataBuffer, cfgLen);

which is a correctly bounded copy, yet it emitted. Reading `analysis.py` locates
two independent reasons the *model* did not record what the code establishes:

  1. For the `memcpy_s` family the destination capacity is taken from `args[1]`,
     the call's own `destMax` (`analysis.py:1066`). That half is right, but the
     destination's real capacity comes from `new T[n]`, and `capacities` never
     learns it: a `new_expression` walks its children and returns the shared
     `UNKNOWN` sentinel (`analysis.py:1444-1449`), so the allocation loses the
     identity a capacity table would have to be keyed by.
  2. `if (cfgLen <= 0) { return; }` is the code base's idiom for "reject
     non-positive lengths", but the predicate table at `analysis.py:1421` types
     `x <= 0` as an *upper* bound and `refine` (`analysis.py:1528-1530`) records
     only the branch where `truth == when`. Falling through therefore yields no
     lower bound, so `state.lower` stays empty and the rule's own first test --
     `length not in state.lower` -- is met. The neighbouring rows of the same
     table (`analysis.py:1419-1424`) do produce lower bounds, for `x < 0` and for
     `x >= 0`; only the `<=` spelling is lost, and `<=` is the spelling this code
     base uses most.

The counterfactual applies one narrow edit per reason to a *copy* of the tree and
re-runs the whole corpus, because the question is not whether one rule goes quiet
at one site -- it is whether it goes quiet **only** where it was wrong. A removal
is expected; an *addition* would mean the edits credited a copy the pinned rule
was right to flag.

Run with --build to (re)create the copy, then --run to audit the corpus with it,
then --report to diff the two runs. Nothing here writes to the pinned tree.
"""
import argparse
import collections
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

PINNED = Path("/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b")
PYTHON = PINNED / ".venv/bin/python"
COPY = Path("/home/audit/wtmp/detector-cf")
AUDIT_ROOTS = [Path("/home/audit/wtmp/ipc-audit"), Path("/home/audit/wtmp/ipc-audit-bline")]
CORPORA = ["/home/audit/openharmony-audit/perf-corpus", "/home/audit/corpus-ipc-widen",
           "/home/audit/corpus-ipc-shape", "/home/audit/openharmony-audit/gitcode-corpus",
           "/home/audit/corpus-ipc-bline"]
OUT = Path("/home/audit/wtmp/cf-out-all")
DEST = Path("/home/audit/ohscanner/worktrees/parallel-ipc-20261017/research/evidence/"
            "interface/ipc/copy_range_counterfactual_20261017")

# The one file the four edits touch. Its hash is the binding between `patch.diff`
# and the run that produced `counterfactual.json`: without it, a copy rebuilt from
# a cosmetically different edit set would leave outputs whose provenance cannot be
# checked. A first run of this script was lost exactly that way -- the tree on disk
# and the recorded patch differed (in comment wording only), so the outputs and the
# patch could not be shown to come from one tree, and the run was redone.
TARGET = "src/ohscanner/detectors/interface/analysis.py"
SHA_FILE = "patched_analysis.sha256"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

# The four edits, each tied to one of the two reasons above. Anchored on exact
# text so an upstream change makes this fail loudly instead of misapplying.
EDITS = [
    ("new-key",
     """        if node.type == "new_expression":
            typ=fn.text(node.child_by_field_name("type"))
            if typ=="HCameraDevice":
                self.action(fn,node,state,"CreateCameraDevice",[])
            for child in node.named_children:self.value(fn,child,state,depth)
            return UNKNOWN
""",
     """        if node.type == "new_expression":
            typ=fn.text(node.child_by_field_name("type"))
            if typ=="HCameraDevice":
                self.action(fn,node,state,"CreateCameraDevice",[])
            for child in node.named_children:self.value(fn,child,state,depth)
            # Keep the expression as the value's identity: a later `dst` assigned
            # this expression then still names the allocation.
            return Value("constant",text)
"""),
    ("new-capacity",
     """                    if dec.type=="init_declarator":
                        d=dec.child_by_field_name("declarator")
                        ids=list(walk(d,"identifier")) if d else []
                        name=fn.text(ids[-1] if ids else d)
                        self.assign(s,name,self.value(fn,dec.child_by_field_name("value"),s,depth))
""",
     """                    if dec.type=="init_declarator":
                        d=dec.child_by_field_name("declarator")
                        ids=list(walk(d,"identifier")) if d else []
                        name=fn.text(ids[-1] if ids else d)
                        _v=dec.child_by_field_name("value")
                        _val=self.value(fn,_v,s,depth)
                        if _v is not None and _v.type=="new_expression":
                            # `new T[n]` -- the destination holds n elements, and
                            # the code that reads it back uses the same n.
                            import re as _re
                            _m=_re.search(r"\\[\\s*([^\\[\\]]+?)\\s*\\]\\s*$",fn.text(_v))
                            if _m:
                                self.capacities[_val.key]=_re.sub(r"\\s+","",_m.group(1))
                        self.assign(s,name,_val)
"""),
    ("exact-fit",
     """                cap = args[1].key if index == 3 else self.capacities.get(args[0].key)
                upper = any(key == length and (cap is not None and bound in (cap,"sizeof("+args[0].key+")"))
                            for key, bound in state.upper)
""",
     """                cap = args[1].key if index == 3 else self.capacities.get(args[0].key)
                # A `memcpy_s(dst, n, src, n)` whose destination was allocated with
                # capacity n matches its own destMax by construction -- met by
                # construction, not by a branch the walk would have had to record.
                exact_fit = (index == 3 and cap == length
                             and self.capacities.get(args[0].key) == length)
                upper = any(key == length and (cap is not None and bound in (cap,"sizeof("+args[0].key+")"))
                            for key, bound in state.upper)
                upper = upper or exact_fit
"""),
    ("le-zero-lower",
     """            if truth==when and accepted:
                attr={"auth":"auth","descriptor":"descriptor","owner":"owner","lower":"lower","upper":"upper","size_lower":"size_lower","caller_class":"caller_class","account":"service_account"}[kind]
                setattr(out,attr,getattr(out,attr)|{key})
""",
     """            if truth==when and accepted:
                attr={"auth":"auth","descriptor":"descriptor","owner":"owner","lower":"lower","upper":"upper","size_lower":"size_lower","caller_class":"caller_class","account":"service_account"}[kind]
                setattr(out,attr,getattr(out,attr)|{key})
            if when and not truth and accepted and kind=="upper" and key[1]=="0":
                # The walk records `x <= 0` as an upper bound on its true branch.
                # Falling through that branch -- what `if (x <= 0) { return; }`
                # does -- establishes the lower bound x > 0, which is the form
                # this code base uses most often and the model did not record.
                out.lower=out.lower|{key[0]}
"""),
]


def build():
    DEST.mkdir(parents=True, exist_ok=True)
    if COPY.exists():
        shutil.rmtree(COPY)
    shutil.copytree(PINNED / "src", COPY / "src")
    for pyc in COPY.rglob("__pycache__"):
        shutil.rmtree(pyc)
    path = COPY / "src/ohscanner/detectors/interface/analysis.py"
    text = path.read_text(encoding="utf-8")
    for label, old, new in EDITS:
        if text.count(old) != 1:
            raise SystemExit("edit %s: anchor matched %d times" % (label, text.count(old)))
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    (DEST / SHA_FILE).write_text(sha256(COPY / TARGET) + "\n")
    diff = subprocess.run(["diff", "-u", "-r", str(PINNED / "src"), str(COPY / "src")],
                          capture_output=True, text=True)
    (DEST / "patch.diff").write_text(diff.stdout)
    print("applied %d edits to a copy; the pinned tree is untouched" % len(EDITS))
    print("pinned %s  %s" % (sha256(PINNED / TARGET)[:16], "pinned tree"))
    print("patched %s  %s" % (sha256(COPY / TARGET)[:16], "the tree the run uses"))


def run():
    OUT.mkdir(parents=True, exist_ok=True)
    for root in AUDIT_ROOTS:
        for d in sorted(p for p in root.iterdir() if p.is_dir()):
            rp = d / "report.json"
            if not rp.is_file():
                continue
            rep = json.loads(rp.read_text())
            name = rep["repository"].split("/")[-1]
            if (OUT / name / "report.json").is_file():
                print("== %s exists" % name)
                continue
            # A component may sit in more than one corpus clone, and the baseline
            # report's commit only exists in the one it was read from. Pick by
            # object presence, not by directory order, or the run dies on
            # "Needed a single revision" and the component silently goes uncompared.
            repo = next(
                (Path(c) / name for c in CORPORA
                 if (Path(c) / name).is_dir()
                 and not subprocess.run(
                     ["git", "-C", str(Path(c) / name), "cat-file", "-e",
                      rep["commit"] + "^{commit}"],
                     capture_output=True).returncode),
                None)
            if repo is None:
                print("== %s NO CORPUS WITH %s" % (name, rep["commit"]))
                continue
            o = OUT / name
            o.mkdir(parents=True, exist_ok=True)
            with open(o / "stdout.log", "w") as log:
                subprocess.run(
                    [str(PYTHON), "-m", "src.ohscanner.detectors.interface.audit",
                     "--repo-dir", str(repo), "--repository", rep["repository"],
                     "--commit", rep["commit"], "--out-dir", str(o),
                     "--json-out", str(o / "report.json"), "--md-out", str(o / "report.md")],
                    cwd=str(COPY), stdout=log, stderr=subprocess.STDOUT)
            cf = json.loads((o / "report.json").read_text())
            n = collections.Counter(c["rule_id"] for c in (cf.get("candidates") or []))
            print("== %-34s %-4d %s" % (name, sum(n.values()),
                                        " ".join("%s=%d" % kv for kv in sorted(n.items()))))


def report():
    def key(c):
        return (c["file"], c["line"], c["rule_id"])

    # Refuse to attribute outputs to a tree they did not come from: if the copy on
    # disk no longer hashes to what build() recorded, the comparison below would be
    # reported against the wrong patch.
    recorded = (DEST / SHA_FILE).read_text().strip()
    current = sha256(COPY / TARGET)
    if recorded != current:
        raise SystemExit("the run tree does not match the recorded patch: "
                         "recorded %s, on disk %s -- rebuild and re-run" % (recorded, current))

    rows, tot_base, tot_new = [], 0, 0
    for root in AUDIT_ROOTS:
        for d in sorted(p for p in root.iterdir() if p.is_dir()):
            rp = d / "report.json"
            if not rp.is_file():
                continue
            base_rep = json.loads(rp.read_text())
            base = {key(c) for c in (base_rep.get("candidates") or [])}
            name = base_rep["repository"].split("/")[-1]
            cfp = OUT / name / "report.json"
            if not cfp.is_file():
                rows.append({"component": name, "status": "not_run"})
                continue
            cf_rep = json.loads(cfp.read_text())
            cf = {key(c) for c in (cf_rep.get("candidates") or [])}
            if (base_rep["snapshot_sha256"] != cf_rep["snapshot_sha256"]
                    or base_rep["plan_sha256"] != cf_rep["plan_sha256"]):
                rows.append({"component": name, "status": "scope_mismatch"})
                continue
            tot_base += len(base)
            tot_new += len(cf)
            rows.append({
                "component": name, "status": "compared",
                "baseline_candidates": len(base), "patched_candidates": len(cf),
                "removed": [{"file": f, "line": l, "rule_id": r} for f, l, r in sorted(base - cf)],
                "added": [{"file": f, "line": l, "rule_id": r} for f, l, r in sorted(cf - base)],
            })

    compared = [r for r in rows if r["status"] == "compared"]
    out = {
        "schema_version": 1, "kind": "ipc_copy_range_counterfactual",
        "generated": "2026-10-17 Asia/Shanghai",
        "detector_version": "0.8.0", "model_version": "oh-ipc-2026.10-v6",
        "baseline": "read-only pinned interface tree at 635b3e04 (unmodified)",
        "counterfactual": ("a copy of the same tree with four narrow edits, run from "
                           "the copy; the pinned tree is never written to"),
        "pinned_analysis_sha256": sha256(PINNED / TARGET),
        "patched_analysis_sha256": current,
        "outputs_pinned_to_patch": ("the run tree hashed to the value build() recorded "
                                    "before any output was compared; a drifted tree "
                                    "aborts the report instead of being attributed to "
                                    "this patch"),
        "edits": [label for label, _, _ in EDITS],
        "compared_components": len(compared),
        "baseline_candidates": tot_base, "patched_candidates": tot_new,
        # Real counts, not a net difference. `removed` and `added` were once written as
        # `tot_base - tot_new` and `tot_new - tot_base`, which sums to a single net
        # number and can print a negative "added" -- the opposite of what this artifact
        # is for, since an addition is the direction that matters most.
        "removed": sum(len(r["removed"]) for r in compared),
        "added": sum(len(r["added"]) for r in compared),
        "net_change": tot_new - tot_base,
        "removed_by_rule": dict(sorted(collections.Counter(
            r["rule_id"] for row in compared for r in row["removed"]).items())),
        "added_by_rule": dict(sorted(collections.Counter(
            r["rule_id"] for row in compared for r in row["added"]).items())),
        "components_with_any_change": [r["component"] for r in compared
                                       if r["removed"] or r["added"]],
        "components_not_compared": [r for r in rows if r["status"] != "compared"],
        "rows": rows,
        "note": ("Candidate sets are compared by (file, line, rule_id) after checking "
                 "both runs share snapshot_sha256 and plan_sha256, so a difference "
                 "cannot come from scope. An addition would be the dangerous "
                 "direction and is reported as loudly as a removal. "
                 "confirmed_vulnerabilities stays 0."),
    }
    DEST.mkdir(parents=True, exist_ok=True)
    (DEST / "counterfactual.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    print("compared=%d baseline=%d patched=%d removed=%d added=%d"
          % (len(compared), tot_base, tot_new, out["removed"], out["added"]))
    print("removed_by_rule:", out["removed_by_rule"])
    print("added_by_rule:  ", out["added_by_rule"])
    print("changed:", out["components_with_any_change"])
    for r in out["components_not_compared"]:
        print("  NOT COMPARED:", r)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build", action="store_true", help="(re)create the patched copy")
    ap.add_argument("--run", action="store_true", help="audit the corpus with the copy")
    ap.add_argument("--report", action="store_true", help="diff the copy against the pinned run")
    a = ap.parse_args()
    if a.build:
        build()
    if a.run:
        run()
    if a.report:
        report()
    if not (a.build or a.run or a.report):
        ap.print_help()
