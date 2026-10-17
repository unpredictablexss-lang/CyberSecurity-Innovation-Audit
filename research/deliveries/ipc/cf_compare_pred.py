"""Diff the two predicate-tier copies against the unpatched ceiling runs.

Both sides are the *same instrument*: `ceiling_probe_site/sitecustomize.py` adds
the same entry roots in both runs (`added_roots` / `skipped_*` must agree, and
the run shares snapshot_sha256 and plan_sha256), so a difference in candidates
cannot come from reachability or scope -- only from the predicate edit.

An added candidate is reported as loudly as a removal: modelling a caller-class
fact can only suppress the caller-class rule at the sites it reaches, but the
fact also flows into other rules' obligations, and that direction has to be
read rather than assumed.
"""
import collections
import json
from pathlib import Path

BASE = {
    ("services", "service"): Path("/home/audit/wtmp/ceiling-out-services-service"),
    ("interfaces", "any"): Path("/home/audit/wtmp/ceiling-out-interfaces-any"),
}
CF = {
    1: {("services", "service"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-pred1-services-service"),
        ("interfaces", "any"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-pred1-interfaces-any")},
    2: {("services", "service"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-pred2-services-service"),
        ("interfaces", "any"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-pred2-interfaces-any")},
    "dw": {("services", "service"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-dw-services-service"),
           ("interfaces", "any"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-dw-interfaces-any")},
    "dw+pred": {("services", "service"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-pred1dw-services-service"),
                ("interfaces", "any"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-pred1dw-interfaces-any")},
    # Targeted camera-only run: tier 2 is observationally identical to tier 1 on
    # every reading, so this copy exists only to show that the combined edit
    # still does not move camera's caller-class record.
    "dw+pred2": {("services", "service"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-pred2dw-services-service"),
                 ("interfaces", "any"): Path("/home/audit/wtmp/ceiling-pred-detector-cf-pred2dw-interfaces-any")},
}
DEST = Path("/home/audit/ohscanner/worktrees/parallel-ipc-20261017/research/evidence/"
            "interface/ipc/caller_class_predicate_counterfactual_20261017")

TIER_TEXT = {
    "1": ("predicate, derived: callee not defined in this file, name in the reviewed bit-test set "
          "(IsSystemApp / IsSystemAppByFullTokenID / IsSystemAppByTokenID / IsSystemAppByTokenId), "
          "and the first argument is the caller's own token id "
          "(Value(kind='caller', subject='token'), derived by the engine from "
          "GetCallingTokenID / GetCallingFullTokenID at analysis.py:1244) => caller_class=system_app"),
    "2": ("predicate, derived as tier 1 plus an assumption: two reviewed names whose bodies live "
          "in another translation unit and are not read here (CheckSystemApp / "
          "CheckSystemAppByTokenID) also yield caller_class=system_app. The added half is an "
          "assumption about a name, not a derivation from source, so it is kept a separate copy."),
    "dw": ("control flow, derived: the zero-iteration escape `analysis.py:1575` forks for every "
           "loop is not a path in C semantics for `do_statement`, so it is not generated for it. "
           "The OHOS guard idiom wraps the check in exactly `do { if (cond) { return ret; } } "
           "while (0)`, so the escape is what left the guarded operation reachable with no guard."),
    "dw+pred": ("both edits in one copy: the do/while escape removed and the tier-1 predicate rule."),
    "dw+pred2": ("both edits in one copy with tier 2's name-level assumptions. This copy was run on "
                 "camera only, as a targeted check: tier 2 is observationally identical to tier 1 on "
                 "every reading, so the other rows are not_run by design, not by failure."),
}


def key(c):
    return (c["file"], c["line"], c["rule_id"])


def load(path):
    rep = json.loads(path.read_text())
    return rep, {key(c) for c in (rep.get("candidates") or [])}


def roots(path):
    p = path.parent / "ceiling.json"
    if not p.is_file():
        return None
    c = json.loads(p.read_text())
    return (len(c["added_roots"]), c["skipped_by_side"], c["skipped_by_owner"],
            c["already_roots"])


def pass_runs(path):
    """Per-pass status/analyzed/diagnostics, which candidate identity alone hides."""
    rep = json.loads(path.read_text())
    return {r["pass"]: {"status": r["detector_status"],
                        "analyzed_files": r["analyzed_files"],
                        "diagnostics": r["diagnostics"]}
            for r in rep["coverage"]["run_state"]["pass_runs"]}


def main():
    out = {"schema_version": 1, "kind": "ipc_caller_class_predicate_counterfactual",
           "generated": "2026-10-17 Asia/Shanghai",
           "detector_version": "0.8.0", "model_version": "oh-ipc-2026.10-v6",
           "baseline": "read-only pinned interface tree at 635b3e04 (unmodified), run under the ceiling probe",
           "counterfactual": ("a copy of the same tree with the predicate edit, run from the copy "
                              "under the same probe; the pinned tree is never written to"),
           "tiers": {str(t): TIER_TEXT[t] for t in TIER_TEXT},
           "tier_runs": {}}

    for tier in CF:
        rows, tot_base, tot_cf, tot_removed, tot_added = [], 0, 0, 0, 0
        per_rule_removed, per_rule_added = collections.Counter(), collections.Counter()
        for (side, owner), broot in BASE.items():
            croot = CF[tier][(side, owner)]
            if not croot.is_dir():
                # A missing counterfactual root must be reported as not_run for
                # every component in that reading. Skipping the reading would
                # make a coverage gap look like "no change".
                for d in sorted(p for p in broot.iterdir() if p.is_dir()):
                    rows.append({"component": d.name, "reading": "%s/%s" % (side, owner),
                                 "status": "not_run"})
                continue
            for d in sorted(p for p in broot.iterdir() if p.is_dir()):
                name = d.name
                brp, crp = d / "report.json", croot / name / "report.json"
                if not brp.is_file() or not crp.is_file():
                    rows.append({"component": name, "reading": "%s/%s" % (side, owner),
                                 "status": "not_run"})
                    continue
                brep, b = load(brp)
                crep, c = load(crp)
                rbase, rcf = roots(brp), roots(crp)
                if (brep["snapshot_sha256"] != crep["snapshot_sha256"]
                        or brep["plan_sha256"] != crep["plan_sha256"]):
                    rows.append({"component": name, "reading": "%s/%s" % (side, owner),
                                 "status": "scope_mismatch"})
                    continue
                if rbase != rcf:
                    rows.append({"component": name, "reading": "%s/%s" % (side, owner),
                                 "status": "roots_mismatch", "baseline_roots": rbase,
                                 "counterfactual_roots": rcf})
                    continue
                removed = sorted(b - c)
                added = sorted(c - b)
                tot_base += len(b)
                tot_cf += len(c)
                tot_removed += len(removed)
                tot_added += len(added)
                per_rule_removed.update(r for _, _, r in removed)
                per_rule_added.update(r for _, _, r in added)
                row = {"component": name, "reading": "%s/%s" % (side, owner),
                       "status": "compared", "added_roots": rbase[0],
                       "baseline_candidates": len(b), "counterfactual_candidates": len(c),
                       "removed": [{"file": f, "line": l, "rule_id": r} for f, l, r in removed],
                       "added": [{"file": f, "line": l, "rule_id": r} for f, l, r in added]}
                pbase, pcf = pass_runs(brp), pass_runs(crp)
                if pbase != pcf:
                    # A record can keep its identity while losing one of its two
                    # sources; the counterfactual must say so rather than let the
                    # candidate count imply "nothing changed" at pass level.
                    row["pass_runs_changed"] = {"baseline": pbase, "counterfactual": pcf}
                rows.append(row)
        compared = [r for r in rows if r["status"] == "compared"]
        out["tier_runs"][str(tier)] = {
            "compared_components": len(compared),
            "baseline_candidates": tot_base, "counterfactual_candidates": tot_cf,
            "net_change": tot_cf - tot_base,
            "removed": tot_removed, "added": tot_added,
            "removed_by_rule": dict(sorted(per_rule_removed.items())),
            "added_by_rule": dict(sorted(per_rule_added.items())),
            "pass_runs_changed": [{"component": r["component"], "reading": r["reading"]}
                                  for r in compared if "pass_runs_changed" in r],
            "rows": rows, "not_compared": [r for r in rows if r["status"] != "compared"],
        }

    out["note"] = ("Same instrument on both sides: both runs carry the same "
                   "snapshot_sha256 and plan_sha256 and the same added_roots / skipped_* "
                   "counts, so a candidate difference comes from the predicate edit alone. "
                   "confirm_vulnerabilities stays 0; a suppression is a statement about the "
                   "model, not a statement that the component is safe.")
    DEST.mkdir(parents=True, exist_ok=True)
    (DEST / "counterfactual.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n")

    for tier in CF:
        r = out["tier_runs"][str(tier)]
        print("tier %s: compared=%d baseline=%d counterfactual=%d removed=%d added=%d"
              % (tier, r["compared_components"], r["baseline_candidates"],
                 r["counterfactual_candidates"], r["removed"], r["added"]))
        print("   removed_by_rule:", r["removed_by_rule"])
        print("   compared:", ["%s@%s %d->%d" % (row["component"], row["reading"],
                                                row["baseline_candidates"],
                                                row["counterfactual_candidates"])
                               for row in r["rows"] if row["status"] == "compared"])
        print("   added_by_rule:  ", r["added_by_rule"])
        for row in r["rows"]:
            if row["status"] == "compared" and (row["removed"] or row["added"]):
                print("   %-34s %-18s %d -> %d" % (row["component"], row["reading"],
                                                   row["baseline_candidates"],
                                                   row["counterfactual_candidates"]))
                for x in row["removed"]:
                    print("        - %s:%s %s" % (x["file"], x["line"], x["rule_id"]))
                for x in row["added"]:
                    print("        + %s:%s %s" % (x["file"], x["line"], x["rule_id"]))
        for row in r["not_compared"]:
            print("   NOT COMPARED:", row)


if __name__ == "__main__":
    main()
