"""What AUTH-01's own report says about the quality of AUTH-01's output.

`ipc.relay.descriptor-boundary` carries most of this lane's candidates (103 of
179). This probe asks a narrow, checkable question about them: how many does the
report's *own* fields already show to be wrong? Three modes, each decided without
reading any source:

  guard_symbol   the function the message blames for lacking descriptor validation
                 is itself a check (`EnforceInterceToken`, `CheckPermission`, ...)
  empty_path     the message claims a relay path while recording `path=()`
  enforced_path  the recorded path contains a condition naming an enforcement call
                 that evaluated True -- i.e. the boundary the rule reports as
                 missing is recorded as having been enforced

A mode match is not a verdict, so every flagged candidate is then read out of the
pinned *blob* at its own commit, and -- because the detector has a suppression path
for exactly this shape -- the instrumented copy below reports which condition of
`relay_guard` (analysis.py:1159) stopped that path from firing. The call site's own
comment says a `("guarded", ...)` verdict means "the relayed-to function is the
guard, so this call site is not itself an unguarded boundary"; every flagged
candidate is a site where that path did not fire, so each one has to be assigned
to a specific condition rather than described in general terms.

Nothing is deleted, withheld or re-scored: the flagged candidates stay candidates
in their reports. The point is to make a knowable defect legible, not to move a
count.

Stages: --screen (report fields + pinned-blob excerpts), --instrument (a copy of
the tree with relay_guard's six exits labelled), --run (audit the components that
carry flagged candidates), --cause (join the verdicts onto the candidates).
"""
import argparse
import collections
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

PINNED = Path("/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b")
PYTHON = PINNED / ".venv/bin/python"
RG_COPY = Path("/home/audit/wtmp/detector-rg")
RG_OUT = Path("/home/audit/wtmp/rg-out")
DEST = Path("/home/audit/ohscanner/worktrees/parallel-ipc-20261017/research/evidence/"
            "interface/ipc/auth01_precision_probe_20261017")

AUDITS = [
    ("baseline30", Path("/home/audit/wtmp/ipc-audit"),
     ["/home/audit/openharmony-audit/perf-corpus", "/home/audit/corpus-ipc-widen",
      "/home/audit/corpus-ipc-shape", "/home/audit/openharmony-audit/gitcode-corpus"]),
    ("bline12", Path("/home/audit/wtmp/ipc-audit-bline"), ["/home/audit/corpus-ipc-bline"]),
]
ALL_CORPORA = ["/home/audit/openharmony-audit/perf-corpus", "/home/audit/corpus-ipc-widen",
               "/home/audit/corpus-ipc-shape", "/home/audit/openharmony-audit/gitcode-corpus",
               "/home/audit/corpus-ipc-bline"]

RULE = "ipc.relay.descriptor-boundary"

# ---- the screen, verbatim from the scratch run -----------------------------
GUARD = re.compile(
    r"(Check|Enforce|Verify|Validate|Is)[A-Za-z]*"
    r"(Descriptor|InterfaceToken|Token|Calling|Permission|Caller|Guard|Access)"
    r"|^(Check|Enforce|Verify|Validate|Is[A-Z])")
ENFORCE = re.compile(
    r"(Check|Enforce|Verify|Validate)[A-Za-z]*(Descriptor|InterfaceToken|Token|Permission)")
EMPTY = re.compile(r"path=\(\)")
PATHITEM = re.compile(r"\((\d+), '(.*?)'\)")
NAMES_HANDLER = re.compile(r"(?:validation|guard)[:;][^:]*?([A-Za-z_][\w:]*::\w+)")

# ---- relay_guard's six exits, labelled ------------------------------------
RG_EXITS = [
    ("""        if helper.body is None or helper.file != fn.file:
            return None""",
     """        if helper.body is None or helper.file != fn.file:
            self._rg(fn, node, helper, "1_body_or_file")
            return None"""),
    ("""        if not carried or any(name not in fn.params for name in carried):
            return None""",
     """        if not carried or any(name not in fn.params for name in carried):
            self._rg(fn, node, helper, "2_args_not_carried")
            return None"""),
    ("""        if check is None:
            return None""",
     """        if check is None:
            self._rg(fn, node, helper, "3_no_descriptor_if")
            return None"""),
    ("""        if expected.subject not in _DESCRIPTOR_ACCEPTED:
            return ("seen", (expected.subject, expected.key) + tuple(expected.terms))""",
     """        if expected.subject not in _DESCRIPTOR_ACCEPTED:
            self._rg(fn, node, helper, "4_subject_not_accepted")
            return ("seen", (expected.subject, expected.key) + tuple(expected.terms))"""),
    ("""        if not any(item.type in _RELAY_LEAVES for item in leaving):
            return None""",
     """        if not any(item.type in _RELAY_LEAVES for item in leaving):
            self._rg(fn, node, helper, "5_mismatch_does_not_leave")
            return None"""),
    ("""        if not any(item.type == "switch_statement" for item in statements[index + 1:]):
            return None""",
     """        if not any(item.type == "switch_statement" for item in statements[index + 1:]):
            self._rg(fn, node, helper, "6_no_switch_after_check")
            return None"""),
    ("""        return ("guarded", where)""",
     """        self._rg(fn, node, helper, "0_guarded")
        return ("guarded", where)"""),
]
RG_SINK = '''
    def _rg(self, fn, node, helper, verdict):
        import os as _os, json as _json
        path = _os.environ.get("RG_LOG")
        if not path:
            return
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(_json.dumps({
                    "file": fn.file, "call_line": node.start_point[0] + 1,
                    "entry": self.root.name, "helper": helper.qualified,
                    "helper_file": helper.file, "verdict": verdict,
                }) + "\\n")
        except Exception:
            pass

    def relay_guard(self, fn, node, args, helper, state, depth):'''

CAUSE_TEXT = {
    "0_guarded": "relay_guard DID recognise the guard",
    "1_body_or_file": "helper body missing, or helper defined in another file",
    "2_args_not_carried": "no argument carried, or a carried argument is not an entry parameter "
                          "(a nullary guard can never be recognised)",
    "3_no_descriptor_if": "no top-level `if` whose condition is a descriptor predicate -- the "
                          "guard is written as a bare returned comparison",
    "4_subject_not_accepted": "a descriptor comparison was found but its subject is accepted",
    "5_mismatch_does_not_leave": "the mismatch branch does not leave",
    "6_no_switch_after_check": "the check is not followed by a `switch` -- the helper is a pure "
                               "predicate, not a dispatching inner handler",
    "no_verdict_recorded": "relay_guard was not invoked at this site",
    "entry_named_not_a_guard": "not applicable: the message names the entry, not a guard",
}


def blob(root, commit, rel):
    r = subprocess.run(["git", "-C", str(root), "rev-parse", "%s:%s" % (commit, rel)],
                       capture_output=True, text=True)
    if r.returncode:
        return None, "blob not addressable at commit: " + r.stderr.strip()[:120]
    b = subprocess.run(["git", "-C", str(root), "cat-file", "blob", r.stdout.strip()],
                       capture_output=True, text=True)
    if b.returncode:
        return None, "blob unreadable"
    return b.stdout, None


def excerpt(root, rel, line, commit, context=5):
    src, err = blob(root, commit, rel)
    if src is None:
        return None, err
    lines = src.splitlines()
    lo, hi = max(0, line - context - 1), min(len(lines), line + context)
    return "\n".join("%6d %s" % (i + 1, lines[i]) for i in range(lo, hi)), None


def screen():
    DEST.mkdir(parents=True, exist_ok=True)
    flagged, batches = [], []
    counts, totals = collections.Counter(), collections.Counter()
    for label, audit, roots in AUDITS:
        for d in sorted(p for p in audit.iterdir() if p.is_dir()):
            rp = d / "report.json"
            if not rp.is_file():
                continue
            rep = json.loads(rp.read_text())
            name = rep["repository"].split("/")[-1]
            root = next((Path(c) / name for c in roots if (Path(c) / name).is_dir()), None)
            for c in rep.get("candidates") or []:
                if c["rule_id"] != RULE:
                    continue
                totals[label] += 1
                msg = c.get("message") or ""
                named = NAMES_HANDLER.search(msg)
                handler = named.group(1) if named else ""
                enforced = [t for _, t in PATHITEM.findall(msg)
                            if ENFORCE.search(t) and "True" in t]
                modes = []
                if GUARD.match(handler.split("::")[-1]):
                    modes.append("guard_symbol")
                if EMPTY.search(msg):
                    modes.append("empty_path")
                if enforced:
                    modes.append("enforced_path")
                if not modes:
                    continue
                for m in modes:
                    counts[(label, m)] += 1
                rec = {"batch": label, "component": name, "repository": rep["repository"],
                       "commit": c["commit"], "file": c["file"], "line": c["line"],
                       "symbol": c.get("symbol"), "named_handler": handler, "modes": modes,
                       "enforced_condition": enforced[0][:120] if enforced else "",
                       "source_sha256": c.get("source_sha256"), "message": msg[:400]}
                if root is not None:
                    src, err = blob(root, c["commit"], c["file"])
                    if src is not None:
                        lines = src.splitlines()
                        lo = max(0, c["line"] - 6)
                        hi = min(len(lines), c["line"] + 5)
                        rec["excerpt"] = "\n".join("%6d %s" % (i + 1, lines[i])
                                                   for i in range(lo, hi))
                    rec["excerpt_error"] = err
                else:
                    rec["excerpt_error"] = "corpus root not found"
                flagged.append(rec)
        any_ = sum(1 for f in flagged if f["batch"] == label)
        batches.append({"batch": label, "candidates": totals[label], "flagged": any_,
                        "modes": {k: counts[(label, k)]
                                  for k in ("guard_symbol", "empty_path", "enforced_path")},
                        "flagged_fraction": round(any_ / totals[label], 4) if totals[label] else None})

    out = {"schema_version": 1, "kind": "ipc_auth01_precision_probe",
           "generated": "2026-10-17 Asia/Shanghai",
           "detector_version": "0.8.0", "model_version": "oh-ipc-2026.10-v6", "rule": RULE,
           "screen_source": ("regexes copied verbatim from the scratch screen; modes are "
                             "decided from the candidate's own message and symbol fields, "
                             "not from the source read"),
           "excerpt_source": ("pinned blob via `git rev-parse <commit>:<path>` then "
                              "`git cat-file blob`; worktree text is never used"),
           "batches": batches, "flagged": flagged,
           "note": ("Flagged candidates are neither deleted nor re-scored; they remain "
                    "candidates in their reports. A mode match is evidence about the "
                    "rule's output, not a verdict that the component is safe. "
                    "confirmed_vulnerabilities stays 0.")}
    (DEST / "precision_probe.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(batches, indent=1))
    print("flagged rows:", len(flagged),
          "excerpt failures:",
          sum(1 for f in flagged if f.get("excerpt_error") and "excerpt" not in f))


def instrument():
    if RG_COPY.exists():
        shutil.rmtree(RG_COPY)
    shutil.copytree(PINNED / "src", RG_COPY / "src")
    for pyc in RG_COPY.rglob("__pycache__"):
        shutil.rmtree(pyc)
    path = RG_COPY / "src/ohscanner/detectors/interface/analysis.py"
    text = path.read_text(encoding="utf-8")
    for old, new in RG_EXITS:
        if text.count(old) != 1:
            raise SystemExit("anchor matched %d times: %s" % (text.count(old), old[:60]))
        text = text.replace(old, new)
    anchor = "\n    def relay_guard(self, fn, node, args, helper, state, depth):"
    if text.count(anchor) != 1:
        raise SystemExit("relay_guard anchor not unique")
    path.write_text(text.replace(anchor, RG_SINK), encoding="utf-8")
    print("relay_guard instrumented: %d exits labelled" % len(RG_EXITS))


def run():
    probe = json.loads((DEST / "precision_probe.json").read_text())
    wanted = sorted({f["component"] for f in probe["flagged"]})
    RG_OUT.mkdir(parents=True, exist_ok=True)
    log = RG_OUT / "all.jsonl"
    if log.exists():
        log.unlink()
    for name in wanted:
        commit = json.loads((Path("/home/audit/wtmp/ipc-audit") / name / "report.json").read_text()
                            )["commit"] if (Path("/home/audit/wtmp/ipc-audit") / name
                                            / "report.json").is_file() else None
        if commit is None:
            commit = json.loads((Path("/home/audit/wtmp/ipc-audit-bline") / name
                                 / "report.json").read_text())["commit"]
        # A component can sit in more than one corpus clone, and its report's commit
        # exists only in the clone it was read from. Pick by object presence: picking
        # by directory order audits a tree the report does not describe, or dies on
        # "Needed a single revision" and leaves the candidate unexplained.
        repo = next(
            (Path(c) / name for c in ALL_CORPORA
             if (Path(c) / name).is_dir()
             and not subprocess.run(["git", "-C", str(Path(c) / name), "cat-file", "-e",
                                     commit + "^{commit}"],
                                    capture_output=True).returncode),
            None)
        if repo is None:
            print("== %s NO CORPUS WITH %s" % (name, commit))
            continue
        d = RG_OUT / name
        d.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, RG_LOG=str(d / "relay.jsonl"))
        with open(d / "stdout.log", "w") as out:
            subprocess.run([str(PYTHON), "-m", "src.ohscanner.detectors.interface.audit",
                            "--repo-dir", str(repo), "--repository", "openharmony/" + name,
                            "--commit", commit, "--out-dir", str(d),
                            "--json-out", str(d / "report.json"),
                            "--md-out", str(d / "report.md")],
                           cwd=str(RG_COPY), stdout=out, stderr=subprocess.STDOUT, env=env)
        n = len((d / "relay.jsonl").read_text().splitlines()) if (d / "relay.jsonl").is_file() else 0
        print("== %-34s relay_calls=%d" % (name, n))
        if (d / "relay.jsonl").is_file():
            with open(log, "a") as fh:
                fh.write((d / "relay.jsonl").read_text())


def cause():
    probe = json.loads((DEST / "precision_probe.json").read_text())
    # The detector re-visits the same call site once per IPC entry it analyses, so a
    # raw append would repeat one verdict dozens of times and the artifact's content
    # would drift with the entry count. Measured over the flagged components: 44
    # distinct call sites, revisits 2-80, and **no** site carried two different
    # verdicts -- so collapsing to a sorted set of distinct verdicts loses nothing.
    # The revisit count is kept: it says how many passes saw the site.
    verdicts = collections.defaultdict(collections.Counter)
    for line in (RG_OUT / "all.jsonl").read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            verdicts[(r["file"], r["call_line"])][r["verdict"]] += 1

    per_handler = collections.defaultdict(collections.Counter)
    rows = []
    for f in probe["flagged"]:
        rec = dict(f)
        if "guard_symbol" not in f["modes"]:
            # The screen's handler regex picked up the entry name here, so a relay
            # verdict would answer a question that was not asked.
            rec["cause"] = "entry_named_not_a_guard"
        else:
            seen = verdicts.get((f["file"], f["line"]), collections.Counter())
            hits = sorted(seen)
            rec["relay_verdicts"] = hits
            rec["relay_verdict_passes"] = sum(seen.values())
            rec["cause"] = hits[0] if hits else "no_verdict_recorded"
            if hits:
                per_handler[rec["cause"]][f["named_handler"].split("::")[-1]] += 1
        rec["cause_note"] = CAUSE_TEXT.get(rec["cause"], "")
        rows.append(rec)

    tally = collections.Counter(r["cause"] for r in rows
                                if r["cause"] != "entry_named_not_a_guard")
    out = {"schema_version": 1, "kind": "ipc_auth01_relay_guard_cause",
           "generated": "2026-10-17 Asia/Shanghai", "rule": RULE,
           "method": ("relay_guard in a copy of the pinned tree was instrumented to "
                      "label each of its six exits; the copy was run on the components "
                      "carrying flagged candidates and the verdicts were joined onto "
                      "the candidates by file and line. Nothing was inferred."),
           "suppression_path": "src/ohscanner/detectors/interface/analysis.py:1159 relay_guard",
           "exits_in_order": [
               ":1178 helper.body is None or helper.file != fn.file",
               ":1182 no argument carried, or a carried argument is not an entry parameter",
               ":1199 no top-level if_statement whose condition is a descriptor predicate",
               ":1211 comparison found but its subject is not in _DESCRIPTOR_ACCEPTED",
               ":1222 the mismatch branch does not leave",
               ":1225 the check is not followed by a switch_statement"],
           "cause_tally": dict(sorted(tally.items())),
           "handler_by_cause": {k: dict(sorted(v.items())) for k, v in sorted(per_handler.items())},
           "rows": rows,
           "note": ("A cause reading, not a detector change. The suppression path itself "
                    "is source-verified; these verdicts say which condition of it did not "
                    "hold. confirmed_vulnerabilities stays 0.")}
    (DEST / "relay_guard_cause.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    print("cause tally:", dict(sorted(tally.items())))
    for c, hs in sorted(per_handler.items()):
        print("  %-28s %s" % (c, dict(sorted(hs.items()))))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    for stage in ("screen", "instrument", "run", "cause"):
        ap.add_argument("--" + stage, action="store_true")
    a = ap.parse_args()
    for stage in ("screen", "instrument", "run", "cause"):
        if getattr(a, stage.replace("-", "_")):
            globals()[stage]()
    if not any(getattr(a, s) for s in ("screen", "instrument", "run", "cause")):
        ap.print_help()
