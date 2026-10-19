"""Put every rule's real-corpus output and control coverage on one line.

The question this answers is not "how many candidates", but "does this rule have,
on a real component, the same three things family 1 has":

  * a candidate the shipped detector raises from real code (not a fixture);
  * a positive control, and the fixed/safe/unrelated controls around it, all
    declared in a family directory manifest;
  * a recorded reason when the corpus count is zero.

Sources, all read-only:

  --audit-root   one or more directories of <component>/report.json
  --fixtures     tests/fixtures/ipc (family manifests + the shared manifest)
  --out          JSON document

Counts are read from the reports and manifests; nothing is retyped. The
`corpus_zero` field is deliberately null when the rule fired and a string when it
did not, so a zero is never left implicit.
"""
import argparse
import collections
import glob
import json
import os

# The silence explanations measured in deliveries 3-15. They are keyed by rule
# and are claims about the corpus, each backed by a named instrument in the
# delivery document; none is a claim about what the code does.
ZERO_REASONS = {
    "ipc.auth.caller-class":
        "12 caller_class_sensitive_calls sites in 6 components; 6 sit under `*mock*` "
        "include paths. The caller-class probe recorded zero evaluations in the three "
        "components holding the other 6 sites (multimedia_audio_framework, "
        "ability_ability_runtime, bundlemanager_bundle_framework), so none of those "
        "was reached from a modeled entry.",
    "ipc.auth.identity-domain":
        "0 of 54 components contains a Verify*Token call whose argument is a caller UID; "
        "the call shape occurs 260 times across 33 components with token-ID arguments "
        "(shape census over the same reports).",
    "ipc.auth.service-identity":
        "Verify*Token over a self identity occurs outside IPC entries (ability_runtime "
        "napi/session code); across the 54 components the probe recorded no "
        "entry-reachable Verify*Token site consuming a self identity.",
    "ipc.auth.request-identity":
        "the predicate probe recorded no caller/self/request subject at any Verify*Token "
        "site across the measured components; the shape census finds no request-derived "
        "argument at those calls.",
    "ipc.parcel.position-underflow":
        "14 RewindRead sites in 5 components; exactly one size-minus shape, a checked "
        "subtraction behind `readPosition > PIXELMAP_UNMARSHALLING_DEBUG_OFFSET` "
        "(graphic_graphic_2d rs_marshalling_helper.cpp:2327); the rule emitted nothing "
        "at it (shape census; no per-site evaluation trace exists).",
}


def load(path):
    with open(path) as handle:
        return json.load(handle)


def manifests(fixtures):
    """Control counts per family and per rule.

    A positive row names its rule; a fixed/safe row is a negative control and
    names only its family (`expected_rule: null`). Counting only the first would
    report that no family has a fixed control, which is false.
    """
    by_rule = collections.defaultdict(collections.Counter)
    by_family = collections.defaultdict(collections.Counter)
    samples = collections.defaultdict(list)
    paths = sorted(glob.glob(os.path.join(fixtures, "*", "manifest.json")))
    paths.append(os.path.join(fixtures, "manifest.json"))
    for path in paths:
        if not os.path.isfile(path):
            continue
        document = load(path)
        rows = document if isinstance(document, list) else document.get("fixtures", [])
        for row in rows:
            variant = row.get("variant", "unspecified")
            family = row.get("family")
            rule = row.get("expected_rule")
            if family:
                by_family[family][variant] += 1
            if not rule:
                continue
            by_rule[rule][variant] += 1
            samples[rule].append({"sample_id": row.get("sample_id"),
                                  "file": row.get("file"),
                                  "variant": variant,
                                  "family": family})
    return by_rule, by_family, samples


def corpus(audit_roots):
    """{rule_id: {count, components, sites}} over every readable report."""
    found = collections.defaultdict(lambda: {"count": 0, "components": set(), "sites": []})
    component_count = 0
    for root in audit_roots:
        for path in sorted(glob.glob(os.path.join(root, "*", "report.json"))):
            try:
                report = load(path)
            except (OSError, ValueError):
                continue
            if report.get("shard_errors") or "/" not in (report.get("repository") or ""):
                continue
            component_count += 1
            name = os.path.basename(os.path.dirname(path))
            for candidate in report.get("candidates") or []:
                rule = candidate.get("rule_id")
                entry = found[rule]
                entry["count"] += 1
                entry["components"].add(name)
                if len(entry["sites"]) < 3:
                    entry["sites"].append({
                        "component": name,
                        "file": candidate.get("file"),
                        "line": candidate.get("line"),
                        "passes": candidate.get("passes"),
                        "file_parse_status": candidate.get("file_parse_status"),
                        "message": (candidate.get("message") or "")[:160],
                    })
    return component_count, found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-root", action="append", required=True)
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--rules", required=True,
                        help="JSON file with [{family, rule, cwe}] declarations")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    declared = load(args.rules)
    controls, family_controls, samples = manifests(args.fixtures)
    component_count, found = corpus(args.audit_root)

    rows = []
    for item in declared:
        rule = item["rule"]
        result = found.get(rule, {"count": 0, "components": set(), "sites": []})
        variants = dict(sorted(controls.get(rule, {}).items()))
        rows.append({
            "family": item["family"],
            "rule": rule,
            "cwe": item.get("cwe"),
            "corpus_candidates": result["count"],
            "corpus_components": len(result["components"]),
            "corpus_sites": result["sites"],
            "corpus_zero": None if result["count"] else ZERO_REASONS.get(
                rule, "zero; no shape measurement recorded for this rule"),
            "controls": variants,
            "control_samples": samples.get(rule, []),
            "family_controls": dict(sorted(family_controls.get(item["family"], {}).items())),
            "has_positive": bool(variants.get("positive")),
            "has_fixed": bool(family_controls.get(item["family"], {}).get("fixed")),
            "has_safe": bool(family_controls.get(item["family"], {}).get("safe")),
        })

    families = collections.defaultdict(lambda: {"rules": 0, "emitting_rules": 0,
                                                "corpus_candidates": 0, "controls": {}})
    for row in rows:
        bucket = families[row["family"]]
        bucket["rules"] += 1
        bucket["corpus_candidates"] += row["corpus_candidates"]
        if row["corpus_candidates"]:
            bucket["emitting_rules"] += 1
    for family, counts in family_controls.items():
        families[family]["controls"] = dict(sorted(counts.items()))

    document = {
        "schema_version": 1,
        "kind": "ipc_family_capability_parity",
        "generated": "2026-10-17 Asia/Shanghai",
        "components_read": component_count,
        "audit_roots": args.audit_root,
        "families": dict(sorted(families.items())),
        "rules": rows,
        "how_to_read": "`corpus_candidates` counts real-component candidates, not fixtures. "
                       "`controls` counts the declared positive/fixed/safe/unrelated fixtures "
                       "for the same rule. A zero with no `corpus_zero` would be a gap in this "
                       "document; every zero above carries one. Candidates are unverified "
                       "static evidence; validated_vulnerability remains 0.",
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print("%-34s %-34s %6s %6s %s" % ("family", "rule", "corpus", "ctrl", "variants"))
    for row in rows:
        print("%-34s %-34s %6d %6d %s" % (
            row["family"], row["rule"], row["corpus_candidates"],
            sum(row["controls"].values()), row["controls"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
