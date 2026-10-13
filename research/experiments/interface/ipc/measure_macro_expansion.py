"""Measure what bounded macro expansion changes on real OpenHarmony components.

`cpp_macros` was ported to close two gaps at once: files Tree-sitter cannot parse
because a macro argument carries a statement, and guards written inside a macro
body that the interpreter therefore never saw. This script measures both, and then
the number that actually matters -- whether the candidate set changes.

Sections, kept separate as the corpus protocol asks:

  1. run state         - units read, catalogue size, whether the budget truncated
  2. analysis coverage - complete/partial parses before and after expansion,
                         invocations expanded, refusals by reason, and what those
                         refusals cost (a refused definition that names a modelled
                         guard callee is reported separately from an absent one)
  3. candidate delta   - findings with expansion off vs on, per rule

Section 3 is a *delta*, not a root-cause intersection: a candidate that appears or
disappears here has not been checked against a historical fix, and
`validated_vulnerability` stays 0. Nothing here establishes a vulnerability.

Usage:
  .venv/bin/python research/experiments/interface/ipc/measure_macro_expansion.py \
      --corpus ~/openharmony-audit/perf-corpus \
      --json outputs/reports/macro_expansion.json \
      --md   outputs/reports/macro_expansion.md
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# Run from anywhere: the project root is four levels up from this file.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp

from src.ohscanner.detectors.interface.analysis import Interpreter, normalize_syntax
from src.ohscanner.detectors.interface.cpp_macros import Expansion, catalog_for_units, expand_with_catalog
from src.ohscanner.detectors.interface.models import IpcPolicy

DEFAULT_CORPUS = Path.home() / "openharmony-audit" / "perf-corpus"
SOURCE_SUFFIXES = (".cpp", ".cc", ".cxx", ".c", ".h", ".hh", ".hpp", ".inl")
SKIPPED_DIRS = ("/test/", "/unittest/", "/fuzztest/")


class Unit:
    """Minimal SourceUnit stand-in: the analysis reads exactly these four fields."""

    def __init__(self, path, text, language):
        self.path = path
        self.language = language
        self.text = text
        self.parse_status = "complete"


def load_units(component_dir):
    units = []
    for path in sorted(component_dir.rglob("*")):
        if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
            continue
        relative = "/" + path.relative_to(component_dir).as_posix()
        if any(marker in relative for marker in SKIPPED_DIRS):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        units.append(Unit(relative.lstrip("/"), text, "c" if path.suffix == ".c" else "cpp"))
    return units


def _parses_clean(source, grammar):
    return not Parser(Language(grammar)).parse(normalize_syntax(source)).root_node.has_error


def refusal_cost(catalog, policy):
    """What the expander's own refusals cost, measured instead of assumed.

    The applied-expansion count cannot answer "the corpus has no macro-hidden
    authorization guard" on its own: `variadic_stringify_or_token_paste` is by far
    the most common refusal, and OpenHarmony's own error-check macros are exactly
    the variadic ones. If a catalogued definition that would have been refused
    mentions a modelled guard callee, then the benefit may be hidden behind the
    refusal rather than absent from the corpus. Both numbers are reported so the
    two explanations can be told apart.
    """
    modelled = set(policy.boolean_permissions) | set(policy.result_permissions)
    refused = expected = 0
    samples = []
    for name, variants in sorted(catalog.items()):
        for definition in variants:
            params = definition["parameters"]
            why = ("variadic_stringify_or_token_paste"
                   if "#" in definition["body"] or (params is not None and "..." in params)
                   else "conditional_definition_requires_build_profile"
                   if definition["conditional_context"] else "")
            if not why:
                continue
            refused += 1
            mentioned = modelled & set(re.findall(r"[A-Za-z_]\w*", definition["body"]))
            if mentioned:
                expected += 1
                if len(samples) < 20:
                    samples.append({"macro": name, "reason": why, "file": definition["file"],
                                    "line": definition["line"], "mentions": sorted(mentioned),
                                    "body": definition["body"][:160]})
    return {"refused_definitions": refused,
            "refused_definitions_mentioning_a_modelled_guard": expected,
            "samples": samples}


def scan_stats(units):
    """Parse and expansion counts, applying the same decision the interpreter does.

    This is the private parse `analysis.Interpreter` performs, not the public
    frontend's, so a file that only becomes parseable after expansion is reported
    here as a private coverage gain and never as a public parse-status change.

    An expansion that would turn a parseable file into a partial one is dropped,
    exactly as `Interpreter` drops it, so `became_parseable` cannot go negative and
    the numbers describe the shipped behaviour rather than the raw expander.
    """
    catalog, sources, total, truncated = catalog_for_units(units, 400, 6_000_000)
    # The number that decides whether any of this can change a finding: an expansion
    # only suppresses a candidate if it puts a *modelled* guard into the path. A
    # macro expanding to `if (!IsPermissionGranted(...)) return;` does nothing here,
    # because that callee is not in the policy's guard sets.
    policy = IpcPolicy()
    guard_identifiers = set(policy.boolean_permissions | policy.result_permissions)
    complete_before = partial_before = complete_after = partial_after = 0
    expanded_files = unexpanded_files = dropped = invocations = control_flow = 0
    guard_introducing = 0
    reasons, fatal_reasons = Counter(), Counter()
    for unit in units:
        raw = unit.text.encode("utf-8")
        grammar = tree_sitter_c.language() if unit.language == "c" else tree_sitter_cpp.language()
        before_clean = _parses_clean(raw, grammar)
        expansion = expand_with_catalog(raw, catalog)
        if (expansion.applied and before_clean
                and not _parses_clean(expansion.source, grammar)):
            dropped += 1
            expansion = Expansion(raw, {}, (), expansion.refused, ("expansion_worsened_the_parse",))
        if expansion.fatal:
            unexpanded_files += 1
            for reason in expansion.fatal:
                fatal_reasons[reason] += 1
        else:
            for _, reason in expansion.refused:
                reasons[reason] += 1
            if expansion.applied:
                expanded_files += 1
                invocations += len(expansion.expansions)
                control_flow += len(expansion.carried_control_flow)
                guard_introducing += sum(
                    1 for record in expansion.expansions
                    if guard_identifiers & set(re.findall(r"[A-Za-z_]\w*", record["expanded"])))
        after_clean = before_clean if not expansion.applied else _parses_clean(expansion.source, grammar)
        complete_before += before_clean
        partial_before += not before_clean
        complete_after += after_clean
        partial_after += not after_clean
    return {"complete_before": complete_before, "partial_before": partial_before,
            "complete_after": complete_after, "partial_after": partial_after,
            "became_parseable": complete_after - complete_before,
            "refusal_cost": refusal_cost(catalog, policy),
            "dropped_to_protect_the_parse": dropped,
            "catalogued_sources": sources, "catalogued_bytes": total, "catalog_truncated": truncated,
            "macros_catalogued": len(catalog), "files_expanded": expanded_files,
            "files_left_unexpanded": unexpanded_files, "invocations_expanded": invocations,
            "expansions_carrying_control_flow": control_flow,
            "expansions_introducing_a_modelled_guard": guard_introducing,
            "refused_by_reason": dict(sorted(reasons.items())),
            "fatal_by_reason": dict(sorted(fatal_reasons.items()))}


def candidate_delta(units):
    findings = {"off": Counter(), "on": Counter()}
    limits = {}
    for label, expand in (("off", False), ("on", True)):
        interpreter = Interpreter(units, IpcPolicy(expand_macros=expand))
        observations, _ = interpreter.run()
        for obs in observations:
            findings[label][obs.rule] += 1
        limits[label] = [s for s in sorted(interpreter.limitations) if s.startswith("Macro expansion")]
    rules = sorted(set(findings["off"]) | set(findings["on"]))
    return {"findings_off": sum(findings["off"].values()), "findings_on": sum(findings["on"].values()),
            "by_rule": {rule: {"off": findings["off"].get(rule, 0), "on": findings["on"].get(rule, 0)}
                        for rule in rules if findings["off"].get(rule, 0) != findings["on"].get(rule, 0)},
            "expansion_note": limits["on"][0] if limits["on"] else "expansion had nothing to do"}


def measure(component_dir, with_delta, limit_units):
    units = load_units(component_dir)
    if limit_units:
        units = units[:limit_units]
    stats = scan_stats(units)
    parse_keys = ("complete_before", "partial_before", "complete_after", "partial_after",
                  "became_parseable")
    report = {"component": component_dir.name, "units": len(units),
              "parse": {key: stats[key] for key in parse_keys},
              "expansion": {key: value for key, value in stats.items() if key not in parse_keys}}
    if with_delta:
        report["candidates"] = candidate_delta(units)
    return report


def render_markdown(reports):
    lines = ["# Macro expansion on real components", "",
             "Generated by `research/experiments/interface/ipc/measure_macro_expansion.py`.",
             "Section 3 is a candidate delta, not a root-cause intersection; nothing here is a "
             "vulnerability claim.", ""]
    for report in reports:
        expansion = report["expansion"]
        parse = report["parse"]
        lines += ["## " + report["component"], "",
                  "| metric | value |", "|---|---:|",
                  "| units read | " + str(report["units"]) + " |",
                  "| catalogued sources / bytes | " + str(expansion["catalogued_sources"]) + " / "
                  + str(expansion["catalogued_bytes"]) + " |",
                  "| macros in catalogue | " + str(expansion["macros_catalogued"]) + " |",
                  "| files with an expansion applied | " + str(expansion["files_expanded"]) + " |",
                  "| files left unexpanded | " + str(expansion["files_left_unexpanded"]) + " |",
                  "| expansions dropped to protect the parse | "
                  + str(expansion["dropped_to_protect_the_parse"]) + " |",
                  "| invocations expanded | " + str(expansion["invocations_expanded"]) + " |",
                  "| ...carrying control flow | " + str(expansion["expansions_carrying_control_flow"]) + " |",
                  "| ...introducing a modelled guard | "
                  + str(expansion["expansions_introducing_a_modelled_guard"]) + " |",
                  "| complete parses before / after | " + str(parse["complete_before"]) + " / "
                  + str(parse["complete_after"]) + " |",
                  "| partial parses before / after | " + str(parse["partial_before"]) + " / "
                  + str(parse["partial_after"]) + " |", ""]
        cost = expansion.get("refusal_cost")
        if cost:
            lines += ["Refused definitions: " + str(cost["refused_definitions"])
                      + ", of which mention a modelled guard callee: "
                      + str(cost["refused_definitions_mentioning_a_modelled_guard"]) + "", ""]
            for sample in cost["samples"][:10]:
                lines.append("- `" + sample["macro"] + "` (" + sample["reason"] + ", "
                             + sample["file"] + ":" + str(sample["line"]) + ") mentions `"
                             + ", ".join(sample["mentions"]) + "`: `"
                             + sample["body"].replace("\n", " ").replace("|", "\\|") + "`")
            if cost["samples"]:
                lines.append("")
        if expansion["refused_by_reason"]:
            lines += ["Refused (macro left as written):", ""]
            lines += ["- `" + k + "`: " + str(v) for k, v in expansion["refused_by_reason"].items()]
            lines.append("")
        if expansion["fatal_by_reason"]:
            lines += ["Not expanded (whole file); these files fall back to the unexpanded source:", ""]
            lines += ["- `" + k + "`: " + str(v) for k, v in expansion["fatal_by_reason"].items()]
            lines.append("")
        if "candidates" in report:
            candidates = report["candidates"]
            lines += ["Candidates off / on: " + str(candidates["findings_off"]) + " / "
                      + str(candidates["findings_on"]), ""]
            if candidates["by_rule"]:
                lines += ["| rule | off | on |", "|---|---:|---:|"]
                lines += ["| `" + rule + "` | " + str(counts["off"]) + " | " + str(counts["on"]) + " |"
                          for rule, counts in candidates["by_rule"].items()]
            else:
                lines.append("No rule changed count.")
            lines.append("")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--components", nargs="*", default=None,
                        help="component directory names; default is every directory with sources")
    parser.add_argument("--limit-units", type=int, default=0,
                        help="cap units per component (0 = no cap); affects the candidate delta cost")
    parser.add_argument("--no-delta", action="store_true", help="coverage and expansion counts only")
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--md", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.components:
        roots = [args.corpus / name for name in args.components]
    else:
        roots = sorted(p for p in args.corpus.iterdir() if p.is_dir() and (p / ".git").exists())
    reports = []
    for root in roots:
        print("... " + root.name, file=sys.stderr)
        reports.append(measure(root, not args.no_delta, args.limit_units))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"components": reports}, indent=2))
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(render_markdown(reports))
    if not args.json and not args.md:
        print(json.dumps({"components": reports}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
