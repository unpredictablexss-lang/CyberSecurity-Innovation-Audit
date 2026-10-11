"""Probe: does macro expansion change what `entry_index` sees?

`analysis.Interpreter` re-parses the *expanded* source, but `EntryIndex` parses the
*raw* source. If an expansion rewrites a class name or a dispatcher's owner, the two
disagree and a dispatch-derived root can silently vanish. This probe builds both
indexes and reports the difference, so the answer is measured rather than argued.

Usage:
  .venv/bin/python research/experiments/interface/ipc/probe_entry_index_expansion.py \
      --corpus ~/openharmony-audit/perf-corpus --components communication_ipc
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from src.ohscanner.detectors.interface.cpp_macros import catalog_for_units, expand_with_catalog
from src.ohscanner.detectors.interface.entry_index import EntryIndex
from src.ohscanner.detectors.interface.models import IpcPolicy

SOURCE_SUFFIXES = (".cpp", ".cc", ".cxx", ".c", ".h", ".hh", ".hpp", ".inl")
SKIPPED_DIRS = ("/test/", "/unittest/", "/fuzztest/")


class Unit:
    def __init__(self, path, text, language):
        self.path, self.text, self.language = path, text, language
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


def expanded_units(units, catalog):
    result, changed = [], 0
    for unit in units:
        expansion = expand_with_catalog(unit.text.encode("utf-8"), catalog)
        if expansion.applied:
            changed += 1
            result.append(Unit(unit.path, expansion.source.decode("utf-8"), unit.language))
        else:
            result.append(Unit(unit.path, unit.text, unit.language))
    return result, changed


def fingerprint(index):
    roots = {(owner, name) for owner, name, _ in index.root_bindings()}
    entries = {(e.dispatcher, e.handler) for e in index.entries}
    return roots, entries


def measure(component_dir, policy):
    units = load_units(component_dir)
    catalog, _, _, _ = catalog_for_units(units, 400, 6_000_000)
    expanded, changed = expanded_units(units, catalog)
    raw_roots, raw_entries = fingerprint(EntryIndex(units, policy))
    new_roots, new_entries = fingerprint(EntryIndex(expanded, policy))
    return {
        "component": component_dir.name, "units": len(units), "files_expanded": changed,
        "roots_before": len(raw_roots), "roots_after": len(new_roots),
        "roots_lost": sorted("/".join(pair) for pair in raw_roots - new_roots),
        "roots_gained": sorted("/".join(pair) for pair in new_roots - raw_roots),
        "entries_before": len(raw_entries), "entries_after": len(new_entries),
        "entries_lost": sorted("/".join(pair) for pair in raw_entries - new_entries),
        "entries_gained": sorted("/".join(pair) for pair in new_entries - raw_entries),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=Path.home() / "openharmony-audit" / "perf-corpus")
    parser.add_argument("--components", nargs="*", default=None)
    args = parser.parse_args(argv)
    roots = ([args.corpus / name for name in args.components] if args.components
             else sorted(p for p in args.corpus.iterdir() if p.is_dir() and (p / ".git").exists()))
    report = []
    for root in roots:
        entry = measure(root, IpcPolicy())
        report.append(entry)
        print("... " + root.name + ": roots " + str(entry["roots_before"]) + "->" + str(entry["roots_after"])
              + " (lost " + str(len(entry["roots_lost"])) + "), entries "
              + str(entry["entries_before"]) + "->" + str(entry["entries_after"])
              + " (lost " + str(len(entry["entries_lost"])) + ")", file=sys.stderr)
    print(json.dumps({"components": report}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
