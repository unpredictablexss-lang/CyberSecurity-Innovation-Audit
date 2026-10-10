"""Verify the shared_ptr_race synthetic fixture manifest and source units.

This is a deterministic read-only experiment. It does not run the detector or
infer any vulnerability status.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from src.ohscanner.fixture import snapshot_digest
from tests.detectors.shared_ptr_race_fixture_support import (
    SHARED_PTR_RACE_FIXTURES,
    load_manifest,
    load_shared_ptr_race_units,
)


def build_summary() -> dict:
    manifest = load_manifest(SHARED_PTR_RACE_FIXTURES)
    units = load_shared_ptr_race_units()
    declared = manifest["provenance"].get("snapshot_sha256")
    actual = snapshot_digest(units)
    if declared != actual:
        raise ValueError("shared_ptr_race fixture snapshot hash mismatch")
    def category_prefix(category: str) -> str:
        for prefix in (
            "vulnerable",
            "fixed",
            "unrelated",
            "safe",
            "unknown",
            "not_applicable",
        ):
            if category.startswith(prefix):
                return prefix
        raise ValueError(f"unsupported fixture category: {category}")

    categories = Counter(
        category_prefix(item["fixture_category"])
        for item in manifest["units"]
    )
    parse_statuses = Counter(unit.parse_status for unit in units)
    languages = Counter(unit.language for unit in units)
    return {
        "schema_version": manifest["schema_version"],
        "fixture_dir": str(SHARED_PTR_RACE_FIXTURES.relative_to(Path.cwd())),
        "snapshot_sha256": declared,
        "unit_count": len(units),
        "categories": dict(sorted(categories.items())),
        "parse_statuses": dict(sorted(parse_statuses.items())),
        "languages": dict(sorted(languages.items())),
    }


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    summary = build_summary()
    text = json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
    if args.json_out is None:
        print(text, end="")
        return 0
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(text, encoding="utf-8")
    print(f"[OK] wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
