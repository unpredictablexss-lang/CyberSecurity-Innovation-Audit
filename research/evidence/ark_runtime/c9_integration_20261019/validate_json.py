#!/usr/bin/env python3
"""Validate tracked JSON files without modifying them."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--files-from", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.root)
    names = Path(args.files_from).read_text(encoding="utf-8").splitlines()
    results = []
    for name in names:
        path = root / name
        try:
            with path.open("r", encoding="utf-8") as handle:
                json.load(handle)
            status, error = "pass", None
        except Exception as exc:
            status, error = "fail", f"{type(exc).__name__}: {exc}"
        results.append({"path": name, "status": status, "error": error})
    payload = {
        "schema": "c9-tracked-json-validation/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "file_count": len(results),
        "passed": sum(row["status"] == "pass" for row in results),
        "failed": sum(row["status"] == "fail" for row in results),
        "results": results,
    }
    Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: payload[key] for key in ("file_count", "passed", "failed")}, indent=2))
    return 0 if payload["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
