#!/usr/bin/env python3
"""Read exact snapshot's SDK prebuilt declaration and implementation references."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

BASE = Path("/home/deepsleep/c-line-c1-profile-20261018/openharmony-git-archive-20261019")
CONFIG = BASE / "build/prebuilts_config.json"


def main() -> int:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    sdk = [item for item in config.get("tool_list", []) if "sdk" in item.get("name", "").lower()]
    matches = []
    for root in (BASE / "build", BASE / "prebuilts", BASE / "web", BASE / "developtools"):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in {".py", ".json", ".gni", ".gn", ".sh"}:
                continue
            try:
                data = path.read_bytes()
                text = data.decode("utf-8", "replace")
            except OSError:
                continue
            if any(term in text for term in ("download_sdk", "ohos-sdk-full-linux", "26.0.1", "sdk_info.json")):
                matches.append({
                    "path": path.relative_to(BASE).as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "matching_lines": [line.strip()[:400] for line in text.splitlines()
                                       if any(term in line for term in ("download_sdk", "ohos-sdk-full-linux", "26.0.1", "sdk_info.json"))][:30],
                })
    print(json.dumps({"sdk_config": sdk, "matching_sources": matches[:80]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
