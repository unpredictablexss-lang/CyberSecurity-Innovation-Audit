from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "research/data_sensitive"
FILES = {
    "iterator_escape": DATA / "D36_CVE_2026_28733_ITERATOR_ASAN.cpp",
    "safe_update": DATA / "D36_CVE_2026_28733_ITERATOR_SAFE.cpp",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    version = subprocess.run(["g++", "--version"], check=True, text=True,
                             stdout=subprocess.PIPE).stdout.splitlines()[0]
    result = {"schema": 1, "compiler": version, "runs_per_case": 3, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="ohscanner-d36-asan-") as tmp:
        for name, source in FILES.items():
            binary = Path(tmp) / name
            subprocess.run([
                "g++", "-std=c++17", "-O1", "-g", "-fsanitize=address",
                "-fno-omit-frame-pointer", str(source), "-o", str(binary),
            ], check=True)
            runs = []
            for _ in range(3):
                proc = subprocess.run(
                    [str(binary)], text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env={**os.environ, "ASAN_OPTIONS": "halt_on_error=1"},
                )
                uaf = "ERROR: AddressSanitizer: heap-use-after-free" in proc.stdout
                if name == "iterator_escape" and not uaf:
                    raise AssertionError("iterator-escape model did not produce the expected ASan UAF")
                if name == "safe_update" and (proc.returncode != 0 or uaf):
                    raise AssertionError("safe update control failed or produced an ASan UAF")
                runs.append({
                    "exit_code": proc.returncode,
                    "asan_heap_use_after_free": uaf,
                    "output_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
                    "output_excerpt": next((line.strip() for line in proc.stdout.splitlines()
                                            if "ERROR: AddressSanitizer:" in line), "clean"),
                })
            result["cases"][name] = {
                "source": str(source.relative_to(ROOT)),
                "source_sha256": sha256(source),
                "runs": runs,
                "expected": "3/3 ASan heap-use-after-free" if name == "iterator_escape"
                            else "0/3 ASan errors",
            }
    output = DATA / "D36_CVE_2026_28733_ASAN_REPLAY.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "results": {
        name: [sum(run["asan_heap_use_after_free"] for run in item["runs"]), len(item["runs"])]
        for name, item in result["cases"].items()
    }}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
