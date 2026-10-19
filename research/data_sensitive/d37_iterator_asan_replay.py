from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "research/data_sensitive"
CASES = {
    "unterminated_full_length": DATA / "D37_CVE_2026_28751_ASAN.cpp",
    "extra_byte_terminator_control": DATA / "D37_CVE_2026_28751_SAFE.cpp",
}


def main() -> int:
    compiler = subprocess.run(["g++", "--version"], check=True, text=True,
                              stdout=subprocess.PIPE).stdout.splitlines()[0]
    result = {"schema": 1, "compiler": compiler, "runs_per_case": 3, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="ohscanner-d37-asan-") as tmp:
        for label, source in CASES.items():
            binary = Path(tmp) / label
            subprocess.run(["g++", "-std=c++17", "-O1", "-g", "-fsanitize=address",
                            "-fno-omit-frame-pointer", str(source), "-o", str(binary)],
                           check=True)
            runs = []
            for _ in range(3):
                proc = subprocess.run([str(binary)], stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True,
                                      env={**os.environ, "ASAN_OPTIONS": "halt_on_error=1"})
                overflow = "ERROR: AddressSanitizer: heap-buffer-overflow" in proc.stdout
                if label == "unterminated_full_length" and not overflow:
                    raise AssertionError("unterminated full-length value did not trigger ASan")
                if label == "extra_byte_terminator_control" and (proc.returncode != 0 or overflow):
                    raise AssertionError("safe extra-byte control failed or triggered ASan")
                runs.append({
                    "exit_code": proc.returncode,
                    "asan_heap_buffer_overflow": overflow,
                    "output_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
                    "output_excerpt": next((line.strip() for line in proc.stdout.splitlines()
                                            if "ERROR: AddressSanitizer:" in line), "clean"),
                })
            result["cases"][label] = {
                "source": str(source.relative_to(ROOT)),
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "expected": "3/3 heap-buffer-overflow" if label == "unterminated_full_length"
                            else "0/3 sanitizer errors",
                "runs": runs,
            }
    output = DATA / "D37_CVE_2026_28751_ASAN_REPLAY.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "results": {
        label: [sum(run["asan_heap_buffer_overflow"] for run in case["runs"]),
               len(case["runs"])]
        for label, case in result["cases"].items()
    }}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
