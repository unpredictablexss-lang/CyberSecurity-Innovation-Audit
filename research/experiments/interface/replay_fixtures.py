"""Offline synthetic research replay, not a second product scanning CLI."""
import json
from pathlib import Path

from src.ohscanner.detectors.interface.permission_prototype import analyze


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    results = []
    for path in sorted((root / "research/corpus/interface/fixtures").glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        result = analyze(case)
        if result["assessment"] != case["expected_assessment"]:
            raise ValueError(f"fixture mismatch: {path.name}")
        results.append(result)
    out = root / "outputs/reports"
    out.mkdir(parents=True, exist_ok=True)
    (out / "synthetic_replay.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Replayed {len(results)} synthetic fixtures; validated_vulnerability=0")
