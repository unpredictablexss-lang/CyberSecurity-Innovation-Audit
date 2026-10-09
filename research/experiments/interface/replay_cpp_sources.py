"""Offline research replay of pinned MMI and labeled synthetic C++ sources."""
import json
from pathlib import Path

from research.experiments.interface.verify_sources import verify
from src.ohscanner.detectors.interface.cpp_permission import analyze_cpp


def replay(root):
    root = Path(root)
    results = []
    fixture_dir = root / "research/corpus/interface/cpp_fixtures"
    models = sorted(fixture_dir.glob("*.json"))
    if not models:
        raise ValueError("no synthetic C++ fixtures")
    for path in models:
        model = json.loads(path.read_text(encoding="utf-8"))
        source = (fixture_dir / Path(model["file"]).name).read_bytes()
        result = analyze_cpp(source, model)
        if result["assessment"] != model["expected_assessment"]:
            raise ValueError(f"unexpected fixture result: {path.name}")
        result["data_origin"] = "synthetic_design_fixture"
        results.append(result)
    source_root = root / "research/experiments/interface/local_sources"
    models_path = root / "research/corpus/interface/mmi_cpp_models.json"
    if source_root.exists():
        verify(root / "research/corpus/interface/mmi_source_manifest.json", source_root)
        for model in json.loads(models_path.read_text(encoding="utf-8")):
            source = (source_root / model["file"]).read_bytes()
            result = analyze_cpp(source, model)
            result["data_origin"] = "fixed_mmi_source"
            results.append(result)
    else:
        results.append({"data_origin": "fixed_mmi_source", "status": "blocked",
                        "assessment": "unknown", "reason": "Local third-party source cache not supplied"})
    return results


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    results = replay(root)
    out = root / "outputs/reports"
    out.mkdir(parents=True, exist_ok=True)
    (out / "cpp_source_replay.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    for row in results:
        print(row.get("file", "MMI cache"), row["assessment"], "calls:", len(row.get("calls", [])))
