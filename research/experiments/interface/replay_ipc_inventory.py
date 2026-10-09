"""Fixed-manifest offline entry/permission research; no arbitrary target runner."""
import json
from pathlib import Path

from research.experiments.interface.verify_sources import verify
from src.ohscanner.detectors.interface.ipc_repository import RepositoryIndex


def replay(root):
    root = Path(root)
    manifest_path = root / "research/corpus/interface/mmi_source_manifest.json"
    source_root = root / "research/experiments/interface/local_sources"
    verified = verify(manifest_path, source_root)
    sources = {row["file"]: (source_root / row["file"]).read_bytes()
               for row in verified["verified_files"] if row["file"].endswith((".h", ".cpp"))}
    return RepositoryIndex(sources, verified["repository"], verified["commit"]).inventory()


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    result = replay(root)
    out = root / "outputs/reports"
    out.mkdir(parents=True, exist_ok=True)
    (out / "ipc_repository_inventory.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Source-derived IPC entries:", len(result["entries"]))
    for entry in result["entries"]:
        if entry["requirements"]:
            print(entry["entry"]["handler"], json.dumps(entry["requirements"], ensure_ascii=False))
