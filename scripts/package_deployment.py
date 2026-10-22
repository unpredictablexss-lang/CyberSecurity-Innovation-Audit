"""Export the committed runtime source and curated local knowledge, without dev data.

Usage: python scripts/package_deployment.py --output /path/ohscanner-source.zip
Only committed Git objects are exported; no working tree environments or secrets.
"""
import argparse
import json
from pathlib import Path
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ref", default="HEAD")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", "--end-of-options", args.ref + "^{commit}"],
        cwd=root, text=True).strip()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    paths = ["src", "web", "scripts", "config", "rules", "models", "docker", "validation",
             "docs", "samples", "requirements.txt", "requirements-web.txt", "README.md",
             "AGENTS.md", "deploy-linux.sh", "deploy-windows.ps1", "deploy-windows.cmd",
             "research/deliveries/OHScanner结项交付_20261021/实验材料包"]
    subprocess.run(["git", "archive", "--format=zip", "--prefix=OHScanner/",
                    "--output=" + str(output), commit, *paths], cwd=root, check=True)
    manifest = {"source_commit": commit, "kind": "runtime_source",
                "prebuilt_dependencies": False, "curated_local_knowledge": True,
                "excluded": ["git history", "development tests", "historical research outside curated knowledge",
                             "environments", "node_modules", "dist", "local database", "local settings"]}
    with zipfile.ZipFile(output, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("OHScanner/DEPLOYMENT_SOURCE.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    print(json.dumps({"output": str(output), "bytes": output.stat().st_size,
                      "source_commit": commit}, indent=2))


if __name__ == "__main__":
    main()
