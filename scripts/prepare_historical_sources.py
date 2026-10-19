"""Explicitly fetch pinned historical commits and affected blobs into local repos.

Unlike benchmark readers, this preparation command intentionally uses the
network. It does not checkout revisions or modify target implementation files.
Run: python -m scripts.prepare_historical_sources --target-root /path/to/repos
"""

import argparse
import hashlib
import json
import os
import signal
import subprocess
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

from src.benchmark.historical import load_sample, _git


def fetch(repo, object_ids, remote="origin"):
    command = ["git", "-c", "http.version=HTTP/1.1", "-C", str(repo), "fetch", "--no-tags", "--filter=blob:none",
               "--depth=2", remote, *object_ids]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=os.name != "nt")
    try:
        stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        raise RuntimeError("Explicit source fetch exceeded 45 seconds")
    if process.returncode:
        raise RuntimeError(stderr.strip() or stdout.strip())
    return {"command": command, "stdout": stdout, "stderr": stderr}


def prepare(sample_path, target_root, raw_only=False, remote="origin"):
    sample = load_sample(sample_path)
    repo = target_root / sample.repository.rsplit("/", 1)[-1]
    if not repo.is_dir():
        raise ValueError(f"target repository is absent: {repo}")
    origin = _git(repo, ["remote", "get-url", "origin"]).stdout.strip().rstrip("/")
    if origin.endswith(".git"):
        origin = origin[:-4]
    if not (origin.lower().endswith("/" + sample.repository.lower()) or
            origin.lower().endswith(":" + sample.repository.lower())):
        raise ValueError("target origin does not match the sample repository")
    head = _git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    records = [] if raw_only else [fetch(repo, [sample.vulnerable_commit, sample.fixed_commit], remote)]
    blobs = set()
    for commit in (sample.vulnerable_commit, sample.fixed_commit):
        for file in sample.affected_files:
            tree = _git(repo, ["ls-tree", commit, "--", file]).stdout.strip()
            if not tree or tree.split()[1] != "blob":
                raise ValueError(f"affected source is absent at {commit}: {file}")
            blobs.add(tree.split()[2])
            expected = tree.split()[2]
            if raw_only and _git(repo, ["cat-file", "-e", expected], check=False).returncode:
                url = f"https://raw.githubusercontent.com/{sample.repository}/{commit}/{quote(file)}"
                with urlopen(url, timeout=15) as response:
                    content = response.read()
                actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
                if actual != expected:
                    raise ValueError(f"raw source Git blob hash mismatch: {file}")
                process = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                                         input=content, capture_output=True, check=True, timeout=10)
                if process.stdout.decode().strip() != expected:
                    raise ValueError("imported source blob identity mismatch")
                records.append({"url": url, "verified_blob": expected, "bytes": len(content)})
    missing = [blob for blob in sorted(blobs) if _git(repo, ["cat-file", "-e", blob], check=False).returncode]
    if missing:
        records.append(fetch(repo, missing, remote))
    for commit in (sample.vulnerable_commit, sample.fixed_commit):
        for file in sample.affected_files:
            _git(repo, ["show", f"{commit}:{file}"])
    if _git(repo, ["rev-parse", "HEAD"]).stdout.strip() != head:
        raise ValueError("source preparation changed target HEAD")
    return {"sample_id": sample.sample_id, "repo": str(repo), "status": "prepared",
            "head_unchanged": head, "fetched_blobs": missing, "fetches": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--raw-only", action="store_true", help="Verify raw sources against existing pinned Git trees")
    parser.add_argument("--remote-url", default="origin", help="Explicit alternate transport; origin stays unchanged")
    args = parser.parse_args()
    try:
        result = prepare(args.sample.resolve(), args.target_root.resolve(), args.raw_only, args.remote_url)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result = {"sample": str(args.sample), "status": "failed", "reason": str(error)}
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.log.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[{result['status']}] {args.sample.stem}")
    if result["status"] != "prepared":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
