"""Local workspace commands. Never fetch, merge, delete or migrate user data."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.error
import urllib.request


def run(argv, cwd, env=None):
    return subprocess.run(argv, cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.home() / "ohscanner")
    parser.add_argument("command", choices=("doctor", "start", "check", "build"))
    args = parser.parse_args()
    root = args.workspace.expanduser().resolve()
    cfg = json.loads((root / "config/local.json").read_text())
    app = Path(cfg["app"])
    python = Path(cfg["python"])
    node_bin = Path(cfg["node_bin"])
    env = os.environ.copy()
    env["PATH"] = str(node_bin) + os.pathsep + env.get("PATH", "")
    env["OHSCANNER_DATA"] = cfg["data"]
    env["OHSCANNER_TARGET_ROOTS"] = os.pathsep.join(cfg["target_roots"])
    url = "http://127.0.0.1:" + str(int(cfg["port"])) + "/api/v1/health"

    def health():
        try:
            # Do not send local health through HTTP_PROXY/HTTPS_PROXY.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url, timeout=2) as response:
                return json.load(response)
        except (OSError, urllib.error.URLError, ValueError):
            return None

    required = [app, python, node_bin / "node", Path(cfg["data"])]
    required.extend(Path(p) for p in cfg["target_roots"])
    missing = [str(p) for p in required if not p.exists()]
    if args.command == "doctor":
        repo = subprocess.run(
            ["git", "-C", str(app), "status", "--short", "--branch"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        disk = shutil.disk_usage(root)
        print(
            json.dumps(
                {
                    "workspace": str(root),
                    "app": str(app),
                    "git": repo.stdout.strip(),
                    "git_error": repo.stderr.strip(),
                    "missing": missing,
                    "data": cfg["data"],
                    "target_roots": cfg["target_roots"],
                    "health": health(),
                    "free_bytes": disk.free,
                    "note": "Local check only; no fetch, branch switch or data modification.",
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        if missing or repo.returncode:
            raise SystemExit(1)
        return
    if missing:
        raise SystemExit("Missing configured paths: " + ", ".join(missing))
    if args.command == "start":
        current = health()
        if current:
            if current.get("worker_running"):
                print("Already running: http://localhost:" + str(cfg["port"]))
                return
            raise SystemExit(
                "API exists but Worker is absent; inspect existing service first."
            )
        if not (app / "web/dist/index.html").is_file():
            raise SystemExit("Build UI first: ~/ohscanner/bin/oh build")
        os.chdir(app)
        os.execve(
            str(python),
            [
                str(python),
                "-m",
                "src.workbench",
                "serve",
                "--port",
                str(cfg["port"]),
            ],
            env,
        )
    elif args.command == "check":
        run([str(python), "-m", "unittest", "discover", "-s", "tests", "-q"], app, env)
        run(["git", "diff", "--check"], app, env)
    elif args.command == "build":
        npm = shutil.which("npm", path=env["PATH"])
        if not npm:
            raise SystemExit("npm missing in configured Node environment")
        run([npm, "ci", "--no-audit", "--no-fund"], app / "web", env)
        run([npm, "run", "build"], app / "web", env)


if __name__ == "__main__":
    main()
