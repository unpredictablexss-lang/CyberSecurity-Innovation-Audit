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


def workspace_path(value, workspace_root):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("workspace paths must be non-empty strings")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = workspace_root / path
    return path.resolve()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.home() / "ohscanner")
    parser.add_argument("command", choices=("doctor", "start", "check", "build"))
    args = parser.parse_args()
    root = args.workspace.expanduser().resolve()
    cfg = json.loads((root / "config/local.json").read_text())
    app = workspace_path(cfg["app"], root)
    python = workspace_path(cfg["python"], root)
    node_bin_value = cfg.get("node_bin")
    node_bin = workspace_path(node_bin_value, root) if node_bin_value else None
    data = workspace_path(cfg["data"], root)
    target_roots = [workspace_path(path, root) for path in cfg["target_roots"]]
    env = os.environ.copy()
    if node_bin:
        env["PATH"] = str(node_bin) + os.pathsep + env.get("PATH", "")
    env["OHSCANNER_DATA"] = str(data)
    env["OHSCANNER_TARGET_ROOTS"] = os.pathsep.join(map(str, target_roots))
    url = "http://127.0.0.1:" + str(int(cfg["port"])) + "/api/v1/health"

    def health():
        try:
            # Do not send local health through HTTP_PROXY/HTTPS_PROXY.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url, timeout=2) as response:
                return json.load(response)
        except (OSError, urllib.error.URLError, ValueError):
            return None

    required = [app, python, data]
    if node_bin:
        required.append(node_bin / "node")
    elif not shutil.which("node", path=env["PATH"]):
        required.append(Path("node (not found in PATH)"))
    if not shutil.which("npm", path=env["PATH"]):
        required.append(Path("npm (not found in PATH)"))
    required.extend(target_roots)
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
                    "data": str(data),
                    "target_roots": list(map(str, target_roots)),
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
