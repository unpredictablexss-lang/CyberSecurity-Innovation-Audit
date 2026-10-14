"""Run the API and one Worker together; always bind to loopback."""

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description="OHScanner local workbench")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be in 1024..65535")
    root = Path(__file__).resolve().parents[2]
    if not (root / "web" / "dist" / "index.html").is_file():
        parser.error("Web UI is not built; run npm ci && npm run build in web/")
    processes = []

    def stop(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        processes.append(
            subprocess.Popen(
                [sys.executable, "-m", "src.workbench.worker"],
                cwd=root,
                start_new_session=True,
            )
        )
        processes.append(subprocess.Popen(
            [sys.executable, "-m", "src.workbench.operation_worker"], cwd=root, start_new_session=True))
        processes.append(subprocess.Popen(
            [sys.executable, "-m", "src.workbench.operation_worker", "--validation"], cwd=root, start_new_session=True))
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "src.workbench.api:create_app",
                    "--factory",
                    "--no-access-log",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(args.port),
                ],
                cwd=root,
                start_new_session=True,
            )
        )
        print(
            f"OHScanner: http://localhost:{args.port} (API + scan, operation and validation Workers)",
            flush=True,
        )
        while all(p.poll() is None for p in processes):
            time.sleep(0.3)
        raise RuntimeError("API or Worker stopped; inspect the terminal output")
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


if __name__ == "__main__":
    main()
