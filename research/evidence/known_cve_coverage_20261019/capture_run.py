from __future__ import annotations
import json, os, pathlib, subprocess, sys, time
name, cwd = sys.argv[1], pathlib.Path(sys.argv[2])
argv = sys.argv[3:]
env = os.environ.copy()
started = time.time()
proc = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
duration = round(time.time() - started, 6)
(cwd / "research/evidence/known_cve_coverage_20261019" / f"{name}_stdout.txt").write_bytes(proc.stdout)
(cwd / "research/evidence/known_cve_coverage_20261019" / f"{name}_stderr.txt").write_bytes(proc.stderr)
record = {
  "name": name,
  "argv": argv,
  "cwd": str(cwd),
  "environment": {"PYTHONPYCACHEPREFIX": env.get("PYTHONPYCACHEPREFIX")},
  "exit_code": proc.returncode,
  "duration_seconds": duration,
  "stdout_file": f"{name}_stdout.txt",
  "stderr_file": f"{name}_stderr.txt",
  "stdout_bytes": len(proc.stdout),
  "stderr_bytes": len(proc.stderr),
}
(cwd / "research/evidence/known_cve_coverage_20261019" / f"{name}_run.json").write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps(record, ensure_ascii=False))
raise SystemExit(proc.returncode)
