"""Run one family PoC end to end and write its record.

The PoC module lives in `src/ohscanner/poc`; this script is the research-level
driver for it. It builds the pinned revisions of the target translation unit,
runs each case under a sanitizer, replays the attack case, and writes the record.

Usage:
  .venv/bin/python research/experiments/interface/poc/run_poc.py \
      --json outputs/reports/poc_auth01_descriptor_bypass.json \
      --md   outputs/reports/poc_auth01_descriptor_bypass.md
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from src.ohscanner.poc import render_markdown, run_poc  # noqa: E402

PROJECT = Path(__file__).resolve().parents[4]
DEFAULT_MANIFEST = (PROJECT / "src/ohscanner/poc/harnesses"
                    / "auth01_descriptor_bypass/manifest.json")
DEFAULT_GIT = Path.home() / "openharmony-audit" / "ipc-research" / "repos" / "inputmethod_imf"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--git-dir", type=Path, default=DEFAULT_GIT,
                        help="local git object store holding the pinned revisions")
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp/ohscan-poc-auth01"))
    parser.add_argument("--compiler", default="clang++")
    parser.add_argument("--cutils", type=Path, default=None,
                        help="local commonlibrary_c_utils checkout supplying the real Parcel")
    parser.add_argument("--repeat", type=int, default=3, help="stability replay count")
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--md", type=Path, default=None)
    args = parser.parse_args()

    result = run_poc(args.manifest, args.git_dir, args.work_dir,
                     compiler=args.compiler, cutils_dir=args.cutils, repeats=args.repeat)

    for name, run in result.revisions.items():
        print(f"{name:11s} commit={run.commit[:12]} build={'ok' if run.build.ok else 'FAILED'} "
              f"state={run.state} replay={run.replay['label']} "
              f"({run.replay['triggered']}/{run.replay['attempts']})", flush=True)
        for case in run.cases:
            signals = " ".join(f"{k}={v}" for k, v in sorted(case.signals.items()))
            met = run.expectations_met.get(case.case_id)
            print(f"    {case.case_id:14s} {case.role:8s} verdict={case.verdict:10s} "
                  f"expected={'ok' if met else 'MISMATCH'} | {signals}", flush=True)
        if not run.build.ok:
            print("    build stderr:", run.build.stderr[-800:], flush=True)

    print(f"state={result.state} evidence={result.evidence_level}", flush=True)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n")
        print("wrote", args.json, flush=True)
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(render_markdown(result))
        print("wrote", args.md, flush=True)


if __name__ == "__main__":
    main()
