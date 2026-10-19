"""Replay pinned Git endpoints in separate processes to isolate parser state.

This is a static candidate regression only. Each endpoint is scanned in a fresh
Python process because the historical in-process two-endpoint command can crash
inside Tree-sitter/macro expansion on this component.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector

from research.experiments.interface.ipc.replay_pinned_git_pair import git, validate_commit

_CHILD = r'''
import json, sys
from pathlib import Path
from research.experiments.interface.ipc.replay_pinned_git_pair import git, replay_side
repo=Path(sys.argv[1])
repository=sys.argv[2]
commit=sys.argv[3]
paths=sys.argv[4:]
tree=git(repo,"rev-parse",commit+"^{tree}").decode().strip()
result=replay_side(repo,repository,commit,tree,paths)
print(json.dumps(result,sort_keys=True))
'''

def isolated_side(repo, repository, commit, paths):
    completed=subprocess.run(
        [sys.executable,"-c",_CHILD,str(repo),repository,commit,*paths],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if completed.returncode:
        raise RuntimeError("isolated replay failed for " + commit + ": "
                           + completed.stderr[-4000:])
    return json.loads(completed.stdout)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo-dir",type=Path,required=True)
    parser.add_argument("--repository",required=True)
    parser.add_argument("--vulnerable",required=True)
    parser.add_argument("--fixed",required=True)
    parser.add_argument("--include",action="append",required=True)
    parser.add_argument("--json-out",type=Path,required=True)
    args=parser.parse_args()
    repo=args.repo_dir.resolve()
    vulnerable_tree=validate_commit(repo,args.vulnerable)
    fixed_tree=validate_commit(repo,args.fixed)
    result={
        "schema_version":1,
        "experiment":"pinned_git_disclosure_pair_replay_isolated",
        "detector_id":"ohscanner.interface.ipc",
        "detector_version":IpcInterfaceDetector.version,
        "model_version":IpcInterfaceDetector.model_version,
        "repository":args.repository,
        "scope":args.include,
        "product_or_exploit_validation":False,
        "vulnerable":isolated_side(repo,args.repository,args.vulnerable,args.include),
        "fixed":isolated_side(repo,args.repository,args.fixed,args.include),
    }
    args.json_out.parent.mkdir(parents=True,exist_ok=True)
    args.json_out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({
        "json_out":str(args.json_out),
        "vulnerable":{"status":result["vulnerable"]["status"],
            "parse":result["vulnerable"]["parse_counts"],"findings":result["vulnerable"]["finding_count"]},
        "fixed":{"status":result["fixed"]["status"],
            "parse":result["fixed"]["parse_counts"],"findings":result["fixed"]["finding_count"]},
    },indent=2))

if __name__=="__main__":
    main()
