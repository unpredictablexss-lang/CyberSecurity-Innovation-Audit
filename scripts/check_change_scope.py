"""Check committed, staged, unstaged and untracked paths against baseline ownership.

This is a delivery check, not a security boundary. The integrator must provide a
trusted full base SHA; policy is read from that commit, never from the worktree.
"""
import argparse
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
import subprocess

POLICY_PATH = "config/collaboration/ownership.json"


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def changed_paths(repo, base):
    # Disable rename detection so BOTH source deletion and destination addition
    # are checked, including an unstaged move across ownership boundaries.
    paths = set()
    for args in (("diff", "--name-only", "--no-renames", "-z", base, "HEAD", "--"),
                 ("diff", "--name-only", "--no-renames", "-z", "HEAD", "--"),
                 ("diff", "--cached", "--name-only", "--no-renames", "-z", "--"),
                 ("ls-files", "--others", "--exclude-standard", "-z")):
        paths.update(p.decode("utf-8") for p in git(repo, *args).split(b"\0") if p)
    return sorted(paths)


def violations(paths, policy, lane):
    allowed = policy["lanes"][lane]["allowed"]
    shared = policy["shared_owner_only"]
    return [p for p in paths if any(fnmatchcase(p, pattern) for pattern in shared)
            or not any(fnmatchcase(p, pattern) for pattern in allowed)]


def check(repo, base, lane):
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        raise ValueError("--base must be the integrator's full 40-character commit SHA")
    git(repo, "merge-base", "--is-ancestor", base, "HEAD")
    policy = json.loads(git(repo, "show", base + ":" + POLICY_PATH))
    if lane not in policy["lanes"]:
        raise ValueError("unknown lane: " + lane)
    paths = changed_paths(repo, base)
    return {"base": base, "lane": lane, "checked_paths": paths,
            "violations": violations(paths, policy, lane)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--lane", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        result = check(args.repo.resolve(), args.base, args.lane)
    except (ValueError, KeyError, subprocess.CalledProcessError) as exc:
        parser.exit(2, "scope check failed: " + str(exc) + "\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(bool(result["violations"]))


if __name__ == "__main__":
    raise SystemExit(main())
