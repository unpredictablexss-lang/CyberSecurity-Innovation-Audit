"""Count the descriptor-check shapes the AUTH-01 rule actually has to handle.

The rule accepts `descriptor != X::GetDescriptor()` only when X is the enclosing
stub class. This measures, over the audited components, how often real code
writes the interface-qualified form instead.
"""
import re
import subprocess

REPOS = [
    ("security_access_token", "/home/audit/openharmony-audit/perf-corpus/security_access_token",
     "17d88bfb36bea6c9370ba919ac41a22d16dd66b3"),
    ("update_updateservice", "/home/audit/openharmony-audit/perf-corpus/update_updateservice",
     "e4942a33cc5ed29040e5c720bea3b2a8e4a79221"),
    ("window_window_manager", "/home/audit/openharmony-audit/perf-corpus/window_window_manager",
     "8b0d8fe1b973d865904c942c286b3d2a3b9b08e7"),
    ("communication_dsoftbus", "/tmp/newcomp/communication_dsoftbus",
     "652f88e0261ce4d0610f73cc451c26b84d2597af"),
    ("communication_ipc", "/home/audit/openharmony-audit/perf-corpus/communication_ipc",
     "bbb92dbb2f52"),
]

QUALIFIED = re.compile(r"([A-Za-z_][A-Za-z0-9_]*::)+GetDescriptor\(\)")


def grep(repo, sha, pattern):
    out = subprocess.run(
        ["git", "-C", repo, "grep", "-h", "-o", "-E", pattern, sha, "--", "*.cpp"],
        capture_output=True, text=True,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


for name, repo, sha in REPOS:
    try:
        sha = subprocess.run(["git", "-C", repo, "rev-parse", sha],
                             capture_output=True, text=True).stdout.strip() or sha
    except Exception:
        pass
    reads = grep(repo, sha, r"ReadInterfaceToken\(\)")
    compares = grep(repo, sha, r"[!=]= *([A-Za-z_][A-Za-z0-9_]*::)*GetDescriptor\(\)")
    qualified = [c for c in compares if QUALIFIED.search(c)]
    plain = [c for c in compares if not QUALIFIED.search(c)]
    print("%-24s ReadInterfaceToken=%3d  compares=%3d  interface-qualified=%3d  unqualified/self=%3d"
          % (name, len(reads), len(compares), len(qualified), len(plain)))
    for sample in sorted(set(qualified))[:3]:
        print("        qualified e.g.:", sample)
    for sample in sorted(set(plain))[:3]:
        print("        plain     e.g.:", sample)
