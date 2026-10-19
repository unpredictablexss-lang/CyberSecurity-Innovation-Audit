"""Reproduce `catalog_for_units` selection for one component's plan.

Read-only. The interpreter catalogues at most `max_macro_sources` sources,
headers first, then path order, with a byte budget as well
(`models.py:210-212`, `cpp_macros.py:119-141`). A macro defined only in a file
that the budget did not reach stays unexpanded, so a guard written inside it is
not interpreted -- that is the mechanism this reproduces, deterministically,
without running the detector.

Inputs: the plan's path list from a saved report, and blob sizes at the pinned
commit (falling back to the corpus working tree when the object is absent).
"""
import json
import os
import subprocess
import sys

REPORT = sys.argv[1]
CORPUS = sys.argv[2]
WANT = sys.argv[3:]          # paths whose catalogue membership is asked about
MAX_SOURCES = 400
MAX_BYTES = 6_000_000
HEADER_SUFFIX = (".h", ".hh", ".hpp", ".hxx")

rep = json.load(open(REPORT))
commit = rep["commit"]
paths = []
for shard in rep["scope"]["shards"]:
    paths.extend(shard["paths"])


def size_of(path):
    try:
        out = subprocess.run(["git", "-C", CORPUS, "cat-file", "-s", commit + ":" + path],
                             capture_output=True, text=True, timeout=30)
        if out.returncode == 0 and out.stdout.strip().isdigit():
            return int(out.stdout.strip())
    except Exception:
        pass
    try:
        return os.path.getsize(os.path.join(CORPUS, path))
    except OSError:
        return 0


sizes = {p: size_of(p) for p in paths}
ordered = sorted(paths, key=lambda p: (not p.endswith(HEADER_SUFFIX), p))
chosen, total, truncated = [], 0, False
for p in ordered:
    n = sizes[p]
    if len(chosen) >= MAX_SOURCES or total + n > MAX_BYTES:
        truncated = True
        break
    chosen.append(p)
    total += n

headers = sum(1 for p in paths if p.endswith(HEADER_SUFFIX))
print("plan=%d headers=%d  chosen=%d  bytes=%d  truncated=%s"
      % (len(paths), headers, len(chosen), total, truncated))
chosen_set = set(chosen)
for want in WANT:
    if want in chosen_set:
        print("  IN    index=%d  %s" % (chosen.index(want), want))
    else:
        # Where it would have been admitted, had the budget not run out.
        rank = ordered.index(want) if want in ordered else -1
        print("  OUT   order_index=%d  %s" % (rank, want))
print("last admitted:", chosen[-1])
