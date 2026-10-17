"""Count each shape the six silent rules key on, over whole corpora.

交付项 4 的普查只在报告声明的**已扫描路径**上计数，所以一个 0 有两种读法：
语料里没有这个形状，或者形状在语料里但落在扫描范围之外。这里在**全部**
C/C++ 文件上匹配，把两种读法分开 -- 而且对每一份语料都用同一个方法，
这样"30 组件"与"新 12 组件"两列才可比。

A reported 0 is only meaningful next to the denominators, so every row carries
the number of components the shape was found in and the file/line denominators
are printed once for the run. Purely a reader: no artifact is written, the
corpora are third-party source read with `-I`.

用法（-I：语料是自己不认识的第三方源码）:
  python3 -I widen_shape_census.py <label>=<corpus-root> [<label>=<root> ...]
"""
import collections
import os
import re
import sys

SHAPES = {
    "RewindRead( 本身": re.compile(r"\bRewindRead\s*\("),
    "RewindRead(<含减号>)": re.compile(r"\bRewindRead\s*\([^;]{0,300}-"),
    "Verify*Token( 本身": re.compile(r"\bVerify(?:Access|Native)Token\s*\("),
    "GetCallingUid 本身": re.compile(r"\bGetCalling(?:Uid|UID|uid)\s*\("),
    "identity-domain 组合 Verify*Token(...GetCallingUid...)":
        re.compile(r"\bVerify(?:Access|Native)Token\s*\([^;)]*GetCalling(?:Uid|UID|uid)\s*\("),
    "caller-class 具名调用": re.compile(
        r"\b(GetReqPermissions|StartUsingPermissionCallback|RemovePermissionUsedRecords"
        r"|GetPermissionUsedRecordsAsync|IsAllowedUsingPermission|SetMutePolicy)\s*\("),
    "copy_calls": re.compile(
        r"\b(memcpy|memmove|memcpy_s|memmove_s|ReadRawData|ReadBuffer)\s*\("),
    "copy 实参里含 Read*": re.compile(
        r"\b(memcpy|memmove|memcpy_s|memmove_s|ReadRawData|ReadBuffer)\s*\([^;]{0,300}\bRead[A-Za-z]*\s*\("),
    "owner_calls": re.compile(r"\b(GetOwnerUid|GetOwnerUID|GetResourceOwnerUid)\s*\("),
}

EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}

# The detector's own production-segment list (audit.py's `--exclude` defaults).
# Excluding only `test`/`tests` is not enough: a mock under `unittest/` forwards to
# the real reader and matches shapes production code never matches, so a census
# with the narrower list overcounts. Matching the list here is what makes a
# whole-corpus count comparable to the detector's scope.
EXCLUDED_SEGMENTS = {
    "test", "tests", "unittest", "unittests", "fuzztest", "fuzz",
    "mock", "mocks", "sample", "samples", "example", "examples",
    "demo", "demos", "benchmark", "benchmarks",
    "third_party", "thirdparty", "3rdparty",
}


def scan(root):
    """Per-shape counts and the set of component directories each shape appears in."""
    per = collections.defaultdict(collections.Counter)
    files = lines = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d.lower() not in EXCLUDED_SEGMENTS and d != ".git"]
        top = os.path.relpath(dirpath, root).split(os.sep)[0]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in EXTS:
                continue
            try:
                text = open(os.path.join(dirpath, fn), encoding="utf-8",
                            errors="replace").read()
            except OSError:
                continue
            files += 1
            lines += text.count("\n")
            for label, pat in SHAPES.items():
                n = len(pat.findall(text))
                if n:
                    per[label][top] += n
    return per, files, lines


def main():
    groups = []
    for arg in sys.argv[1:]:
        label, _, root = arg.partition("=")
        if not root or not os.path.isdir(root):
            raise SystemExit("expected <label>=<existing-root>, got: " + arg)
        groups.append((label, root))

    results, metrics = {}, []
    for label, root in groups:
        per, files, lines = scan(root)
        results[label] = per
        metrics.append((label, root, files, lines))
        print("%-14s %-46s files=%-6d lines=%d" % (label, root, files, lines))

    print()
    for shape in SHAPES:
        row = []
        for label, _ in groups:
            per = results[label]
            row.append("%s: total=%-5d comps=%d"
                       % (label, sum(per[shape].values()), len(per[shape])))
        print("%-52s %s" % (shape, "   |   ".join(row)))

    print("\n-- where the shape was found (top components per group) --")
    for shape in SHAPES:
        for label, _ in groups:
            per = results[label]
            if not per[shape]:
                continue
            top = ", ".join("%s:%d" % (c, n) for c, n in per[shape].most_common(5))
            print("%-52s %-14s %s" % (shape, label, top))


if __name__ == "__main__":
    main()
