"""Assemble result.json from the harness output and the pinned-source digests.

Run after build.sh and run.sh:

    python3 assemble.py <build-dir> <detector-vulnerable.json> \
        <detector-fixed.json> <out.json>

Only digests, counts and the harness's own JSON lines are written. No
third-party source is copied into the repository.
"""
import hashlib
import json
import os
import subprocess
import sys

VULNERABLE = "3287e85450f16d3f41801040abe35701131ad6f4"
FIXED = "ddee7c00d97d54423c6168fac994d3ef6204f385"
CUTILS = "3bdc11e00e7bf6e577cee300ad51045ca9958efd"
PASTEBOARD = "openharmony/distributeddatamgr_pasteboard"

SOURCES = {
    "framework/tlv/message_parcel_warp.cpp": "message_parcel_warp.cpp",
    "framework/tlv/message_parcel_warp.h": "message_parcel_warp.h",
    "utils/native/include/pasteboard_hilog.h": "pasteboard_hilog.h",
    "framework/framework/include/api/visibility.h": "api/visibility.h",
}


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def detector_pass(path):
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    return {
        "commit": report["commit"],
        "all_files": report["passes"]["all-files"],
        "complete_ast": report["passes"]["complete-ast"],
    }


def main(build, detector_vulnerable, detector_fixed, out):
    revisions = {}
    for name, commit in (("vulnerable", VULNERABLE), ("fixed", FIXED)):
        target = os.path.join(build, name)
        revisions[name] = {
            "commit": commit,
            "sources": {path: digest(os.path.join(target, local))
                        for path, local in SOURCES.items()},
            "binary_sha256": digest(os.path.join(target, "harness")),
        }
    payload = {
        "schema_version": 1,
        "family": "DATA-02",
        "harness": "pasteboard_read_raw_data_fd",
        "repository": PASTEBOARD,
        "vulnerable_commit": VULNERABLE,
        "fixed_commit": FIXED,
        "fix": "ReadRawData checks AshmemGetSize(fd) >= 0 and size <= actualSize "
               "before mmap; before the fix any descriptor the parcel carried was "
               "mapped for the declared size.",
        "culprit_symbol": "OHOS::MiscServices::MessageParcelWarp::ReadRawData",
        "cutils_commit": CUTILS,
        "revisions": revisions,
        "compiler": subprocess.run(["clang++", "--version"], capture_output=True,
                                   text=True, check=False).stdout.splitlines()[0],
        "kernel": os.uname().release,
        "scenarios": {
            "vulnerable": jsonl(os.path.join(build, "vulnerable.jsonl")),
            "fixed": jsonl(os.path.join(build, "fixed.jsonl")),
        },
        "detector": {
            "vulnerable": detector_pass(detector_vulnerable),
            "fixed": detector_pass(detector_fixed),
            "note": "Both revisions are silent for DATA-01..04. Two causes, both "
                    "observed: (1) the rules key on parcel-derived copies and "
                    "ReadRawData destinations, not on a parcel-carried descriptor "
                    "used as an mmap backing; (2) the call site is "
                    "messageData.ReadRawData(...), and Interpreter.resolve refuses "
                    "a receiver that is not `this` (analysis.py:711-713), so the "
                    "function body is never interpreted. A probe counted "
                    "dest_sites=1/dest_request=1 at the call site and zero "
                    "ReadFileDescriptor/mmap evaluations inside the body. This is a "
                    "false negative of the present rule set, recorded rather than "
                    "removed.",
        },
        "validated_vulnerability": 0,
        "reachability": {
            "status": "partial",
            "summary": "ReadRawData is the function the pasteboard TLV layer calls on "
                       "the receiving side. The harness calls it directly; which "
                       "process can put a descriptor into that parcel, and what "
                       "privilege it holds, is not established here.",
        },
    }
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(json.dumps({"out": out,
                      "vulnerable": payload["scenarios"]["vulnerable"],
                      "fixed": payload["scenarios"]["fixed"]}, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: assemble.py <build-dir> <dv.json> <df.json> <out.json>")
    main(*sys.argv[1:])
