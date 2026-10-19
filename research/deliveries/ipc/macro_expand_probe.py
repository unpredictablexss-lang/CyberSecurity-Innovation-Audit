"""Expand the real hcamera_service.cpp through the real expander.

Read-only. Builds the same catalogue `catalog_for_units` would build for this
component's plan (same budget, same order), expands the file that holds the
surviving candidate, and prints the expanded text of the guard call and of the
sensitive call. This answers one question with source: what does the walk
actually see at the guard?
"""
import hashlib
import json
import subprocess
import sys

sys.path.insert(0, "/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b")
from src.ohscanner.detectors.interface.cpp_macros import (  # noqa: E402
    catalog_for_units, expand_with_catalog)
from src.ohscanner.contracts import SourceUnit  # noqa: E402

REPORT = "/home/audit/wtmp/ceiling-out-services-service/multimedia_camera_framework/report.json"
CORPUS = "/home/audit/openharmony-audit/perf-corpus/multimedia_camera_framework"
TARGET = "services/camera_service/src/hcamera_service.cpp"
NEEDLES = ("CHECK_RETURN_RET_ELOG", "CAMERA_NO_PERMISSION", "MuteCameraPersist(",
           "SetMutePolicy")

rep = json.load(open(REPORT))
commit = rep["commit"]
paths = []
for shard in rep["scope"]["shards"]:
    paths.extend(shard["paths"])


def blob(path):
    out = subprocess.run(["git", "-C", CORPUS, "show", commit + ":" + path],
                         capture_output=True, timeout=60)
    return out.stdout.decode("utf-8", "replace") if out.returncode == 0 else ""


units = []
for p in paths:
    text = blob(p)
    units.append(SourceUnit(p, "cpp", text,
                            hashlib.sha256(text.encode("utf-8")).hexdigest(), "complete"))

catalog, used, total, truncated = catalog_for_units(units, 400, 6_000_000)
print("catalogue: sources=%d bytes=%d truncated=%s" % (used, total, truncated))
raw = blob(TARGET)
exp = expand_with_catalog(raw.encode("utf-8"), catalog)
print("expansion: expansions=%d refused=%d fatal=%s"
      % (len(exp.expansions), len(exp.refused), list(exp.fatal)[:3]))
text = exp.source.decode("utf-8", "replace")
lines = text.splitlines()
for i, line in enumerate(lines):
    if "MuteCameraPersist(" in line and "int32_t HCameraService::" in line:
        start = i
        break
else:
    start = 0
import collections  # noqa: E402
print("refusal reasons for this file:", dict(collections.Counter(
    reason for _, reason in exp.refused)))
print("=== expanded lines %d..%d of the target function" % (start + 1, start + 30))
for n in range(start, min(len(lines), start + 30)):
    print("%5d| %s" % (n + 1, lines[n]))
