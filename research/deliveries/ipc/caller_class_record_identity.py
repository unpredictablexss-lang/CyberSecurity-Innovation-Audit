"""Field-level identity of one candidate record across every counterfactual tier.

Read-only. Candidate *counts* can stay equal while a record's `passes`/`sources`
change (that is what the `dw` edit does to camera's AUTH-01 records), so the
camera caller-class record is compared field by field instead. Paths are the
saved runs used for this measurement; nothing here writes anywhere.
"""
import json

ROOTS = {
    "base": "/home/audit/wtmp/ceiling-out-services-service",
    "dw": "/home/audit/wtmp/ceiling-pred-detector-cf-dw-services-service",
    "pred1": "/home/audit/wtmp/ceiling-pred-detector-cf-pred1-services-service",
    "pred2": "/home/audit/wtmp/ceiling-pred-detector-cf-pred2-services-service",
    "pred1dw": "/home/audit/wtmp/ceiling-pred-detector-cf-pred1dw-services-service",
    "pred2dw": "/home/audit/wtmp/ceiling-pred-detector-cf-pred2dw-services-service",
}
COMP = "multimedia_camera_framework"
WANT = ("services/camera_service/src/hcamera_service.cpp", 2621)


def load(tag):
    p = "%s/%s/report.json" % (ROOTS[tag], COMP)
    try:
        rep = json.load(open(p))
    except OSError:
        return None
    for c in rep["candidates"]:
        if (c["file"], c["line"]) == WANT and c["rule_id"] == "ipc.auth.caller-class":
            return c
    return "absent"


base = load("base")
print("base record keys:", sorted(base))
for tag in ROOTS:
    c = load(tag)
    if c is None:
        print("%-8s MISSING" % tag)
    elif c == "absent":
        print("%-8s absent" % tag)
    else:
        diff = [f for f in base if base.get(f) != c.get(f)]
        print("%-8s identical=%s differing=%s" % (tag, not diff, diff or ""))
        for f in diff:
            print("    %-22s %r -> %r" % (f, base.get(f), c.get(f)))
