import importlib, json, sys
mods = [
    "src.ohscanner.detectors.known_cves",
    "src.ohscanner.detectors.catalog",
    "src.ohscanner.detectors.ark_runtime.model",
    "src.ohscanner.detectors.ark_runtime.runtime_ir",
    "src.ohscanner.detectors.ark_runtime.syntax",
    "src.ohscanner.detectors.ark_runtime.type_origin",
    "src.ohscanner.detectors.ark_runtime.runtime_exception",
    "src.ohscanner.detectors.ark_runtime.size_overflow",
    "src.ohscanner.detectors.ark_runtime.receiver_guard",
    "src.ohscanner.detectors.ark_runtime.detector",
    "src.ohscanner.runner",
]
out=[]
for name in mods:
    try:
        m=importlib.import_module(name)
        out.append({"module":name,"status":"pass","file":getattr(m,"__file__",None)})
    except Exception as e:
        out.append({"module":name,"status":"fail","error":type(e).__name__+": "+str(e)})
print(json.dumps({"schema":"c9-latest-static-import-smoke/v1","python":sys.version,"modules":out},ensure_ascii=False,indent=2))
raise SystemExit(0 if all(x["status"]=="pass" for x in out) else 1)
