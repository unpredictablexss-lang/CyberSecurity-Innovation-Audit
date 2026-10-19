"""Repeat pinned CVE candidates through Workbench API/Worker and source viewer."""
from pathlib import Path
import argparse, json, sys, tempfile
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient
from src.workbench import service
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.worker import Worker
MIRROR = Path("/mnt/g/OpenHarmony-GitCode-Mirror")
DETECTOR = "ohscanner.known_disclosed_cves"
SPECS = [
 ("third_party_libpng", MIRROR/"campaign-100-20261017/repos/third_party_libpng", "e57b1079564a02a50321ec528aa6e41884979d32", ["libpng-1.6.55.tar.gz"], ["CVE-2026-33636","CVE-2026-46675"]),
 ("third_party_libtiff", MIRROR/"campaign-100-20261017/repos/third_party_libtiff", "d4a0516c477dfbaf1153ae295893ab75aadd63d4", ["libtiff/tif_getimage.c"], ["CVE-2025-9900"]),
 ("third_party_curl", MIRROR/"campaign-100-20261017/repos/third_party_curl", "1386bb128bb060b284309397b97adcaaec21c003", ["lib/mime.c"], ["CVE-2026-92391"]),
 ("third_party_cJSON", MIRROR/"repos/third_party_cJSON", "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748", ["cJSON.c","cJSON_Utils.c"], ["CVE-2026-67215","CVE-2026-67216"]),
 ("miscservices_pasteboard", MIRROR/"campaign-100-20261017/repos/miscservices_pasteboard", "dd22c7cb5e5f207a6c38c50f45b7369ee8575840", ["services/core/src/pasteboard_service.cpp","services/zidl/src/pasteboard_service_stub.cpp"], ["CVE-2025-25212","CVE-2025-27247"]),
]
def scan(client, app, settings, repo_id, headers, spec):
 r=client.post("/api/v1/scans",headers=headers,json={"repository_id":repo_id,"revision":spec[2],"include_paths":spec[3],"detector_ids":[DETECTOR]})
 if r.status_code!=201: raise RuntimeError(r.text)
 jid=r.json()["id"]; Worker(settings).run(once=True); job=app.state.store.job(jid); report=service.read_report(settings,job)
 ds=[d for run in report["detector_runs"] for d in run["diagnostics"] if d.get("symbol","").startswith("CVE-")]
 found={d["symbol"] for d in ds}; missing=set(spec[4])-found
 if missing: raise RuntimeError(f"{spec[0]} lost candidates: {sorted(missing)}")
 bindings=[]
 for path in sorted({d["file"] for d in ds}):
  src=service.source(settings,app.state.store,job,path)
  if {d["source_sha256"] for d in ds if d["file"]==path}!={src["sha256"]}: raise RuntimeError(f"source hash mismatch: {path}")
  bindings.append((path,src["sha256"],src.get("blob"),src.get("archive_binding")))
 sig=sorted((d["symbol"],d["file"],d["line"],d["source_sha256"]) for d in ds)
 return {"status":job["status"],"detector_status":report["detector_runs"][0]["status"],"git_tree":report["git_tree"],"snapshot_sha256":report["snapshot_sha256"],"report_sha256":job["report_sha256"],"diagnostics":sig,"source_bindings":bindings,"validated_vulnerability":report["validated_vulnerability"]}
def main():
 p=argparse.ArgumentParser(); p.add_argument("--output",type=Path,default=Path(__file__).with_name("D32_KNOWN_CVE_PANEL_REPLAY.json")); out=p.parse_args().output
 if any(not x[1].is_dir() for x in SPECS): raise SystemExit("a required G-mirror repository is unavailable")
 results=[]
 with tempfile.TemporaryDirectory(prefix="ohscanner-d32-panel-") as td:
  settings=Settings(Path(td)/"data",(MIRROR,)); app=create_app(settings); headers={"x-ohscanner-client":"workbench-v1"}
  with TestClient(app) as client:
   if client.get("/").status_code!=200: raise RuntimeError("Workbench homepage failed")
   catalog=client.get("/api/v1/detectors").json()
   if DETECTOR not in {x["id"] for x in catalog}: raise RuntimeError("detector absent from catalog")
   for spec in SPECS:
    rr=client.post("/api/v1/repositories",headers=headers,json={"name":"G-mirror/"+spec[0],"path":str(spec[1])})
    if rr.status_code!=201: raise RuntimeError(rr.text)
    a=scan(client,app,settings,rr.json()["id"],headers,spec); b=scan(client,app,settings,rr.json()["id"],headers,spec)
    stable=(a["git_tree"],a["snapshot_sha256"],a["diagnostics"],a["source_bindings"])==(b["git_tree"],b["snapshot_sha256"],b["diagnostics"],b["source_bindings"])
    if not stable: raise RuntimeError(f"{spec[0]} nondeterministic API result")
    results.append({"repository":spec[0],"commit":spec[2],"include_paths":spec[3],"expected_cves":spec[4],"runs":[a,b],"repeat_equal":stable})
 result={"schema":1,"experiment":"D32 pinned known-CVE scans through Workbench API and Worker","detector":DETECTOR,"catalog_registered":True,"results":results,"limitations":["All findings remain candidates; validated_vulnerability is zero.","Pinned G-mirror component source does not prove product inclusion, reachability, attacker control or impact.","Blocked/partial coverage is preserved and repeated hits do not prove full analysis.","TestClient covers API, Worker, report and hash-checked source-viewer paths, not the live service."]}
 out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 print(json.dumps({"output":str(out),"results":[{"repository":x["repository"],"cves":[d[0] for d in x["runs"][0]["diagnostics"]],"statuses":[r["detector_status"] for r in x["runs"]],"repeat_equal":x["repeat_equal"],"validated_vulnerability":x["runs"][0]["validated_vulnerability"]} for x in results]},ensure_ascii=False,indent=2))
if __name__=="__main__": main()
