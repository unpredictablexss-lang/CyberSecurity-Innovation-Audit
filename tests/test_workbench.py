"""Real local Git and child-process integration; not detector accuracy tests."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.store import Store
from src.workbench.worker import Worker
from src.workbench import service
from src.ohscanner.execution import run_fixed_commit_scan

ROOT = Path(__file__).resolve().parents[1]
HEADERS = {"x-ohscanner-client":"workbench-v1"}
IDS = ["ohscanner.cpp.lifetime","ohscanner.cpp.shared_ptr_race","ohscanner.interface.ipc"]

def git(repo,*args):
    return subprocess.check_output(["git","-C",str(repo),*args],stderr=subprocess.DEVNULL,text=True).strip()

class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root/"targets"/"sample"
        self.repo.mkdir(parents=True)
        fixture = ROOT/"tests"/"detectors"/"fixtures"
        (self.repo/"lifetime.cpp").write_text((fixture/"cpp_lifetime"/"vulnerable_unserialized.cpp").read_text())
        (self.repo/"race.cpp").write_text((fixture/"cpp_shared_ptr_race"/"vulnerable_non_atomic_shared_ptr.cpp").read_text())
        (self.repo/"ipc.cpp").write_text((ROOT/"tests"/"fixtures"/"ipc"/"auth_positive.cpp").read_text())
        (self.repo/"partial.cpp").write_text("int unfinished( {\n")
        (self.repo/"index.ets").write_text("let text: string = 'unknown';\n")
        (self.repo/"private.txt").write_text("not source")
        git(self.repo,"init","-q");git(self.repo,"config","user.name","test")
        git(self.repo,"config","user.email","test@example.invalid")
        git(self.repo,"add",".");git(self.repo,"commit","-qm","fixed")
        self.commit = git(self.repo,"rev-parse","HEAD")
        self.settings = Settings(self.root/"data",(self.root/"targets",))
        self.app = create_app(self.settings)
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)
        self.store = self.app.state.store
        r = self.client.post("/api/v1/repositories",json={"name":"fixture/sample","path":str(self.repo)},headers=HEADERS)
        self.assertEqual(r.status_code,201,r.text)
        self.repo_id = r.json()["id"]

    def queue(self,**extra):
        data = {"repository_id":self.repo_id,"revision":"HEAD","detector_ids":IDS,**extra}
        r = self.client.post("/api/v1/scans",json=data,headers=HEADERS)
        self.assertEqual(r.status_code,201,r.text)
        return r.json()

    def completed(self):
        job = self.queue()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        self.assertIn(job["status"],{"completed","completed_with_limitations"},job)
        return job

    def test_catalog_research_only(self):
        r = self.client.get("/api/v1/detectors")
        self.assertEqual({x["id"] for x in r.json()},set(IDS))
        self.assertTrue(all(x["version"] for x in r.json()))

    def test_mutation_requires_header(self):
        self.assertEqual(self.client.post("/api/v1/scans",json={}).status_code,403)

    def test_cross_origin_rejected(self):
        self.assertEqual(self.client.get("/api/v1/health",headers={"Origin":"https://evil.invalid"}).status_code,403)

    def test_untrusted_host_rejected(self):
        self.assertEqual(self.client.get("/api/v1/health",headers={"host":"evil.invalid"}).status_code,400)

    def test_repository_outside_roots(self):
        r = self.client.post("/api/v1/repositories",json={"name":"fixture/out","path":str(ROOT)},headers=HEADERS)
        self.assertEqual(r.status_code,409)

    def test_repository_symlink_rejected(self):
        link=self.root/"targets"/"link";link.symlink_to(self.repo)
        r=self.client.post("/api/v1/repositories",json={"name":"fixture/link","path":str(link)},headers=HEADERS)
        self.assertEqual(r.status_code,409)

    def test_pin_does_not_follow_branch_later(self):
        job=self.queue()
        (self.repo/"private.txt").write_text("changed")
        git(self.repo,"add",".");git(self.repo,"commit","-qm","changed")
        self.assertEqual(job["spec"]["commit"],self.commit)
        self.assertNotEqual(git(self.repo,"rev-parse","HEAD"),job["spec"]["commit"])

    def test_scope_escape_rejected(self):
        r=self.client.post("/api/v1/scans",json={"repository_id":self.repo_id,"revision":"HEAD","detector_ids":IDS,
                                               "include_paths":["../escape"]},headers=HEADERS)
        self.assertEqual(r.status_code,409)

    def test_arbitrary_detector_rejected(self):
        r=self.client.post("/api/v1/scans",json={"repository_id":self.repo_id,"revision":"HEAD",
                                               "detector_ids":["os.system"]},headers=HEADERS)
        self.assertEqual(r.status_code,409)

    def test_revision_option_rejected(self):
        r=self.client.post("/api/v1/scans",json={"repository_id":self.repo_id,"revision":"--help",
                                               "detector_ids":IDS},headers=HEADERS)
        self.assertEqual(r.status_code,409)

    def test_queue_cancel_never_executes(self):
        job=self.queue()
        self.client.post(f"/api/v1/scans/{job['id']}/cancel",headers=HEADERS)
        Worker(self.settings).run(once=True)
        self.assertEqual(self.store.job(job["id"])["status"],"cancelled")
        self.assertFalse(service.artifact_dir(self.settings,job["id"]).exists())

    def test_atomic_claim(self):
        job=self.queue(); output=[]
        threads=[threading.Thread(target=lambda:output.append(Store(self.settings.data_dir).claim())) for _ in range(4)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual([x["id"] for x in output if x],[job["id"]])

    def test_restart_marks_interrupted(self):
        job=self.queue();self.store.claim()
        Worker(self.settings).run(once=True)
        self.assertEqual(self.store.job(job["id"])["status"],"interrupted")

    def test_reopen_persistent_store(self):
        job=self.queue()
        self.assertEqual(Store(self.settings.data_dir).job(job["id"])["spec"]["commit"],self.commit)

    def test_api_cli_parity_partial_and_obligations(self):
        job=self.completed(); web=service.read_report(self.settings,job)
        cli=run_fixed_commit_scan(self.repo,"fixture/sample",self.commit,(".",),tuple(IDS),
                                  self.root/"cli.json",self.root/"cli.md")
        self.assertEqual(web["snapshot_sha256"],cli["snapshot_sha256"])
        self.assertEqual(web["detector_coverage"],cli["detector_coverage"])
        for a,b in zip(web["detector_runs"],cli["detector_runs"]):
            self.assertEqual(a["diagnostics"],b["diagnostics"])
        self.assertIn("index.ets",web["files_in_scope_without_a_claiming_detector"])
        self.assertEqual(web["validated_vulnerability"],0)
        self.assertTrue(service.findings(web))
        self.assertTrue(all(x["evidence"].get("obligations") for x in service.findings(web)))

    def test_viewer_uses_git_not_worktree(self):
        job=self.completed()
        expected=(self.repo/"lifetime.cpp").read_text()
        (self.repo/"lifetime.cpp").write_text("working tree tamper")
        r=self.client.get(f"/api/v1/scans/{job['id']}/source",params={"file":"lifetime.cpp"})
        self.assertEqual(r.status_code,200,r.text);self.assertEqual(r.json()["text"],expected)

    def test_viewer_rejects_unscanned_blob(self):
        job=self.completed()
        self.assertEqual(self.client.get(f"/api/v1/scans/{job['id']}/source",params={"file":"private.txt"}).status_code,409)

    def test_report_tampering_rejected(self):
        job=self.completed()
        (service.artifact_dir(self.settings,job["id"])/"report.json").write_text("{}")
        self.assertEqual(self.client.get(f"/api/v1/scans/{job['id']}/report").status_code,409)

    def test_markdown_tampering_rejected(self):
        job=self.completed()
        (service.artifact_dir(self.settings,job["id"])/"report.md").write_text("altered")
        self.assertEqual(self.client.get(f"/api/v1/scans/{job['id']}/artifacts/report.md").status_code,409)

    def test_review_is_append_only_with_conflict_detection(self):
        job=self.completed(); identity=service.findings(service.read_report(self.settings,job))[0]["id"]
        path=f"/api/v1/scans/{job['id']}/findings/{identity}/reviews"
        body={"status":"under_review","reviewer":"captain","notes":"Check entry boundary","expected_id":0}
        first=self.client.post(path,json=body,headers=HEADERS)
        self.assertEqual(first.status_code,201,first.text)
        self.assertEqual(self.client.post(path,json=body,headers=HEADERS).status_code,409)
        body.update(status="plausible_unproven",expected_id=first.json()[-1]["id"])
        self.assertEqual(len(self.client.post(path,json=body,headers=HEADERS).json()),2)
        self.assertEqual(service.read_report(self.settings,job)["validated_vulnerability"],0)

    def test_review_cannot_self_promote(self):
        job=self.completed(); identity=service.findings(service.read_report(self.settings,job))[0]["id"]
        r=self.client.post(f"/api/v1/scans/{job['id']}/findings/{identity}/reviews",
                           json={"status":"confirmed","reviewer":"x","notes":"AI said yes"},headers=HEADERS)
        self.assertEqual(r.status_code,422)

    def test_case_links_require_existing_run_candidates(self):
        job=self.completed(); identity=service.findings(service.read_report(self.settings,job))[0]["id"]
        data={"title":"Investigate common root cause","links":[{"job_id":job["id"],"candidate_id":identity,"rationale":"same reviewed object"}]}
        r=self.client.post("/api/v1/cases",json=data,headers=HEADERS)
        self.assertEqual(r.status_code,201,r.text);self.assertEqual(r.json()["status"],"investigation")
        data["links"][0]["candidate_id"]="invalid"
        self.assertEqual(self.client.post("/api/v1/cases",json=data,headers=HEADERS).status_code,404)

    def test_export_binds_review_and_report(self):
        job=self.completed()
        r=self.client.get(f"/api/v1/scans/{job['id']}/artifacts/review.json")
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()["scanner_report_sha256"],job["report_sha256"])
        self.assertEqual(r.json()["commit"],self.commit)

    def test_retry_freezes_original_commit(self):
        job=self.completed()
        (self.repo/"private.txt").write_text("new");git(self.repo,"add",".");git(self.repo,"commit","-qm","new")
        retry=self.client.post(f"/api/v1/scans/{job['id']}/retry",headers=HEADERS).json()
        self.assertEqual(retry["spec"]["commit"],self.commit);self.assertEqual(retry["spec"]["retry_of"],job["id"])

    def test_engine_drift_fails_instead_of_reusing_claim(self):
        job=self.queue()
        with self.store.connect() as db:
            spec=copy.deepcopy(job["spec"]);spec["engine_sha256"]="0"*64
            db.execute("UPDATE jobs SET spec=? WHERE id=?", (json.dumps(spec),job["id"]))
        Worker(self.settings).run(once=True)
        result=self.store.job(job["id"])
        self.assertEqual(result["status"],"failed");self.assertIsNone(result["report_sha256"])

    def test_hard_timeout_kills_process(self):
        job=self.queue(timeout_seconds=1);claimed=self.store.claim()
        real_popen=subprocess.Popen; processes=[]
        def sleeper(*args,**kwargs):
            proc=real_popen(["/usr/bin/python3","-c","import time; time.sleep(30)"],**kwargs)
            processes.append(proc);return proc
        start=time.monotonic()
        with patch("src.workbench.worker.check_repository",return_value=self.repo), patch("src.workbench.worker.subprocess.Popen",side_effect=sleeper):
            Worker(self.settings).execute(claimed)
        self.assertLess(time.monotonic()-start,5)
        self.assertEqual(self.store.job(job["id"])["status"],"timed_out")
        self.assertIsNotNone(processes[0].poll())

    def test_running_cancel_kills_process(self):
        job=self.queue();claimed=self.store.claim()
        real_popen=subprocess.Popen;processes=[]
        def sleeper(*args,**kwargs):
            proc=real_popen(["/usr/bin/python3","-c","import time; time.sleep(30)"],**kwargs)
            processes.append(proc);return proc
        thread=threading.Thread(target=lambda:(time.sleep(.3),self.store.cancel(job["id"])))
        thread.start()
        with patch("src.workbench.worker.check_repository",return_value=self.repo), patch("src.workbench.worker.subprocess.Popen",side_effect=sleeper):
            Worker(self.settings).execute(claimed)
        thread.join()
        self.assertEqual(self.store.job(job["id"])["status"],"cancelled")
        self.assertIsNotNone(processes[0].poll())
