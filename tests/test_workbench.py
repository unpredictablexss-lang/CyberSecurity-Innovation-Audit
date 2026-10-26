import io
import zipfile
"""Real local Git and child-process integration; not detector accuracy tests."""

import copy
import json
import io
import hashlib
import os
import tarfile
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
import zipfile
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
    from src.workbench.api import create_app
except ModuleNotFoundError as error:
    if error.name.split(".")[0] not in {"fastapi", "httpx", "pydantic", "starlette"}:
        raise
    create_app = None
from src.workbench.settings import Settings
from src.workbench.store import Store
from src.workbench.worker import Worker
from src.workbench import service
from src.ohscanner.execution import run_fixed_commit_scan

ROOT = Path(__file__).resolve().parents[1]
HEADERS = {"x-ohscanner-client": "workbench-v1"}
IDS = [
    "ohscanner.cpp.lifetime",
    "ohscanner.cpp.shared_ptr_race",
    "ohscanner.interface.ipc",
]


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL, text=True
    ).strip()


@unittest.skipIf(
    create_app is None, "optional workbench dependencies: install requirements-web.txt"
)
class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "targets" / "sample"
        self.repo.mkdir(parents=True)
        fixture = ROOT / "tests" / "detectors" / "fixtures"
        (self.repo / "lifetime.cpp").write_text(
            (fixture / "cpp_lifetime" / "vulnerable_unserialized.cpp").read_text()
        )
        (self.repo / "race.cpp").write_text(
            (
                fixture / "cpp_shared_ptr_race" / "vulnerable_non_atomic_shared_ptr.cpp"
            ).read_text()
        )
        (self.repo / "ipc.cpp").write_text(
            (ROOT / "tests" / "fixtures" / "ipc" / "auth_positive.cpp").read_text()
        )
        (self.repo / "partial.cpp").write_text("int unfinished( {\n")
        (self.repo / "index.ets").write_text("let text: string = 'unknown';\n")
        (self.repo / "private.txt").write_text("not source")
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "test")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "fixed")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        self.settings = Settings(self.root / "data", (self.root / "targets",))
        self.app = create_app(self.settings)
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)
        self.store = self.app.state.store
        r = self.client.post(
            "/api/v1/repositories",
            json={"name": "fixture/sample", "path": str(self.repo)},
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 201, r.text)
        self.repo_id = r.json()["id"]

    def test_validation_catalog_lists_auth_and_cpp_reproduction_tests(self):
        response = self.client.get("/api/v1/validation-tests")
        self.assertEqual(response.status_code, 200, response.text)
        tests = response.json()["tests"]
        self.assertEqual({item["id"] for item in tests}, {
            "auth01_descriptor_bypass", "cpp_lifetime_unique_ptr_alias",
            "cpp_shared_ptr_delayed_singleton",
        })
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "C++ reproduction integration",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"], "rationale": "archive test"}],
        }).json()
        created = self.client.post("/api/v1/operations/validations", headers=HEADERS, json={
            "case_id": case["id"], "harness_id": "cpp_lifetime_unique_ptr_alias",
        })
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["spec"]["validation_scope"], "synthetic_harness")
        self.assertEqual(created.json()["spec"]["harness_id"], "cpp_lifetime_unique_ptr_alias")
    def queue(self, **extra):
        data = {
            "repository_id": self.repo_id,
            "revision": "HEAD",
            "detector_ids": IDS,
            **extra,
        }
        r = self.client.post("/api/v1/scans", json=data, headers=HEADERS)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def completed(self):
        job = self.queue()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
        return job

    def test_prebuilt_homepage_api_worker_and_report_artifacts(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("OHScanner", page.text)
        self.assertIn("assets/app", page.text)

        job = self.completed()
        detail = self.client.get(f"/api/v1/scans/{job['id']}")
        self.assertEqual(detail.status_code, 200, detail.text)
        report = self.client.get(f"/api/v1/scans/{job['id']}/artifacts/report.json")
        markdown = self.client.get(f"/api/v1/scans/{job['id']}/artifacts/report.md")
        manifest = self.client.get(f"/api/v1/scans/{job['id']}/artifacts/manifest.json")
        self.assertEqual(report.status_code, 200, report.text)
        self.assertEqual(markdown.status_code, 200, markdown.text)
        self.assertEqual(manifest.status_code, 200, manifest.text)
        self.assertEqual(manifest.json()["artifacts"]["report.json"], job["report_sha256"])
        self.assertEqual(json.loads(report.text)["commit"], self.commit)
        self.assertIn("OHScanner", markdown.text)

    def test_catalog_research_only(self):
        r = self.client.get("/api/v1/detectors")
        self.assertEqual({x["id"] for x in r.json()}, {
            "ohscanner.cpp.lifetime", "ohscanner.cpp.shared_ptr_race",
            "ohscanner.cpp.null_dereference", "ohscanner.cpp.bounds",
            "ohscanner.cpp.integer_bounds", "ohscanner.cpp.resource_lifetime",
            "ohscanner.cpp.unsafe_memory_call", "ohscanner.interface.ipc",
            "ohscanner.cpp.path_traversal", "ohscanner.ark.runtime.type_safety",
            "ohscanner.oh.arkts_js", "ohscanner.data.sensitive_exposure",
            "ohscanner.known_disclosed_cves",
        })
        self.assertTrue(all(x["version"] for x in r.json()))
        cve_detector = next(
            x for x in r.json() if x["id"] == "ohscanner.known_disclosed_cves"
        )
        self.assertEqual(cve_detector["kind"], "research_candidate")
        self.assertTrue(cve_detector.get("default_enabled", True))
        self.assertIn("independent holdout", cve_detector["admission_reason"])

    def test_mutation_requires_header(self):
        self.assertEqual(self.client.post("/api/v1/scans", json={}).status_code, 403)

    def test_cross_origin_rejected(self):
        self.assertEqual(
            self.client.get(
                "/api/v1/health", headers={"Origin": "https://evil.invalid"}
            ).status_code,
            403,
        )

    def test_untrusted_host_rejected(self):
        self.assertEqual(
            self.client.get(
                "/api/v1/health", headers={"host": "evil.invalid"}
            ).status_code,
            400,
        )

    def test_local_api_responses_disallow_embedding_and_unused_browser_capabilities(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertEqual(response.headers["permissions-policy"],
                         "camera=(), microphone=(), geolocation=()")
        self.assertEqual(response.headers["cross-origin-resource-policy"], "same-origin")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_repository_outside_roots(self):
        r = self.client.post(
            "/api/v1/repositories",
            json={"name": "fixture/out", "path": str(ROOT)},
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 409)

    def test_repository_symlink_rejected(self):
        link = self.root / "targets" / "link"
        link.symlink_to(self.repo)
        r = self.client.post(
            "/api/v1/repositories",
            json={"name": "fixture/link", "path": str(link)},
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 409)

    def test_pin_does_not_follow_branch_later(self):
        job = self.queue()
        (self.repo / "private.txt").write_text("changed")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "changed")
        self.assertEqual(job["spec"]["commit"], self.commit)
        self.assertNotEqual(git(self.repo, "rev-parse", "HEAD"), job["spec"]["commit"])

    def test_incremental_base_is_previewed_bound_and_reported_with_full_fallback(self):
        source = self.repo / "lifetime.cpp"
        source.write_text(source.read_text() + "\n// incremental API fixture change\n")
        git(self.repo, "add", "lifetime.cpp")
        git(self.repo, "commit", "-qm", "head source change")
        head = git(self.repo, "rev-parse", "HEAD")
        request = {
            "repository_id": self.repo_id,
            "revision": head,
            "base_commit": self.commit,
            "include_paths": ["."],
            "detector_ids": IDS,
            "audit_mode": "static_only",
        }
        preview = self.client.post("/api/v1/audit-plans", json=request, headers=HEADERS)
        self.assertEqual(preview.status_code, 200, preview.text)
        plan = preview.json()
        self.assertEqual(plan["base_commit"], self.commit)
        self.assertEqual(plan["incremental_mode"], "full_scan_fallback_if_dependency_reuse_unproven")

        job = self.queue(revision=head, base_commit=self.commit, audit_mode="static_only")
        self.assertEqual(job["spec"]["base_commit"], self.commit)
        self.assertNotEqual(
            job["spec"]["workflow_sha256"],
            service.audit_workflow_sha256(job["spec"]["plan_sha256"], "static_only"),
        )
        Worker(self.settings).run(once=True)
        completed = self.store.job(job["id"])
        self.assertIn(completed["status"], {"completed", "completed_with_limitations"})
        report = self.client.get(f"/api/v1/scans/{job['id']}/report").json()
        self.assertEqual(report["incremental"]["base_commit"], self.commit)
        self.assertEqual(report["incremental"]["head_commit"], head)
        self.assertTrue(report["incremental"]["fallback"])
        self.assertEqual(report["incremental"]["execution"], "full_scan_required")

    def test_scope_escape_rejected(self):
        r = self.client.post(
            "/api/v1/scans",
            json={
                "repository_id": self.repo_id,
                "revision": "HEAD",
                "detector_ids": IDS,
                "include_paths": ["../escape"],
            },
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 409)

    def test_arbitrary_detector_rejected(self):
        r = self.client.post(
            "/api/v1/scans",
            json={
                "repository_id": self.repo_id,
                "revision": "HEAD",
                "detector_ids": ["os.system"],
            },
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 409)

    def test_revision_option_rejected(self):
        r = self.client.post(
            "/api/v1/scans",
            json={
                "repository_id": self.repo_id,
                "revision": "--help",
                "detector_ids": IDS,
            },
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 409)

    def test_queue_cancel_never_executes(self):
        job = self.queue()
        self.client.post(f"/api/v1/scans/{job['id']}/cancel", headers=HEADERS)
        Worker(self.settings).run(once=True)
        self.assertEqual(self.store.job(job["id"])["status"], "cancelled")
        self.assertFalse(service.artifact_dir(self.settings, job["id"]).exists())

    def test_atomic_claim(self):
        job = self.queue()
        output = []
        threads = [
            threading.Thread(
                target=lambda: output.append(Store(self.settings.data_dir).claim())
            )
            for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual([x["id"] for x in output if x], [job["id"]])

    def test_restart_marks_interrupted(self):
        job = self.queue()
        self.store.claim()
        Worker(self.settings).run(once=True)
        self.assertEqual(self.store.job(job["id"])["status"], "interrupted")

    def test_reopen_persistent_store(self):
        job = self.queue()
        self.assertEqual(
            Store(self.settings.data_dir).job(job["id"])["spec"]["commit"], self.commit
        )

    def test_api_cli_parity_partial_and_obligations(self):
        job = self.completed()
        web = service.read_report(self.settings, job)
        cli = run_fixed_commit_scan(
            self.repo,
            "fixture/sample",
            self.commit,
            (".",),
            tuple(IDS),
            self.root / "cli.json",
            self.root / "cli.md",
        )
        self.assertEqual(web["snapshot_sha256"], cli["snapshot_sha256"])
        self.assertEqual(web["detector_coverage"], cli["detector_coverage"])
        for a, b in zip(web["detector_runs"], cli["detector_runs"]):
            self.assertEqual(a["diagnostics"], b["diagnostics"])
        self.assertIn("index.ets", web["files_in_scope_without_a_claiming_detector"])
        self.assertEqual(web["validated_vulnerability"], 0)
        self.assertTrue(service.findings(web))
        self.assertTrue(
            all(x["evidence"].get("obligations") for x in service.findings(web))
        )

    def test_data06_source_candidate_and_fixed_retest_reach_finding_detail_api(self):
        ipc_repo = Path(os.environ.get("T74_IPC_GIT", ROOT / "tmp/t71-communication-ipc"))
        source_rel = Path("interfaces/innerkits/cj/src/message_sequence_impl.cpp")
        if not ipc_repo.is_dir():
            self.skipTest("pinned communication_ipc Git objects are unavailable; set T74_IPC_GIT")
        for commit in (
            "84d681288793785e8f39f71c824f211edaed8f1e",
            "de3a68cc8b7d6f18017fd261060def0e38dce54a",
        ):
            try:
                subprocess.run(
                    ["git", "-C", str(ipc_repo), "cat-file", "-e", f"{commit}:{source_rel.as_posix()}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                )
            except (FileNotFoundError, subprocess.CalledProcessError):
                self.skipTest(f"pinned communication_ipc object {commit} is unavailable; set T74_IPC_GIT")
        target_repo = self.root / "targets" / "openharmony" / "communication_ipc"
        target_repo.mkdir(parents=True)
        git(target_repo, "init", "-q")
        git(target_repo, "config", "user.name", "test")
        git(target_repo, "config", "user.email", "test@example.invalid")
        source_path = target_repo / source_rel

        def install_source(commit, message):
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(subprocess.check_output(
                ["git", "-C", str(ipc_repo), "show", f"{commit}:{source_rel.as_posix()}"]
            ))
            git(target_repo, "add", str(source_rel))
            git(target_repo, "commit", "-qm", message)
            return git(target_repo, "rev-parse", "HEAD")

        vulnerable_bytes = subprocess.check_output(
            ["git", "-C", str(ipc_repo), "show", f"84d681288793785e8f39f71c824f211edaed8f1e:{source_rel.as_posix()}"]
        )
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(vulnerable_bytes)
        git(target_repo, "add", str(source_rel))
        git(target_repo, "commit", "-qm", "pin DATA-06 vulnerable source bytes")
        registration = self.client.post(
            "/api/v1/repositories",
            json={"name": "openharmony/communication_ipc", "path": str(target_repo)},
            headers=HEADERS,
        )
        self.assertEqual(registration.status_code, 201, registration.text)
        self.repo_id = registration.json()["id"]

        vulnerable = git(target_repo, "rev-parse", "HEAD")
        request = self.queue(revision=vulnerable, detector_ids=["ohscanner.interface.ipc"])
        Worker(self.settings).run(once=True)
        job = self.store.job(request["id"])
        report = service.read_report(self.settings, job)
        candidate = next(
            item for item in service.findings(report)
            if item["rule_id"] == "ipc.parcel.array-allocation-width"
        )
        risk = candidate["risk_assessment"]
        self.assertIn("候选映射；非根因证明", risk["identifier"])
        self.assertIn("provenance only", risk["mapping_basis"])
        self.assertEqual("unknown", risk["product_applicability"])
        self.assertEqual(
            hashlib.sha256((ROOT / risk["poc"]["record"]).read_bytes()).hexdigest(),
            risk["poc"]["record_sha256"],
        )
        self.assertEqual(
            hashlib.sha256((ROOT / risk["poc"]["replay"]).read_bytes()).hexdigest(),
            risk["poc"]["replay_sha256"],
        )
        self.assertEqual(vulnerable, report["commit"])
        detail = self.client.get(
            f"/api/v1/scans/{job['id']}/findings/{candidate['id']}"
        )
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(risk, detail.json()["risk_assessment"])
        self.assertEqual(hashlib.sha256(source_path.read_bytes()).hexdigest(),
                         detail.json()["source"]["sha256"])
        self.assertEqual(str(source_rel).replace("\\", "/"), detail.json()["source"]["file"])

        fixed = install_source(
            "de3a68cc8b7d6f18017fd261060def0e38dce54a", "pin official DATA-06 fixed source bytes"
        )
        fixed_request = self.queue(revision=fixed, detector_ids=["ohscanner.interface.ipc"])
        Worker(self.settings).run(once=True)
        fixed_job = self.store.job(fixed_request["id"])
        fixed_report = service.read_report(self.settings, fixed_job)
        self.assertEqual(fixed, fixed_report["commit"])
        self.assertFalse(any(
            item["rule_id"] == "ipc.parcel.array-allocation-width"
            for item in service.findings(fixed_report)
        ))

        evidence_dir = os.environ.get("DATA06_DEMO_OUTPUT_DIR")
        if evidence_dir:
            output = Path(evidence_dir)
            output.mkdir(parents=True, exist_ok=True)
            vulnerable_report = self.client.get(
                f"/api/v1/scans/{job['id']}/artifacts/report.json"
            )
            vulnerable_markdown = self.client.get(
                f"/api/v1/scans/{job['id']}/artifacts/report.md"
            )
            fixed_report_response = self.client.get(
                f"/api/v1/scans/{fixed_job['id']}/artifacts/report.json"
            )
            fixed_markdown = self.client.get(
                f"/api/v1/scans/{fixed_job['id']}/artifacts/report.md"
            )
            for response in (vulnerable_report, vulnerable_markdown, detail,
                             fixed_report_response, fixed_markdown):
                self.assertEqual(200, response.status_code, response.text[:500])
            artifacts = {
                "vulnerable_report.json": vulnerable_report.content,
                "vulnerable_report.md": vulnerable_markdown.content,
                "finding_detail.json": detail.content,
                "fixed_report.json": fixed_report_response.content,
                "fixed_report.md": fixed_markdown.content,
            }
            source_location = risk["source_location"]
            poc = risk["poc"]
            retest = risk["component_retest"]
            evidence_markdown = "\n".join([
                "# DATA-06 candidate evidence",
                "",
                "> Source-level candidate only. The CVE association is provenance, not root-cause proof.",
                "",
                f"- Candidate report SHA-256: `{job['report_sha256']}`",
                f"- Candidate: `{candidate['rule_id']}` at `{candidate['file']}:{candidate['line']}`",
                f"- Source SHA-256: `{candidate['source_sha256']}`",
                f"- Source location: `{source_location['symbol']}`, `{source_location['file']}:{source_location['lines']}`",
                f"- Vulnerable source commit: `{source_location['vulnerable_commit']}`",
                f"- CVE mapping: {risk['identifier']}",
                f"- Mapping basis: {risk['mapping_basis']}",
                f"- Mapping source: {risk['source']}",
                f"- Severity / product applicability: `{risk['severity']}` / `{risk['product_applicability']}`",
                "- Disposition: `candidate/unknown`; no product confirmation.",
                "",
                "## Component-level PoC and fix comparison",
                "",
                f"- PoC scope: {poc['kind']}",
                f"- Harness entry: {poc['entrypoint']}",
                f"- PoC record: `{poc['record']}` (SHA-256 `{poc['record_sha256']}`)",
                f"- Replay command: `{poc['replay']}` (SHA-256 `{poc['replay_sha256']}`)",
                f"- Raw ASan output: `{poc['raw_output']}` (decoded SHA-256 `{poc['raw_output_sha256']}`)",
                f"- Fixed source: `{source_location['fixed_commit']}`; {risk['remediation']}",
                f"- Upstream fix: {risk['upstream_fix']}",
                f"- Vulnerable replay: {retest['affected_poc']}",
                f"- Fixed replay: {retest['fixed_poc']}",
                f"- Exact-source retest: {retest['fixed_source']}",
                "",
                "## Limits",
                "",
                f"- {risk['product_evidence']}",
                f"- {retest['scope']}",
                "- No real IPC or FFI reachability or product impact was established; no OpenHarmony component build was produced.",
                "- The API replay wraps pinned official source bytes in temporary local Git commits; those wrapper commits are not OpenHarmony release identifiers.",
                "",
            ]).encode("utf-8")
            evidence_text = evidence_markdown.decode("utf-8")
            self.assertIn("CVE mapping: CVE-2025-26474", evidence_text)
            self.assertIn(source_location["vulnerable_commit"], evidence_text)
            self.assertIn(poc["raw_output_sha256"], evidence_text)
            self.assertIn(source_location["fixed_commit"], evidence_text)
            self.assertIn("Upstream fix:", evidence_text)
            self.assertIn("No real IPC or FFI reachability", evidence_text)
            self.assertIn("does not establish Binder/DBinder reachability", evidence_text)
            self.assertIn("candidate/unknown", evidence_text)
            artifacts["finding_evidence.md"] = evidence_markdown
            for name, payload in artifacts.items():
                (output / name).write_bytes(payload)
            summary = {
                "schema_version": 1,
                "kind": "DATA-06 isolated workbench API replay",
                "source_bytes_from": {
                    "repository": "openharmony/communication_ipc",
                    "vulnerable_commit": "84d681288793785e8f39f71c824f211edaed8f1e",
                    "fixed_commit": "de3a68cc8b7d6f18017fd261060def0e38dce54a",
                    "vulnerable_file_sha256": hashlib.sha256(vulnerable_bytes).hexdigest(),
                    "fixed_file_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                },
                "local_workbench": {
                    "vulnerable_scan_commit": vulnerable,
                    "fixed_scan_commit": fixed,
                    "vulnerable_report_sha256": job["report_sha256"],
                    "fixed_report_sha256": fixed_job["report_sha256"],
                    "finding_detail_sha256": hashlib.sha256(detail.content).hexdigest(),
                },
                "finding": {
                    "rule_id": candidate["rule_id"],
                    "file": candidate["file"],
                    "line": candidate["line"],
                    "source_sha256": candidate["source_sha256"],
                    "risk_assessment": risk,
                    "source_status": detail.json()["source_status"],
                },
                "fixed_retest": {"rule_findings": 0, "report_sha256": fixed_job["report_sha256"]},
                "product_impact": "unknown",
                "poc_limit": "source-semantic harness; no OpenHarmony component build, real IPC/FFI reachability, or product impact claim",
            }
            (output / "summary.json").write_text(
                json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            entries = []
            for path in sorted(output.iterdir()):
                if path.is_file() and path.name != "SHA256SUMS":
                    entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
            (output / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")

    def test_real_scan_overview_risks_preserves_severity_api_contract(self):
        """A real scan -> persisted report -> API must agree with presentation routing."""
        from src.workbench.smart_audit import severity_metadata, _severity
        job = self.completed()
        report = service.read_report(self.settings, job)
        findings = {item["id"]: item for item in service.findings(report)}
        self.assertTrue(findings)
        response = self.client.get("/api/v1/overview/risks?scan_limit=10&limit=100")
        self.assertEqual(response.status_code, 200, response.text)
        rows = [row for row in response.json()["items"] if row["audit_id"] == job["id"]]
        self.assertTrue(rows)
        finding_list = self.client.get(f"/api/v1/scans/{job['id']}/findings?limit=200")
        self.assertEqual(finding_list.status_code, 200, finding_list.text)
        displayed = {row["id"]: row for row in finding_list.json()["items"]}
        for row in rows:
            with self.subTest(candidate_id=row["candidate_id"]):
                candidate = findings[row["candidate_id"]]
                expected = severity_metadata(candidate)
                self.assertEqual(displayed[row["candidate_id"]]["risk_presentation"], expected)
                # Preserve the raw detector assertion independently from UI presentation.
                self.assertEqual(displayed[row["candidate_id"]]["severity"], candidate["severity"])
                detail = self.client.get(
                    f"/api/v1/scans/{job['id']}/findings/{row['candidate_id']}")
                self.assertEqual(detail.status_code, 200, detail.text)
                self.assertEqual(detail.json()["risk_presentation"], expected)
                for field in ("severity", "severity_label", "severity_evidence", "severity_basis"):
                    self.assertEqual(row[field], expected[field])
                self.assertEqual(row["vulnerability_state"], "candidate")
                self.assertEqual(row["validated_case_ids"], [])
                self.assertIn(row["human_review_status"],
                              ("unassessed", "under_review", "plausible_unproven",
                               "likely_false_positive", "refuted"))
                if expected["severity"] in {"high", "critical"}:
                    self.assertGreaterEqual(_severity(candidate), 4)

    def test_candidate_clusters_keep_each_line_identity(self):
        job = self.completed()
        report = service.read_report(self.settings, job)
        original = service.findings(report)
        response = self.client.get(f"/api/v1/scans/{job['id']}/clusters")
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertIn("not a root-cause", data["semantics"])
        group = next(x for x in data["items"] if x["file"] == "race.cpp" and x["symbol"] == "instance_")
        members = group["candidates"]
        self.assertGreaterEqual(group["observation_count"], 2)
        self.assertEqual(len({x["id"] for x in members}), len(members))
        self.assertTrue(all(x["id"] in {f["id"] for f in original} for x in members))
        self.assertEqual(group["root_cause_conclusion"], "not_inferred")

    def test_viewer_uses_git_not_worktree(self):
        job = self.completed()
        expected = (self.repo / "lifetime.cpp").read_text()
        (self.repo / "lifetime.cpp").write_text("working tree tamper")
        r = self.client.get(
            f"/api/v1/scans/{job['id']}/source", params={"file": "lifetime.cpp"}
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["text"], expected)

    def test_viewer_rejects_unscanned_blob(self):
        job = self.completed()
        self.assertEqual(
            self.client.get(
                f"/api/v1/scans/{job['id']}/source", params={"file": "private.txt"}
            ).status_code,
            409,
        )

    def test_report_tampering_rejected(self):
        job = self.completed()
        (service.artifact_dir(self.settings, job["id"]) / "report.json").write_text(
            "{}"
        )
        self.assertEqual(
            self.client.get(f"/api/v1/scans/{job['id']}/report").status_code, 409
        )

    def test_markdown_tampering_rejected(self):
        job = self.completed()
        (service.artifact_dir(self.settings, job["id"]) / "report.md").write_text(
            "altered"
        )
        self.assertEqual(
            self.client.get(
                f"/api/v1/scans/{job['id']}/artifacts/report.md"
            ).status_code,
            409,
        )

    def test_review_is_append_only_with_conflict_detection(self):
        job = self.completed()
        identity = service.findings(service.read_report(self.settings, job))[0]["id"]
        path = f"/api/v1/scans/{job['id']}/findings/{identity}/reviews"
        body = {
            "status": "under_review",
            "reviewer": "captain",
            "notes": "Check entry boundary",
            "expected_id": 0,
        }
        first = self.client.post(path, json=body, headers=HEADERS)
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(
            self.client.post(path, json=body, headers=HEADERS).status_code, 409
        )
        body.update(status="plausible_unproven", expected_id=first.json()[-1]["id"])
        self.assertEqual(
            len(self.client.post(path, json=body, headers=HEADERS).json()), 2
        )
        self.assertEqual(
            service.read_report(self.settings, job)["validated_vulnerability"], 0
        )


    def test_cjson_cve_candidate_runs_through_api_worker_report_and_source_viewer(self):
        source = """static cJSON_bool decode_array_index_from_pointer(const unsigned char * const pointer, size_t * const index) {
            size_t parsed_index = 0;
            size_t position = 0;
            for (position = 0; (pointer[position] >= '0') && (pointer[0] <= '9'); position++) {
                parsed_index = (10 * parsed_index) + (size_t)(pointer[position] - '0');
            }
            if ((pointer[position] != '\\0') && (pointer[position] != '/')) return 0;
            *index = parsed_index;
            return 1;
        }"""
        (self.repo / "cJSON_Utils.c").write_text(source)
        git(self.repo, "add", "cJSON_Utils.c")
        git(self.repo, "commit", "-qm", "add pinned cJSON component fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        job_request = self.queue(detector_ids=["ohscanner.known_disclosed_cves"])
        Worker(self.settings).run(once=True)
        job = self.store.job(job_request["id"])
        self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
        report = service.read_report(self.settings, job)
        diagnostics = report["detector_runs"][0]["diagnostics"]
        candidate = next(item for item in diagnostics if item["symbol"] == "CVE-2025-57052")
        self.assertEqual(candidate["source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(report["validated_vulnerability"], 0)
        viewed = service.source(self.settings, self.store, job, candidate["file"])
        self.assertEqual(viewed["text"], source)
    def test_device_manager_cve_candidate_runs_through_api_worker_report_and_source_viewer(self):
        source = """void DmAuthManager::OnGroupCreated(int64_t requestId, const std::string &groupId) {
            int32_t pinCode = GeneratePincode();
            nlohmann::json jsonObj;
            jsonObj[PIN_CODE_KEY] = pinCode;
            jsonObj[PIN_TOKEN] = authResponseContext_->token;
            authResponseContext_->authToken = jsonObj.dump();
            authMessageProcessor_->SetResponseContext(authResponseContext_);
            std::string message = authMessageProcessor_->CreateSimpleMessage(MSG_TYPE_RESP_AUTH);
            softbusConnector_->GetSoftbusSession()->SendData(authResponseContext_->sessionId, message);
        }"""
        (self.repo / "dm_auth_manager.cpp").write_text(source)
        git(self.repo, "add", "dm_auth_manager.cpp")
        git(self.repo, "commit", "-qm", "add pinned device manager CVE source fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        request = self.queue(detector_ids=["ohscanner.known_disclosed_cves"])
        Worker(self.settings).run(once=True)
        job = self.store.job(request["id"])
        self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
        report = service.read_report(self.settings, job)
        diagnostics = [
            item for run in report["detector_runs"] for item in run["diagnostics"]
            if item["symbol"] == "CVE-2022-45877"
        ]
        self.assertEqual(1, len(diagnostics))
        candidate = diagnostics[0]
        self.assertEqual("CWE-319", candidate["candidate_cwe"])
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), candidate["source_sha256"])
        self.assertEqual(0, report["validated_vulnerability"])
        viewed = service.source(self.settings, self.store, job, candidate["file"])
        self.assertEqual(viewed["text"], source)

    def test_webview_cve_candidate_runs_through_api_worker_report_and_source_viewer(self):
        source = """char *FlowbufStrAtIndex(void *mem, int i, int *argIndex, size_t *strLen) {
            char *header = (char *)mem;
            size_t offset = header[i * INDEX_SIZE];
            *strLen = *(header + (i * INDEX_SIZE) + 1) - 1;
            *argIndex = header[i * INDEX_SIZE + 2];
            return (char *)mem + HEADER_SIZE + offset;
        }
        int ProcessNativeProxyResultNewFlowbuf(Args *args, int flowbufSize, int argIndex) {
            size_t argsSize = args->GetSize();
            std::vector<std::vector<uint8_t>> dataList(argsSize +
                static_cast<size_t>(flowbufSize));
            size_t curIndex = 0;
            char *value = FlowbufStrAtIndex(nullptr, 0, &argIndex, &strLen);
            while (argIndex == curIndex) {
                dataList[curIndex] = {};
            }
            return 0;
        }"""
        (self.repo / "nweb_handler_delegate.cc").write_text(source)
        git(self.repo, "add", "nweb_handler_delegate.cc")
        git(self.repo, "commit", "-qm", "add pinned WebView component fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        job_request = self.queue(detector_ids=["ohscanner.known_disclosed_cves"])
        Worker(self.settings).run(once=True)
        job = self.store.job(job_request["id"])
        self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
        report = service.read_report(self.settings, job)
        diagnostics = report["detector_runs"][0]["diagnostics"]
        candidate = next(item for item in diagnostics if item["symbol"] == "CVE-2026-27648")
        self.assertEqual(candidate["source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(report["validated_vulnerability"], 0)
        viewed = service.source(self.settings, self.store, job, candidate["file"])
        self.assertEqual(viewed["text"], source)

    def test_libpng_neon_cve_candidate_and_fix_run_through_api_worker_report(self):
        fixture_dir = ROOT / "tests" / "fixtures" / "data_sensitive" / "cve_2026_33636"
        relative = Path("arm/palette_neon_intrinsics.c")
        source_path = self.repo / relative
        source_path.parent.mkdir(parents=True)
        vulnerable = (fixture_dir / "libpng-1.6.55-palette_neon_intrinsics.c").read_bytes()
        fixed = (fixture_dir / "libpng-1.6.56-palette_neon_intrinsics.c").read_bytes()

        def scan_blob(blob, message):
            source_path.write_bytes(blob)
            git(self.repo, "add", str(relative))
            git(self.repo, "commit", "-qm", message)
            request = self.queue(detector_ids=["ohscanner.known_disclosed_cves"])
            Worker(self.settings).run(once=True)
            job = self.store.job(request["id"])
            self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
            return job, service.read_report(self.settings, job)

        vulnerable_job, vulnerable_report = scan_blob(vulnerable, "add pinned libpng 1.6.55 source")
        vulnerable_findings = [
            item for run in vulnerable_report["detector_runs"] for item in run["diagnostics"]
            if item["symbol"] == "CVE-2026-33636"
        ]
        self.assertEqual(2, len(vulnerable_findings))
        self.assertTrue(all(item["source_sha256"] == hashlib.sha256(vulnerable).hexdigest()
                            for item in vulnerable_findings))
        self.assertEqual(0, vulnerable_report["validated_vulnerability"])
        viewed = service.source(self.settings, self.store, vulnerable_job, vulnerable_findings[0]["file"])
        self.assertEqual(viewed["text"].encode(), vulnerable)

        _, fixed_report = scan_blob(fixed, "replace with pinned libpng 1.6.56 fixed source")
        fixed_findings = [
            item for run in fixed_report["detector_runs"] for item in run["diagnostics"]
            if item["symbol"] == "CVE-2026-33636"
        ]
        self.assertEqual([], fixed_findings)
        self.assertEqual(0, fixed_report["validated_vulnerability"])

    def test_archived_candidate_runs_through_api_worker_and_source_viewer(self):
        archive_path = self.repo / "vendor" / "sample.tar.gz"
        archive_path.parent.mkdir()
        payload = b'#define PNG_LIBPNG_VER_STRING "1.6.55"\n'
        with tarfile.open(archive_path, "w:gz") as archive:
            member = tarfile.TarInfo("libpng/png.h")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        git(self.repo, "add", "vendor/sample.tar.gz")
        git(self.repo, "commit", "-qm", "add pinned source archive")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        job_request = self.queue(detector_ids=["ohscanner.known_disclosed_cves"])
        Worker(self.settings).run(once=True)
        job = self.store.job(job_request["id"])
        self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
        report = service.read_report(self.settings, job)
        diagnostics = report["detector_runs"][0]["diagnostics"]
        self.assertTrue(any(item["symbol"] == "CVE-2026-46675" for item in diagnostics))
        candidate = next(item for item in diagnostics if item["symbol"] == "CVE-2026-46675")
        self.assertEqual(candidate["source_archive_binding"]["archive_path"], "vendor/sample.tar.gz")
        api_candidate = next(item for item in service.findings(report) if item["symbol"] == "CVE-2026-46675")
        risk = api_candidate["risk_assessment"]
        self.assertEqual("medium", risk["severity"])
        self.assertEqual("unknown", risk["product_applicability"])
        self.assertIn("D30_LIBPNG_CVE_2026_46675_REPORT.md", risk["poc"]["record"])
        self.assertEqual("B9729E5E80D0440AADF606AB29912E8E8811929E06240EDECDF3DDE40DBCDDFA",
                         risk["poc"]["record_sha256"])
        self.assertIn("0/3 ASan", risk["component_retest"]["fixed_poc"])
        detail = self.client.get(f"/api/v1/scans/{job['id']}/findings/{api_candidate['id']}").json()
        self.assertEqual(risk, detail["risk_assessment"])
        self.assertEqual(candidate["source_sha256"], detail["source_sha256"])
        self.assertEqual(report["validated_vulnerability"], 0)
        viewed = service.source(self.settings, self.store, job, candidate["file"])
        self.assertEqual(viewed["text"], payload.decode())
        self.assertIsNone(viewed["blob"])
        self.assertEqual(viewed["archive_binding"]["archive_path"], "vendor/sample.tar.gz")
        self.assertEqual(viewed["archive_binding"]["member_sha256"], candidate["source_sha256"])

    def test_review_cannot_self_promote(self):
        job = self.completed()
        identity = service.findings(service.read_report(self.settings, job))[0]["id"]
        r = self.client.post(
            f"/api/v1/scans/{job['id']}/findings/{identity}/reviews",
            json={"status": "confirmed", "reviewer": "x", "notes": "AI said yes"},
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 422)

    def test_agent_review_queue_binds_entire_report_and_deduplicates(self):
        job = self.completed()
        expected = service.findings(service.read_report(self.settings, job))
        # New scans do not create a non-executable legacy queue pointer; the
        # compatibility endpoint remains explicit and binds the frozen report.
        queued_items = [x for x in self.app.state.operations.list()
                        if x["kind"] == "candidate_review_batch" and x["spec"].get("job_id") == job["id"]]
        self.assertEqual(queued_items, [])
        queued = self.client.post("/api/v1/operations/agent-review-queue",
                                  json={"job_id": job["id"]}, headers=HEADERS)
        self.assertEqual(queued.status_code, 201, queued.text)
        body = queued.json()
        self.assertEqual(body["candidate_count"], len(expected))
        self.assertEqual(body["status"], "queued")
        self.assertFalse(body["model_available"])
        self.assertEqual(body["spec"]["report_sha256"], job["report_sha256"])
        queue_status = self.client.get("/api/v1/operations/agent-review-queue/status")
        self.assertEqual(queue_status.status_code, 200, queue_status.text)
        self.assertEqual(queue_status.json()["queued_batches"], 1)
        self.assertEqual(queue_status.json()["queued_candidates"], len(expected))
        again = self.client.post("/api/v1/operations/agent-review-queue",
                                 json={"job_id": job["id"]}, headers=HEADERS)
        self.assertEqual(again.status_code, 201, again.text)
        self.assertEqual(again.json()["id"], body["id"])
        self.assertEqual(self.app.state.operations.get(body["id"])["status"], "queued")

    def test_agent_proposal_is_append_only_and_requires_exact_fixed_source_citation(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "agent citation binding",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"], "rationale": "test"}],
        }).json()
        source = service.source(self.settings, self.store, job, candidate["file"])
        payload = {
            "candidate_id": candidate["id"], "agent_id": "agent:test",
            "suggestion": "proposed_confirmation", "summary": "hypothesis only",
            "source_commit": job["spec"]["commit"], "source_blob": source["blob"],
            "source_sha256": source["sha256"], "line_start": candidate["line"],
            "line_end": candidate["line"], "supporting_evidence": [{
                "file": candidate["file"], "blob": source["blob"], "source_sha256": source["sha256"],
                "line_start": candidate["line"], "line_end": candidate["line"],
                "observation": "candidate location",
            }], "refuting_evidence": [], "unresolved_obligations": ["product reachability"],
            "provider": "test-fixture", "model_version": "none", "prompt_version": "test-v1",
            "tool_version": "readonly-v1", "run_id": "run-test", "input_tokens": 1,
            "output_tokens": 1, "duration_ms": 1,
        }
        response = self.client.post(f"/api/v1/cases/{case['id']}/agent-assessments",
                                    headers=HEADERS, json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        record = response.json()[-1]
        self.assertEqual(record["record_kind"], "agent_proposal")
        self.assertEqual(record["source_binding"]["blob"], source["blob"])
        self.assertEqual(record["confirmation_effect"], "none; human approval and existing validation gate remain required")
        self.assertIn("caller-supplied", record["model_runtime"]["attestation"])
        self.assertEqual(service.read_report(self.settings, job)["validated_vulnerability"], 0)
        payload["supporting_evidence"][0]["source_sha256"] = "0" * 64
        bad_evidence = self.client.post(f"/api/v1/cases/{case['id']}/agent-assessments",
                                        headers=HEADERS, json=payload)
        self.assertEqual(bad_evidence.status_code, 409)
        payload["supporting_evidence"][0]["source_sha256"] = source["sha256"]
        payload["source_blob"] = "0" * len(source["blob"])
        rejected = self.client.post(f"/api/v1/cases/{case['id']}/agent-assessments",
                                    headers=HEADERS, json=payload)
        self.assertEqual(rejected.status_code, 409)

    def test_agent_assessment_cannot_confirm_or_report(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "agent proposal gate",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"], "rationale": "test"}],
        })
        self.assertEqual(case.status_code, 201, case.text)
        for outcome in ("confirmed", "reportable", "dynamic_reproduced_component_issue"):
            response = self.client.post(f"/api/v1/cases/{case.json()['id']}/assessments", headers=HEADERS, json={
                "outcome": outcome, "reviewer_kind": "agent", "reviewer": "agent:test",
                "notes": "suggestion only", "evidence_ids": [], "validation_operation_ids": [],
                "remaining_unknowns": [],
            })
            self.assertEqual(response.status_code, 409, response.text)
        report = service.read_report(self.settings, job)
        self.assertEqual(report["validated_vulnerability"], 0)


    def test_case_confirmation_rejects_unverified_product_reachability(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "unverified reachability", "links": [{
                "job_id": job["id"], "candidate_id": candidate["id"], "rationale": "test"}],
        }).json()
        evidence = self.client.post(
            f"/api/v1/scans/{job['id']}/findings/{candidate['id']}/evidence",
            headers=HEADERS,
            json={"file": candidate["file"], "start_line": candidate["line"],
                  "end_line": candidate["line"], "note": "source evidence"},
        )
        ops = self.app.state.operations
        validation = ops.create("validation", {"case_id": case["id"]})
        self.assertEqual(ops.claim(validation=True)["id"], validation["id"])
        ops.finish(validation["id"], {
            "status": "completed_with_limitations", "validation_gate": "passed",
            "case_id": case["id"], "reachability_status": "unknown",
        }, state="completed_with_limitations")
        rejected = self.client.post(f"/api/v1/cases/{case['id']}/assessments", headers=HEADERS, json={
            "outcome": "confirmed", "reviewer_kind": "human", "reviewer": "reviewer:test",
            "notes": "Attempted without product reachability", "evidence_ids": [evidence.json()["id"]],
            "validation_operation_ids": [validation["id"]], "remaining_unknowns": ["scope"],
        })
        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertEqual(self.client.get(f"/api/v1/cases/{case['id']}/report.json").json()
                         ["validated_vulnerability"], 0)

    def test_case_report_exposes_agent_and_fixed_harness_evidence_without_promotion(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "case report evidence view",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"], "rationale": "inspect fixed evidence"}],
        }).json()
        self.store.add_source_evidence(job["id"], candidate["id"], {
            "file": candidate["file"], "start_line": candidate["line"], "end_line": candidate["line"],
            "note": "Reviewer-recorded source location",
        })
        self.store.add_review(job["id"], candidate["id"], "needs_more_evidence",
                              "reviewer:test", "Product entry still needs review.", 0)

        ops = self.app.state.operations
        agent = ops.create("agent_investigation", {
            "case_id": case["id"], "job_id": job["id"], "candidate_id": candidate["id"],
            "experiment_id": "case-report-eval", "report_sha256": job["report_sha256"],
            "source_commit": self.commit, "candidate_source_sha256": candidate["source_sha256"],
        })
        self.assertEqual(ops.claim()["id"], agent["id"])
        ops.finish(agent["id"], {
            "status": "completed", "case_id": case["id"], "vulnerability_state": "candidate",
            "validated_vulnerability": 0, "mode": "tool_agent", "experiment_id": "case-report-eval",
            "binding": {"job_id": job["id"], "report_sha256": job["report_sha256"],
                        "source_sha256": candidate["source_sha256"],
                        "repository": "fixture/sample", "commit": self.commit,
                        "file": candidate["file"], "line": candidate["line"],
                        "candidate_id": candidate["id"]},
            "summary_provenance": "server_generated_from_structured_triage",
            "initial_evidence": {"evidence_id": "evidence-1", "context": {
                "file": candidate["file"], "evidence_obligations": [{"kind": "reachability", "description": "Trace product entry."}],
            }},
            "knowledge_retrieval": {"status": "matched", "algorithm": "bm25-k1.5-b0.75-v1",
                "corpus_sha256": "1" * 64, "indexed_files": 2,
                "disclaimer": "Knowledge material is analogical only.",
                "references": [{"path": "04_D线/CVE回放与PoC/example.md", "start_line": 5,
                    "end_line": 7, "summary": "Component-only CVE harness example.",
                    "sha256": "2" * 64, "score": 1.2, "excerpt": "CVE reference excerpt."}]},
            "knowledge_references": [{"path": "04_D线/CVE回放与PoC/example.md", "start_line": 5,
                "end_line": 7, "summary": "Component-only CVE harness example.",
                "sha256": "2" * 64, "score": 1.2, "excerpt": "CVE reference excerpt."}],
            "tool_calls": [{"tool": "read_source", "status": "completed"}],
            "model_calls": [{"model": "test-model"}], "model_usage": {"input_tokens": 10, "output_tokens": 4},
            "agent_assessment": {
                "assessment": "needs_more_evidence", "summary": "Trace the product entry.",
                "supported_claims": [{"claim": "A guarded source branch exists.", "obligation_indices": [0],
                                      "citations": [{"evidence_id": "evidence-1", "quote": "if (guard)"}]}],
                "obligation_reviews": [{"obligation_index": 0, "disposition": "unresolved", "citations": []}],
                "unknowns": ["Whether an external caller reaches this path."],
                "unsupported_claims": ["A remote attacker can reach it."],
                "next_steps": ["Review the product entry path."],
                "vulnerability_report": {"status": "draft_unverified", "title": "Candidate report",
                    "citations": [{"file": candidate["file"], "line_start": candidate["line"], "line_end": candidate["line"]}]},
                "poc_draft": {"status": "insufficient_evidence", "code": "", "citations": []},
            },
            "limitations": ["Product reachability is unknown."],
        }, state="completed")
        ops.record_agent_review(agent["id"], {
            "reviewer": "reviewer:test", "usefulness": "partially_useful",
            "citation_accuracy": "all_accurate", "claim_adjudications": [
                {"claim_index": 0, "disposition": "supported"}],
            "post_review_disposition": "investigate", "elapsed_seconds": 35,
            "notes": "Source citation was useful; keep reachability open.",
        })

        validation = ops.create("validation", {
            "case_id": case["id"], "harness_id": "auth01_descriptor_bypass",
            "target_repository": "fixture/sample", "target_commit": self.commit,
            "cutils_commit": "c" * 40,
        })
        self.assertEqual(ops.claim(validation=True)["id"], validation["id"])
        ops.finish(validation["id"], {
            "status": "completed_with_limitations", "case_id": case["id"],
            "validation_gate": "passed", "gate_reason": "fixed revision controls passed",
            "reachability_status": "unknown", "validated_vulnerability": 0,
            "input_manifest_sha256": "a" * 64, "validation_command_sha256": "b" * 64,
            "docker_log_sha256": "d" * 64, "docker_exit_code": 0,
            "result": {"harness": "auth01_descriptor_bypass", "family": "AUTH-01",
                "revisions": {"vulnerable": {
                    "commit": "e" * 40, "state": "stable_reproduced",
                    "build": {"compiler": "clang++", "compiler_version": "test", "sanitizers": ["address"], "returncode": 0},
                    "replay": {"label": "stable_reproduced", "attempts": 3, "triggered": 3, "all_cases_match": True,
                               "cases": [{"case_id": "no_token", "role": "attack", "expected": "trigger",
                                          "observed": ["trigger"] * 3, "matches_expectation": [True] * 3}]},
                    "expectations_met": {"no_token": True},
                }}},
            "patched_revision": {"synthetic_commit": "f" * 40, "base_commit": "e" * 40,
                                 "fixed_commit": "5" * 40, "patch_sha256": "9" * 64},
            "limitations": ["Harness calls the stub directly; product entry reachability is not proven."],
        }, state="completed_with_limitations")

        response = self.client.get(f"/api/v1/cases/{case['id']}/report.json")
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["validated_vulnerability"], 0)
        self.assertEqual(data["candidates"][0]["source_evidence"][0]["note"], "Reviewer-recorded source location")
        self.assertEqual(data["candidates"][0]["reviews"][0]["status"], "needs_more_evidence")
        agent_row = next(item for item in data["operations"] if item["id"] == agent["id"])
        agent_triage = agent_row["agent_triage"]
        self.assertEqual(agent_triage["knowledge_references"][0]["path"],
                         "04_D线/CVE回放与PoC/example.md")
        self.assertEqual(agent_triage["knowledge_retrieval"]["corpus_sha256"], "1" * 64)
        validation_row = next(item for item in data["operations"] if item["id"] == validation["id"])
        evidence = validation_row["validation_evidence"]
        self.assertEqual(evidence["harness_id"], "auth01_descriptor_bypass")
        self.assertEqual(evidence["revisions"]["vulnerable"]["replay_cases"][0]["case_id"], "no_token")
        self.assertEqual(evidence["docker_log_sha256"], "d" * 64)
        self.assertEqual(validation_row["reachability_status"], "unknown")
        self.assertEqual(validation_row["validated_vulnerability"], 0)

        markdown = self.client.get(f"/api/v1/cases/{case['id']}/report.md")
        self.assertEqual(markdown.status_code, 200, markdown.text)
        self.assertIn("人工登记源码证据", markdown.text)
        self.assertIn("智能调查漏洞报告草案", markdown.text)
        self.assertIn("知识库参考资料（不属于当前源码证据）", markdown.text)
        self.assertIn("04\\_D线/CVE回放与PoC/example\\.md", markdown.text)
        self.assertIn("CVE reference excerpt\\.", markdown.text)
        self.assertIn("固定隔离测试环境：auth01\\_descriptor\\_bypass", markdown.text)
        self.assertIn("案例 no", markdown.text)
        self.assertIn("经门控确认的漏洞数：0", markdown.text)
        self.assertIn("漏洞数：0", markdown.text)
        self.assertIn("产品入口可达性保持未知", markdown.text)


    def test_case_report_queries_exact_case_and_discloses_more_than_twenty_operations(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "case report operation truncation",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"], "rationale": "test"}],
        }).json()
        ops = self.app.state.operations
        for index in range(25):
            operation = ops.create("validation", {"case_id": case["id"], "test_index": index})
            self.assertEqual(ops.claim(validation=True)["id"], operation["id"])
            ops.finish(operation["id"], {
                "status": "completed_with_limitations", "case_id": case["id"],
                "validation_gate": "not_passed", "reachability_status": "unknown",
                "validated_vulnerability": 0, "test_index": index,
            }, state="completed_with_limitations")

        # More recent unrelated operations used to push this case outside the
        # global 200-row list before the report applied its case_id filter.
        with self.store.connect() as db:
            for index in range(205):
                db.execute(
                    "INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                    (f"{index:032x}", "investigation", json.dumps({"case_id": "another-case"}),
                     "completed", "2099-01-01T00:00:00Z"),
                )

        report = self.client.get(f"/api/v1/cases/{case['id']}/report.json")
        self.assertEqual(report.status_code, 200, report.text)
        data = report.json()
        self.assertEqual(len(data["operations"]), 20)
        self.assertEqual(data["operation_summaries"], {
            "total": 25, "included": 20, "truncated": True, "limit": 20,
        })
        self.assertTrue(all(item["kind"] == "validation" for item in data["operations"]))
        markdown = self.client.get(f"/api/v1/cases/{case['id']}/report.md")
        self.assertEqual(markdown.status_code, 200, markdown.text)
        self.assertIn("展示 20 / 25 条", markdown.text)
        self.assertIn("最近 20 条结果", markdown.text)
        self.assertIn("未展开的 5 条操作仍存在", markdown.text)
        self.assertEqual(data["validated_vulnerability"], 0)


    def test_case_report_exports_structured_agent_drafts_and_escaped_html_manifest(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "structured export case",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"], "rationale": "review"}],
        }).json()
        ops = self.app.state.operations
        operation = ops.create("agent_investigation", {
            "case_id": case["id"], "job_id": job["id"], "candidate_id": candidate["id"],
            "source_commit": job["spec"]["commit"], "report_sha256": job["report_sha256"],
            "candidate_source_sha256": candidate["source_sha256"],
        })
        self.assertEqual(ops.claim()["id"], operation["id"])
        hostile = "<script>alert(1)</script><img src=x onerror=alert(2)>"
        ops.finish(operation["id"], {
            "status": "completed", "case_id": case["id"], "vulnerability_state": "candidate",
            "binding": {"job_id": job["id"], "candidate_id": candidate["id"], "commit": job["spec"]["commit"], "report_sha256": job["report_sha256"], "source_sha256": candidate["source_sha256"]},
            "validated_vulnerability": 0, "artifact_generation": {"status": "completed", "calls_used": 1},
            "agent_assessment": {
                "assessment": "needs_more_evidence", "summary": "fixed source needs review",
                "supported_claims": [], "obligation_reviews": [], "unknowns": ["Product reachability"],
                "unsupported_claims": [], "next_steps": ["Review the fixed product entry."],
                "vulnerability_report": {
                    "status": "draft_unverified", "title": hostile,
                    "summary": "Candidate summary", "root_cause": "Root cause draft",
                    "impact": "unknown", "preconditions": ["Reviewed build required"],
                    "attack_path": ["Trace the call path"], "remediation": "Add authorization check",
                    "citations": [{"evidence_id": "evidence-1", "file": "src/example.cpp",
                                   "line_start": 4, "line_end": 6, "quote": hostile}],
                },
                "poc_draft": {
                    "status": "draft_unexecuted", "title": "Local regression draft", "language": "cpp",
                    "code": "<script>alert(3)</script>\n```\nreturn;\n```",
                    "prerequisites": ["Use a disposable local build"],
                    "run_steps": ["Review the draft; do not execute automatically."],
                    "expected_observation": "The fixed guard rejects the input.",
                    "negative_control": "A safe input remains accepted.",
                    "citations": [{"evidence_id": "evidence-2", "file": "src/example.cpp",
                                   "line_start": 8, "line_end": 9, "quote": "if (safe)"}],
                },
            },
        }, state="completed")

        markdown = self.client.get(f"/api/v1/cases/{case['id']}/report.md")
        self.assertEqual(markdown.status_code, 200, markdown.text)
        self.assertIn("智能调查漏洞报告草案与验证用例（PoC）计划", markdown.text)
        self.assertIn("Root cause draft", markdown.text)
        self.assertIn("Add authorization check", markdown.text)
        self.assertIn("验证用例（PoC）计划（智能调查草案，未执行）", markdown.text)
        self.assertIn("未执行、未验证；当前仍为候选 / 未知", markdown.text)
        self.assertIn("Local regression draft", markdown.text)
        self.assertIn("固定隔离测试结果另列", markdown.text)

        html_report = self.client.get(f"/api/v1/cases/{case['id']}/report.html")
        self.assertEqual(html_report.status_code, 200, html_report.text)
        self.assertIn("text/html", html_report.headers["content-type"])
        self.assertIn("智能调查草案 · 未执行 · 未验证 · 候选 / 未知", html_report.text)
        self.assertIn("Root cause draft", html_report.text)
        self.assertIn("Add authorization check", html_report.text)
        self.assertIn("&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;", html_report.text)
        self.assertIn("&amp;lt;img src=x onerror=alert(2)&amp;gt;", html_report.text)
        self.assertNotIn("<script>alert(1)</script>", html_report.text)
        self.assertNotIn("<img src=x onerror=alert(2)>", html_report.text)

        manifest_response = self.client.get(f"/api/v1/cases/{case['id']}/manifest.json")
        self.assertEqual(manifest_response.status_code, 200, manifest_response.text)
        manifest = manifest_response.json()
        self.assertEqual(set(manifest["artifacts"]), {"report.json", "report.md", "report.html"})
        for artifact, endpoint in (
            ("report.json", "report.json"), ("report.md", "report.md"), ("report.html", "report.html")
        ):
            response = self.client.get(f"/api/v1/cases/{case['id']}/{endpoint}")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(manifest["artifacts"][artifact]["sha256"], hashlib.sha256(response.content).hexdigest())
            self.assertEqual(manifest["artifacts"][artifact]["size_bytes"], len(response.content))
        self.assertEqual(manifest["scope"]["validated_vulnerability"], 0)


    def test_combined_audit_markdown_discloses_risk_detail_truncation(self):
        from src.workbench.operations_api import _combined_audit_report_markdown

        items = [{
            "risk_tier_label": "高可信候选", "detector_id": "test.detector", "rule_id": "test.rule",
            "candidate_id": f"candidate{index}", "file": f"src/file-{index}.cpp", "line": index + 1,
            "source_sha256": f"{index:064x}", "triage": {"state": "not_triaged"},
            "reasons": ["fixed source review needed"],
        } for index in range(25)]
        document = {
            "report_snapshot_id": "snapshot-1", "report_snapshot_sha256": "a" * 64,
            "scan": {"report_sha256": "b" * 64, "repository": "fixture/sample", "commit": "c" * 40,
                     "tree": "d" * 40, "status": "completed"},
            "triage": {"state": "not_triaged", "authorization": None},
            "validated_vulnerability": 0,
            "risk_snapshot": {"counts": {"high_confidence_candidate": 25}, "items": items,
                              "limitations": []},
            "coverage": {"source_parsing": {}}, "limitations": [],
        }
        markdown = _combined_audit_report_markdown(document)
        self.assertIn("统计覆盖 25 条候选观测；本节仅展示前 20 条明细，另有 5 条明细未展开", markdown)
        self.assertIn("candidate19", markdown)
        self.assertNotIn("candidate20", markdown)

    def test_case_links_require_existing_run_candidates(self):
        job = self.completed()
        identity = service.findings(service.read_report(self.settings, job))[0]["id"]
        data = {
            "title": "Investigate common root cause",
            "links": [
                {
                    "job_id": job["id"],
                    "candidate_id": identity,
                    "rationale": "same reviewed object",
                }
            ],
        }
        r = self.client.post("/api/v1/cases", json=data, headers=HEADERS)
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["status"], "investigation")
        data["links"][0]["candidate_id"] = "invalid"
        self.assertEqual(
            self.client.post("/api/v1/cases", json=data, headers=HEADERS).status_code,
            404,
        )

    def test_export_binds_review_and_report(self):
        job = self.completed()
        r = self.client.get(f"/api/v1/scans/{job['id']}/artifacts/review.json")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["scanner_report_sha256"], job["report_sha256"])
        self.assertEqual(r.json()["commit"], self.commit)

    def test_retry_freezes_original_commit(self):
        job = self.completed()
        (self.repo / "private.txt").write_text("new")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "new")
        retry = self.client.post(
            f"/api/v1/scans/{job['id']}/retry", headers=HEADERS
        ).json()
        self.assertEqual(retry["spec"]["commit"], self.commit)
        self.assertEqual(retry["spec"]["retry_of"], job["id"])

    def test_engine_drift_fails_instead_of_reusing_claim(self):
        job = self.queue()
        with self.store.connect() as db:
            spec = copy.deepcopy(job["spec"])
            spec["engine_sha256"] = "0" * 64
            db.execute(
                "UPDATE jobs SET spec=? WHERE id=?", (json.dumps(spec), job["id"])
            )
        Worker(self.settings).run(once=True)
        result = self.store.job(job["id"])
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["report_sha256"])

    def test_hard_timeout_kills_process(self):
        job = self.queue(timeout_seconds=1)
        claimed = self.store.claim()
        real_popen = subprocess.Popen
        processes = []

        def sleeper(*args, **kwargs):
            proc = real_popen(
                ["/usr/bin/python3", "-c", "import time; time.sleep(30)"], **kwargs
            )
            processes.append(proc)
            return proc

        start = time.monotonic()
        with (
            patch("src.workbench.worker.check_repository", return_value=self.repo),
            patch("src.workbench.worker.subprocess.Popen", side_effect=sleeper),
        ):
            Worker(self.settings).execute(claimed)
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(self.store.job(job["id"])["status"], "timed_out")
        self.assertIsNotNone(processes[0].poll())

    def test_running_cancel_kills_process(self):
        job = self.queue()
        claimed = self.store.claim()
        real_popen = subprocess.Popen
        processes = []

        def sleeper(*args, **kwargs):
            proc = real_popen(
                ["/usr/bin/python3", "-c", "import time; time.sleep(30)"], **kwargs
            )
            processes.append(proc)
            return proc

        thread = threading.Thread(
            target=lambda: (time.sleep(0.3), self.store.cancel(job["id"]))
        )
        thread.start()
        with (
            patch("src.workbench.worker.check_repository", return_value=self.repo),
            patch("src.workbench.worker.subprocess.Popen", side_effect=sleeper),
        ):
            Worker(self.settings).execute(claimed)
        thread.join()
        self.assertEqual(self.store.job(job["id"])["status"], "cancelled")
        self.assertIsNotNone(processes[0].poll())

    def test_source_evidence_binds_original_blob_and_survives_restart(self):
        job = self.completed()
        item = service.findings(service.read_report(self.settings, job))[0]
        path = f"/api/v1/scans/{job['id']}/findings/{item['id']}/evidence"
        r = self.client.post(
            path,
            json={
                "file": item["file"],
                "start_line": item["line"],
                "end_line": item["line"],
                "note": "Context only; no reachability proof",
            },
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 201, r.text)
        record = r.json()
        self.assertEqual(record["commit"], self.commit)
        self.assertEqual(record["source_sha256"], item["evidence"]["source_sha256"])
        self.assertEqual(record["excerpt_sha256"], service.sha(record["text"].encode()))
        self.assertEqual(
            Store(self.settings.data_dir).source_evidence(job["id"], item["id"])[0][
                "id"
            ],
            record["id"],
        )
        bundle = service.review_bundle(self.settings, self.store, job)
        self.assertEqual(bundle["supplemental_evidence"][0]["id"], record["id"])
        self.assertEqual(bundle["validated_vulnerability"], 0)

    def test_source_evidence_rejects_out_of_scope_and_bad_range(self):
        job = self.completed()
        item = service.findings(service.read_report(self.settings, job))[0]
        path = f"/api/v1/scans/{job['id']}/findings/{item['id']}/evidence"
        for file, start, end in [
            ("private.txt", 1, 1),
            (item["file"], 1, 100000),
            (item["file"], 2, 1),
            ("../escape", 1, 1),
        ]:
            r = self.client.post(
                path,
                json={
                    "file": file,
                    "start_line": start,
                    "end_line": end,
                    "note": "context",
                },
                headers=HEADERS,
            )
            self.assertEqual(r.status_code, 409, r.text)
        self.assertEqual(self.store.source_evidence(job["id"]), [])

    def test_evidence_cannot_attach_to_other_candidate(self):
        job = self.completed()
        r = self.client.post(
            f"/api/v1/scans/{job['id']}/findings/forged/evidence",
            json={
                "file": "lifetime.cpp",
                "start_line": 1,
                "end_line": 1,
                "note": "forged",
            },
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.store.source_evidence(job["id"]), [])

    def test_case_can_append_existing_candidates_without_overwrite(self):
        job = self.completed()
        items = service.findings(service.read_report(self.settings, job))
        self.assertGreaterEqual(len(items), 2)

        def link(item):
            return {
                "job_id": job["id"],
                "candidate_id": item["id"],
                "rationale": "manual association only",
            }

        case = self.client.post(
            "/api/v1/cases",
            json={"title": "test investigation", "links": [link(items[0])]},
            headers=HEADERS,
        ).json()
        path = f"/api/v1/cases/{case['id']}/links"
        r = self.client.post(path, json={"links": [link(items[1])]}, headers=HEADERS)
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(len(r.json()["links"]), 2)
        self.assertEqual(
            self.client.post(
                path, json={"links": [link(items[1])]}, headers=HEADERS
            ).status_code,
            409,
        )
        self.assertEqual(len(self.store.cases()[0]["links"]), 2)

    def test_cancel_at_atomic_publication_discards_report(self):
        job = self.queue()
        self.store.claim()
        self.store.cancel(job["id"])
        self.store.finish(job["id"], "completed", report_sha256="f" * 64)
        result = self.store.job(job["id"])
        self.assertEqual(result["status"], "cancelled")
        self.assertIsNone(result["report_sha256"])

    def test_second_worker_cannot_recover_live_jobs(self):
        import fcntl

        job = self.queue()
        self.store.claim()
        with (self.settings.data_dir / "worker.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, "another Worker"):
                Worker(self.settings).run(once=True)
        self.assertEqual(self.store.job(job["id"])["status"], "running")

    def test_health_measures_lock_not_old_lock_file(self):
        import fcntl

        lock_path = self.settings.data_dir / "worker.lock"
        lock_path.touch()
        self.assertFalse(self.client.get("/api/v1/health").json()["worker_running"])
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(self.client.get("/api/v1/health").json()["worker_running"])

    def test_manifest_export_matches_committed_artifacts(self):
        job = self.completed()
        r = self.client.get(f"/api/v1/scans/{job['id']}/artifacts/manifest.json")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["artifacts"]["report.json"], job["report_sha256"])
        self.assertEqual(r.json()["spec"]["commit"], self.commit)

    def test_missing_repository_returns_explicit_error(self):
        r = self.client.post(
            "/api/v1/repositories",
            json={"name": "fixture/missing", "path": str(self.repo.parent / "missing")},
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 409)

    def test_case_confirmation_rejects_multi_candidate_case(self):
        job = self.completed()
        candidates = service.findings(service.read_report(self.settings, job))
        self.assertGreaterEqual(len(candidates), 2)
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "multi-candidate case cannot confirm as a whole",
            "links": [{"job_id": job["id"], "candidate_id": item["id"], "rationale": "test"}
                      for item in candidates[:2]],
        }).json()
        first = candidates[0]
        evidence = self.client.post(
            f"/api/v1/scans/{job['id']}/findings/{first['id']}/evidence",
            headers=HEADERS,
            json={"file": first["file"], "start_line": first["line"],
                  "end_line": first["line"], "note": "evidence for only the first candidate"},
        )
        self.assertEqual(evidence.status_code, 201, evidence.text)
        validation = self.app.state.operations.create("validation", {"case_id": case["id"]})
        self.assertEqual(self.app.state.operations.claim(validation=True)["id"], validation["id"])
        self.app.state.operations.finish(validation["id"], {
            "status": "completed_with_limitations", "validation_gate": "passed",
            "case_id": case["id"], "reachability_status": "verified",
        }, state="completed_with_limitations")
        rejected = self.client.post(f"/api/v1/cases/{case['id']}/assessments", headers=HEADERS, json={
            "outcome": "confirmed", "reviewer_kind": "human", "reviewer": "reviewer:test",
            "notes": "Only one linked candidate has source evidence.",
            "evidence_ids": [evidence.json()["id"]], "validation_operation_ids": [validation["id"]],
            "remaining_unknowns": ["the other candidate was not reviewed"],
        })
        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertIn("one case per candidate", rejected.text)
        report = self.client.get(f"/api/v1/cases/{case['id']}/report.json").json()
        self.assertEqual(report["validated_vulnerability"], 0)


    def test_case_report_missing_or_mismatched_source_stays_unknown(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "source integrity gate", "links": [{"job_id": job["id"],
                "candidate_id": candidate["id"], "rationale": "fixed source check"}],
        })
        self.assertEqual(case.status_code, 201, case.text)
        case_id = case.json()["id"]
        with patch("src.workbench.operations_api.service.source", side_effect=ValueError("source missing")):
            missing = self.client.get(f"/api/v1/cases/{case_id}/report.json").json()
            missing_markdown = self.client.get(f"/api/v1/cases/{case_id}/report.md")
        row = missing["candidates"][0]
        self.assertEqual(row["source_anchor"]["state"], "unknown")
        self.assertFalse(row["source_anchor"].get("verified", False))
        self.assertEqual(row["remediation_draft"]["state"], "unknown")
        self.assertIsNone(row["remediation_draft"]["draft"])
        self.assertIsNone(row["remediation_draft"]["source_anchor"])
        self.assertEqual(row["poc_plan"]["state"], "unknown")
        self.assertEqual(row["poc_plan"]["steps"], [])
        self.assertFalse(row["poc_plan"]["execution"]["executed"])
        self.assertEqual(row["risk"]["vulnerability_state"], "candidate")
        self.assertEqual(missing["poc_status"]["state"], "unknown")
        self.assertEqual(missing["validated_vulnerability"], 0)
        self.assertEqual(missing_markdown.status_code, 200, missing_markdown.text)
        self.assertIn("固定源码锚点：未知", missing_markdown.text)
        self.assertIn("验证计划状态：未知", missing_markdown.text)

        mismatched_source = {"file": candidate["file"], "commit": job["spec"]["commit"],
                             "sha256": "0" * 64, "text": "int forged_evidence;"}
        with patch("src.workbench.operations_api.service.source", return_value=mismatched_source):
            mismatch = self.client.get(f"/api/v1/cases/{case_id}/report.json").json()
            mismatch_markdown = self.client.get(f"/api/v1/cases/{case_id}/report.md")
        row = mismatch["candidates"][0]
        self.assertEqual(row["source_anchor"]["state"], "unknown")
        self.assertIn("不匹配", row["source_anchor"]["reason"])
        self.assertEqual(row["remediation_draft"]["state"], "unknown")
        self.assertEqual(row["poc_plan"]["state"], "unknown")
        self.assertEqual(row["poc_plan"]["steps"], [])
        self.assertEqual(row["risk"]["vulnerability_state"], "candidate")
        self.assertEqual(mismatch["validated_vulnerability"], 0)
        self.assertEqual(mismatch_markdown.status_code, 200, mismatch_markdown.text)
        self.assertNotIn("forged_evidence", mismatch_markdown.text)
        self.assertIn("固定源码锚点：未知", mismatch_markdown.text)
        self.assertIn("验证计划状态：未知", mismatch_markdown.text)

        forged_content_source = {"file": candidate["file"], "commit": job["spec"]["commit"],
                                 "sha256": candidate["source_sha256"],
                                 "text": "int content_hash_does_not_match_metadata;"}
        with patch("src.workbench.operations_api.service.source", return_value=forged_content_source):
            content_mismatch = self.client.get(f"/api/v1/cases/{case_id}/report.json").json()
            content_mismatch_markdown = self.client.get(f"/api/v1/cases/{case_id}/report.md")
        row = content_mismatch["candidates"][0]
        self.assertEqual(row["source_anchor"]["state"], "unknown")
        self.assertIn("哈希不匹配", row["source_anchor"]["reason"])
        self.assertEqual(row["remediation_draft"]["state"], "unknown")
        self.assertEqual(row["poc_plan"]["steps"], [])
        self.assertNotIn("content_hash_does_not_match_metadata", content_mismatch_markdown.text)



    def test_case_report_recovers_only_exact_fixed_candidate_agent_results(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        source = service.source(self.settings, self.store, job, candidate["file"])
        ops = self.app.state.operations
        fixed_spec = {
            "job_id": job["id"], "candidate_id": candidate["id"], "case_id": None,
            "report_sha256": job["report_sha256"], "source_commit": job["spec"]["commit"],
            "candidate_source_sha256": source["sha256"], "mode": "single_shot",
        }
        good = ops.create("agent_investigation", fixed_spec)
        self.assertEqual(ops.claim()["id"], good["id"])
        good_binding = {"job_id": job["id"], "candidate_id": candidate["id"],
            "report_sha256": job["report_sha256"], "commit": job["spec"]["commit"],
            "source_sha256": source["sha256"]}
        ops.finish(good["id"], {"status": "completed", "binding": good_binding,
            "vulnerability_state": "candidate", "validated_vulnerability": 0,
            "agent_assessment": {"assessment": "needs_more_evidence",
                                 "summary": "Synthetic hypothesis only"}},
            state="completed_with_limitations")

        wrong_result = ops.create("agent_investigation", fixed_spec)
        self.assertEqual(ops.claim()["id"], wrong_result["id"])
        ops.finish(wrong_result["id"], {"status": "completed", "binding": {
            **good_binding, "source_sha256": "0" * 64}, "vulnerability_state": "candidate"},
            state="completed_with_limitations")

        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "candidate linked after investigation",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"],
                       "rationale": "fixed candidate report <script>alert(1)</script>"}],
        })
        self.assertEqual(case.status_code, 201, case.text)
        case_id = case.json()["id"]
        report = self.client.get(f"/api/v1/cases/{case_id}/report.json")
        self.assertEqual(report.status_code, 200, report.text)
        body = report.json()
        self.assertEqual(body["schema_version"], 2)
        self.assertEqual(len(body["candidates"]), 1)
        candidate_report = body["candidates"][0]
        self.assertEqual(candidate_report["risk"]["vulnerability_state"], "candidate")
        self.assertEqual(candidate_report["risk"]["risk_tier"], "further_validation")
        self.assertTrue(candidate_report["source_anchor"]["verified"])
        self.assertEqual(candidate_report["source_anchor"]["commit"], job["spec"]["commit"])
        self.assertEqual(candidate_report["source_anchor"]["source_sha256"], candidate["source_sha256"])
        self.assertEqual(candidate_report["remediation_draft"]["state"], "draft_unverified")
        self.assertIn("source_anchor", candidate_report["remediation_draft"])
        self.assertEqual(candidate_report["poc_plan"]["state"], "plan_only")
        self.assertFalse(candidate_report["poc_plan"]["execution"]["requested"])
        self.assertFalse(candidate_report["poc_plan"]["execution"]["queued"])
        self.assertFalse(candidate_report["poc_plan"]["execution"]["executed"])
        self.assertTrue(all(step["source_anchor"]["anchor_id"] == candidate_report["source_anchor"]["anchor_id"]
                            and step["source_anchor"]["commit"] == candidate_report["source_anchor"]["commit"]
                            and step["source_anchor"]["source_sha256"] == candidate_report["source_anchor"]["source_sha256"]
                            for step in candidate_report["poc_plan"]["steps"]))
        self.assertEqual(body["poc_status"]["state"], "not_run")
        self.assertIn("未执行", body["poc_status"]["label"])
        self.assertEqual([item["id"] for item in body["operations"]], [good["id"]])
        triage = body["operations"][0]["agent_triage"]
        self.assertEqual(triage["summary"], "")
        self.assertEqual(triage["citation_review"]["state"], "unknown")
        self.assertEqual(triage["supported_claims"], [])
        self.assertEqual(triage["next_steps"], [])
        self.assertEqual(body["validated_vulnerability"], 0)
        markdown = self.client.get(f"/api/v1/cases/{case_id}/report.md")
        self.assertEqual(markdown.status_code, 200, markdown.text)
        self.assertIn("验证用例 / 受控验证", markdown.text)
        self.assertIn("安全验证计划", markdown.text)
        self.assertIn("计划已生成", markdown.text)
        self.assertIn("修复建议草案（未验证", markdown.text)
        self.assertIn("观测状态：候选（单条观测保持候选；案例人工结论单独记录）", markdown.text)
        self.assertIn("智能调查建议：未知", markdown.text)
        self.assertIn("智能调查源码依据状态：未知", markdown.text)
        html_report = self.client.get(f"/api/v1/cases/{case_id}/report.html")
        self.assertEqual(html_report.status_code, 200, html_report.text)
        self.assertTrue(html_report.headers["content-disposition"].startswith("inline;"))
        self.assertIn("<h1>OHScanner", html_report.text)
        self.assertIn("&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;", html_report.text)
        self.assertNotIn("<script>alert(1)</script>", html_report.text)
        self.assertIn("default-src 'none'", html_report.headers["content-security-policy"])
        manifest = self.client.get(f"/api/v1/cases/{case_id}/report.manifest.json")
        self.assertEqual(manifest.status_code, 200, manifest.text)
        manifest_body = manifest.json()
        canonical_json = json.dumps(body, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")
        self.assertEqual(manifest_body["artifacts"]["report.json"]["sha256"],
                         hashlib.sha256(canonical_json).hexdigest())
        self.assertEqual(manifest_body["artifacts"]["report.md"]["sha256"],
                         hashlib.sha256(markdown.content).hexdigest())
        self.assertEqual(manifest_body["artifacts"]["report.html"]["sha256"],
                         hashlib.sha256(html_report.content).hexdigest())
        self.assertEqual(manifest_body["source_bindings"][0]["candidate_id"], candidate["id"])
        self.assertEqual(manifest_body["source_bindings"][0]["commit"], job["spec"]["commit"])
        self.assertEqual(manifest_body["source_bindings"][0]["vulnerability_state"], "candidate")
        bundle = self.client.get(f"/api/v1/cases/{case_id}/report.bundle.zip")
        self.assertEqual(bundle.status_code, 200, bundle.text)
        self.assertEqual(bundle.headers["content-type"], "application/zip")
        with zipfile.ZipFile(io.BytesIO(bundle.content)) as archive:
            self.assertEqual(set(archive.namelist()), {
                "report.json", "report.md", "report.html", "manifest.json"})
            bundled_json = archive.read("report.json")
            bundled_markdown = archive.read("report.md")
            bundled_html = archive.read("report.html")
            bundled_manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(bundled_manifest["artifacts"]["report.json"]["sha256"],
                             hashlib.sha256(bundled_json).hexdigest())
            self.assertEqual(bundled_manifest["artifacts"]["report.md"]["sha256"],
                             hashlib.sha256(bundled_markdown).hexdigest())
            self.assertEqual(bundled_manifest["artifacts"]["report.html"]["sha256"],
                             hashlib.sha256(bundled_html).hexdigest())
            self.assertEqual(json.loads(bundled_json)["case_id"], case_id)

        queued_validation = ops.create("validation", {"case_id": case_id})
        queued_report = self.client.get(f"/api/v1/cases/{case_id}/report.json")
        self.assertEqual(queued_report.status_code, 200, queued_report.text)
        self.assertEqual(queued_report.json()["poc_status"]["state"], "queued")
        validation_summary = next(item for item in queued_report.json()["operations"]
                                  if item["id"] == queued_validation["id"])
        self.assertEqual(validation_summary["status"], "queued")
        self.assertEqual(validation_summary["validation_gate"], None)



    def test_case_report_rejects_agent_citation_not_in_fixed_source(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        source = service.source(self.settings, self.store, job, candidate["file"])
        ops = self.app.state.operations
        spec = {"job_id": job["id"], "candidate_id": candidate["id"], "case_id": None,
                "report_sha256": job["report_sha256"], "source_commit": job["spec"]["commit"],
                "candidate_source_sha256": source["sha256"], "mode": "single_shot"}
        operation = ops.create("agent_investigation", spec)
        self.assertEqual(ops.claim()["id"], operation["id"])
        binding = {"job_id": job["id"], "candidate_id": candidate["id"],
                   "report_sha256": job["report_sha256"], "commit": job["spec"]["commit"],
                   "source_sha256": source["sha256"]}
        result = {"status": "completed", "binding": binding,
                  "vulnerability_state": "candidate", "validated_vulnerability": 0,
                  "citation_integrity": {"quote_presence": "verified_for_all_citations",
                                          "citation_count": 1,
                                          "semantic_support": "unverified_by_machine"},
                  "initial_evidence": {"evidence_id": "ev-source-fixed-test",
                      "evidence_kind": "source_code", "file": candidate["file"],
                      "source_sha256": source["sha256"], "line": candidate["line"],
                      "source_excerpt_start_line": 1,
                      "context": {"source_excerpt": "int this_text_is_not_in_the_candidate_source;"}},
                  "agent_assessment": {"assessment": "likely_true_positive",
                      "summary": "forged summary must not be displayed",
                      "supported_claims": [{"claim": "forged claim",
                          "citations": [{"evidence_id": "ev-source-fixed-test",
                              "file": candidate["file"], "line_start": 1, "line_end": 1,
                              "quote": "int this_text_is_not_in_the_candidate_source;"}]}],
                      "obligation_reviews": [], "unsupported_claims": [], "unknowns": [],
                      "next_steps": ["forged remediation advice"]}}
        ops.finish(operation["id"], result, state="completed_with_limitations")
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "reject forged citation", "links": [{"job_id": job["id"],
                "candidate_id": candidate["id"], "rationale": "fixed source mismatch"}],
        })
        self.assertEqual(case.status_code, 201, case.text)
        case_id = case.json()["id"]
        report = self.client.get(f"/api/v1/cases/{case_id}/report.json")
        self.assertEqual(report.status_code, 200, report.text)
        body = report.json()
        triage = body["operations"][0]["agent_triage"]
        self.assertEqual(triage["citation_review"]["state"], "unknown")
        self.assertIn("不匹配", triage["citation_review"]["reason"])
        self.assertEqual(triage["assessment"], "unknown")
        self.assertEqual(triage["summary"], "")
        self.assertEqual(triage["supported_claims"], [])
        self.assertEqual(triage["model_suggestions"], [])
        self.assertEqual(body["candidates"][0]["risk"]["vulnerability_state"], "candidate")
        self.assertEqual(body["validated_vulnerability"], 0)
        markdown = self.client.get(f"/api/v1/cases/{case_id}/report.md")
        self.assertNotIn("forged summary", markdown.text)
        self.assertNotIn("forged remediation advice", markdown.text)
        self.assertIn("智能调查建议：未知", markdown.text)



    def test_case_report_rejects_forged_supplemental_tool_excerpt(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        source = service.source(self.settings, self.store, job, candidate["file"])
        ops = self.app.state.operations
        spec = {"job_id": job["id"], "candidate_id": candidate["id"], "case_id": None,
                "report_sha256": job["report_sha256"], "source_commit": job["spec"]["commit"],
                "candidate_source_sha256": source["sha256"], "mode": "tool_agent"}
        operation = ops.create("agent_investigation", spec)
        self.assertEqual(ops.claim()["id"], operation["id"])
        binding = {"job_id": job["id"], "candidate_id": candidate["id"],
                   "report_sha256": job["report_sha256"], "commit": job["spec"]["commit"],
                   "source_sha256": source["sha256"]}
        forged_line = "1: int forged_supplemental_evidence_not_in_git;"
        result = {"status": "completed", "binding": binding,
                  "vulnerability_state": "candidate", "validated_vulnerability": 0,
                  "citation_integrity": {"quote_presence": "verified_for_all_citations",
                                          "citation_count": 1,
                                          "semantic_support": "unverified_by_machine"},
                  "initial_evidence": {"evidence_id": "ev-source-initial-valid",
                      "evidence_kind": "source_code", "file": candidate["file"],
                      "source_sha256": source["sha256"], "source_commit": job["spec"]["commit"],
                      "line": candidate["line"], "source_excerpt_start_line": 1,
                      "context": {"source_excerpt": source["text"]}},
                  "tool_calls": [{"tool": "read_fixed_source_range",
                      "evidence_id": "ev-source-forged-tool-result", "evidence_kind": "source_code",
                      "result": {"commit": job["spec"]["commit"], "file": candidate["file"],
                          "source_sha256": source["sha256"], "git_blob": source.get("blob"),
                          "start_line": 1, "text": forged_line}}],
                  "agent_assessment": {"assessment": "likely_true_positive",
                      "summary": "forged supplemental quote must not be displayed",
                      "supported_claims": [{"claim": "forged supplemental source claim",
                          "citations": [{"evidence_id": "ev-source-forged-tool-result",
                              "file": candidate["file"], "line_start": 1, "line_end": 1,
                              "quote": forged_line.split(": ", 1)[1]}]}],
                      "obligation_reviews": [], "unsupported_claims": [], "unknowns": [],
                      "next_steps": ["forged tool-based advice"]}}
        ops.finish(operation["id"], result, state="completed_with_limitations")
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "reject forged tool evidence", "links": [{"job_id": job["id"],
                "candidate_id": candidate["id"], "rationale": "supplemental source must match Git"}],
        })
        self.assertEqual(case.status_code, 201, case.text)
        case_id = case.json()["id"]
        report = self.client.get(f"/api/v1/cases/{case_id}/report.json")
        self.assertEqual(report.status_code, 200, report.text)
        body = report.json()
        triage = body["operations"][0]["agent_triage"]
        self.assertEqual(triage["citation_review"]["state"], "unknown")
        self.assertIn("不匹配", triage["citation_review"]["reason"])
        self.assertEqual(triage["summary"], "")
        self.assertEqual(triage["model_suggestions"], [])
        self.assertEqual(body["candidates"][0]["remediation_draft"]["ai_basis"]["state"], "unknown")
        self.assertEqual(body["candidates"][0]["risk"]["vulnerability_state"], "candidate")
        self.assertEqual(body["validated_vulnerability"], 0)
        markdown = self.client.get(f"/api/v1/cases/{case_id}/report.md")
        self.assertNotIn("forged supplemental quote", markdown.text)
        self.assertNotIn("forged tool-based advice", markdown.text)
        self.assertIn("智能调查建议：未知", markdown.text)



    def test_case_report_shows_unverified_ai_basis_only_for_fixed_source_citations(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        source = service.source(self.settings, self.store, job, candidate["file"])
        source_line = source["text"].splitlines()[candidate["line"] - 1]
        ops = self.app.state.operations
        spec = {"job_id": job["id"], "candidate_id": candidate["id"], "case_id": None,
                "report_sha256": job["report_sha256"], "source_commit": job["spec"]["commit"],
                "candidate_source_sha256": source["sha256"], "mode": "single_shot"}
        operation = ops.create("agent_investigation", spec)
        self.assertEqual(ops.claim()["id"], operation["id"])
        binding = {"job_id": job["id"], "candidate_id": candidate["id"],
                   "report_sha256": job["report_sha256"], "commit": job["spec"]["commit"],
                   "source_sha256": source["sha256"]}
        result = {"status": "completed", "binding": binding,
                  "summary_provenance": "server_generated_from_structured_triage",
                  "vulnerability_state": "candidate", "validated_vulnerability": 0,
                  "citation_integrity": {"quote_presence": "verified_for_all_citations",
                                          "citation_count": 1,
                                          "semantic_support": "unverified_by_machine"},
                  "initial_evidence": {"evidence_id": "ev-source-fixed-valid",
                      "evidence_kind": "source_code", "file": candidate["file"],
                      "source_sha256": source["sha256"], "source_commit": job["spec"]["commit"],
                      "line": candidate["line"], "source_excerpt_start_line": 1,
                      "context": {"source_excerpt": source["text"]}},
                  "agent_assessment": {"assessment": "needs_more_evidence",
                      "summary": "A source-bound hypothesis requiring human review",
                      "supported_claims": [{"claim": "A source-local observation",
                          "citations": [{"evidence_id": "ev-source-fixed-valid",
                              "file": candidate["file"], "line_start": candidate["line"],
                              "line_end": candidate["line"], "quote": source_line}]}],
                      "obligation_reviews": [], "unsupported_claims": [], "unknowns": [],
                      "next_steps": ["Review the caller and define a safe observable"]}}
        ops.finish(operation["id"], result, state="completed_with_limitations")
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "fixed source AI citation", "links": [{"job_id": job["id"],
                "candidate_id": candidate["id"], "rationale": "citation binding positive control"}],
        })
        self.assertEqual(case.status_code, 201, case.text)
        report = self.client.get(f"/api/v1/cases/{case.json()['id']}/report.json")
        self.assertEqual(report.status_code, 200, report.text)
        body = report.json()
        triage = body["operations"][0]["agent_triage"]
        self.assertEqual(triage["citation_review"]["state"], "unverified_model_advice")
        self.assertEqual(len(triage["model_suggestions"]), 1)
        suggestion = triage["model_suggestions"][0]
        self.assertEqual(suggestion["state"], "unverified_model_suggestion")
        self.assertEqual(suggestion["semantic_support"], "unverified_by_machine")
        self.assertEqual(suggestion["source_anchor"]["source_sha256"], source["sha256"])
        draft = body["candidates"][0]["remediation_draft"]
        self.assertEqual(draft["ai_basis"]["state"], "source_bound_unverified")
        self.assertEqual(draft["ai_basis"]["citations"][0]["quote"], source_line)
        self.assertEqual(body["candidates"][0]["risk"]["vulnerability_state"], "candidate")
        self.assertEqual(body["validated_vulnerability"], 0)



    def test_experiment_evidence_summary_keeps_holdout_unknown_and_harness_separate(self):
        empty = self.client.get("/api/v1/agent/evaluation-summary")
        self.assertEqual(empty.status_code, 200, empty.text)
        empty_evidence = empty.json()["evidence_evaluation"]
        self.assertEqual(empty_evidence["agent"]["state"], "unknown")
        self.assertEqual(empty_evidence["validation"]["state"], "unknown")
        self.assertEqual(empty_evidence["holdout"]["state"], "unknown")

        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        source = service.source(self.settings, self.store, job, candidate["file"])
        ops = self.app.state.operations
        spec = {
            "job_id": job["id"], "candidate_id": candidate["id"], "case_id": None,
            "experiment_id": "issue42-evaluation-fixture", "mode": "single_shot",
            "provider_model": "fixture-model", "prompt_version": "p1", "tool_policy_version": "t1",
            "report_sha256": job["report_sha256"], "source_commit": job["spec"]["commit"],
            "candidate_source_sha256": source["sha256"],
        }
        agent = ops.create("agent_investigation", spec)
        self.assertEqual(ops.claim()["id"], agent["id"])
        binding = {"job_id": job["id"], "candidate_id": candidate["id"],
                   "repository": service.read_report(self.settings, job)["repository"],
                   "report_sha256": job["report_sha256"], "commit": job["spec"]["commit"],
                   "source_sha256": source["sha256"]}
        ops.finish(agent["id"], {
            "status": "completed_with_limitations", "mode": "single_shot",
            "experiment_id": spec["experiment_id"], "provider": {"model": spec["provider_model"]},
            "prompt_version": spec["prompt_version"], "tool_policy_version": spec["tool_policy_version"],
            "binding": binding, "vulnerability_state": "candidate", "validated_vulnerability": 0,
        }, state="completed_with_limitations")

        mismatched = ops.create("agent_investigation", {**spec, "candidate_source_sha256": "0" * 64})
        self.assertEqual(ops.claim()["id"], mismatched["id"])
        ops.finish(mismatched["id"], {
            "status": "completed_with_limitations", "mode": "single_shot",
            "experiment_id": spec["experiment_id"], "provider": {"model": spec["provider_model"]},
            "prompt_version": spec["prompt_version"], "tool_policy_version": spec["tool_policy_version"],
            "binding": binding, "vulnerability_state": "candidate", "validated_vulnerability": 0,
        }, state="completed_with_limitations")

        target_commit = "a" * 40
        manifest = {"target_commit": target_commit,
                    "target_repository": "openharmony/inputmethod_imf",
                    "cutils_commit": "b" * 40,
                    "harness_manifest_sha256": "c" * 64}
        raw_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        validation_spec = {"case_id": "case-not-linked-to-experiment",
                           "harness_id": "auth01_descriptor_bypass",
                           "target_repository": manifest["target_repository"],
                           "target_commit": target_commit, "cutils_commit": manifest["cutils_commit"]}
        validation = ops.create("validation", validation_spec)
        self.assertEqual(ops.claim(validation=True)["id"], validation["id"])
        manifest_path = ops.directory(validation["id"]) / "input-manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(raw_manifest)
        validation_result = {"status": "completed_with_limitations",
                             "input_manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
                             "validation_gate": "passed", "reachability_status": "unknown",
                             "validated_vulnerability": 0}
        ops.finish(validation["id"], validation_result, state="completed_with_limitations")

        response = self.client.get("/api/v1/agent/evaluation-summary")
        self.assertEqual(response.status_code, 200, response.text)
        evidence = response.json()["evidence_evaluation"]
        self.assertFalse(evidence["accuracy_claim"])
        self.assertEqual(evidence["agent"]["fixed_source_bound_result_count"], 1)
        self.assertEqual(evidence["agent"]["unknown_binding_count"], 1)
        self.assertEqual(evidence["agent"]["groups"][0]["fixed_source_bound_result_count"], 1)
        self.assertEqual(evidence["holdout"]["state"], "unknown")
        self.assertEqual(evidence["validation"]["scope_counts"], {
            "component_harness": 1, "product_level": 0, "unknown": 0,
        })
        harness_view = evidence["validation"]["runs"][0]
        self.assertEqual(harness_view["scope"], "component_harness")
        self.assertEqual(harness_view["input_manifest_state"], "verified_input_manifest")
        self.assertEqual(harness_view["reachability_status"], "unknown")
        self.assertEqual(harness_view["validated_vulnerability"], 0)

        # A gate pass alone cannot turn a component harness into product validation.
        manifest_path.write_text("{}\n", encoding="utf-8")
        stale = self.client.get("/api/v1/agent/evaluation-summary").json()["evidence_evaluation"]
        stale_run = stale["validation"]["runs"][0]
        self.assertEqual(stale_run["scope"], "component_harness")
        self.assertEqual(stale_run["input_manifest_state"], "unknown")
        self.assertEqual(stale_run["validation_gate"], "passed")
        self.assertEqual(stale_run["validated_vulnerability"], 0)

    def test_case_confirmation_rejects_component_or_unregistered_product_validator(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "component harness cannot confirm product reachability",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"], "rationale": "test"}],
        }).json()
        evidence = self.client.post(
            f"/api/v1/scans/{job['id']}/findings/{candidate['id']}/evidence",
            headers=HEADERS,
            json={"file": candidate["file"], "start_line": candidate["line"],
                  "end_line": candidate["line"], "note": "human-reviewed source evidence"},
        )
        self.assertEqual(evidence.status_code, 201, evidence.text)

        ops = self.app.state.operations
        component = ops.create("validation", {
            "case_id": case["id"], "harness_id": "auth01_descriptor_bypass",
            "validation_scope": "component_harness", "target_repository": "fixture/sample",
            "target_commit": self.commit,
        })
        self.assertEqual(ops.claim(validation=True)["id"], component["id"])
        ops.finish(component["id"], {
            "status": "completed_with_limitations", "validation_gate": "passed",
            "case_id": case["id"], "reachability_status": "verified",
            "validation_scope": "product_level", "harness_id": "auth01_descriptor_bypass",
        }, state="completed_with_limitations")

        unregistered = ops.create("validation", {
            "case_id": case["id"], "harness_id": "future_product_validator",
            "validation_scope": "product_level", "target_repository": "fixture/sample",
            "target_commit": self.commit,
        })
        self.assertEqual(ops.claim(validation=True)["id"], unregistered["id"])
        ops.finish(unregistered["id"], {
            "status": "completed_with_limitations", "validation_gate": "passed",
            "case_id": case["id"], "reachability_status": "verified",
            "validation_scope": "product_level", "harness_id": "future_product_validator",
        }, state="completed_with_limitations")

        payload = {
            "outcome": "confirmed", "reviewer_kind": "human", "reviewer": "reviewer:test",
            "notes": "Attempted to confirm using component-only or unregistered validation.",
            "evidence_ids": [evidence.json()["id"]],
            "validation_operation_ids": [component["id"], unregistered["id"]],
            "remaining_unknowns": ["Product entry reachability is not established."],
        }
        rejected = self.client.post(f"/api/v1/cases/{case['id']}/assessments",
                                    headers=HEADERS, json=payload)
        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertEqual(self.client.get(f"/api/v1/cases/{case['id']}/report.json").json()
                         ["validated_vulnerability"], 0)

        # A legacy or internally inserted human record still cannot bypass the live gate.
        ops.assessment(case["id"], payload)
        report = self.client.get(f"/api/v1/cases/{case['id']}/report.json")
        self.assertEqual(report.status_code, 200, report.text)
        self.assertEqual(report.json()["validated_vulnerability"], 0)
        latest = self.client.post(f"/api/v1/cases/{case['id']}/assessments", headers=HEADERS, json={
            **payload, "outcome": "candidate", "validation_operation_ids": [],
            "notes": "A later human decision reopens the case.",
        })
        self.assertEqual(latest.status_code, 201, latest.text)
        self.assertEqual(self.client.get(f"/api/v1/cases/{case['id']}/report.json").json()
                         ["validated_vulnerability"], 0)

    def test_case_confirmation_rejects_mismatched_product_candidate_binding(self):
        job = self.completed()
        candidate = service.findings(service.read_report(self.settings, job))[0]
        case = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "product validation candidate binding",
            "links": [{"job_id": job["id"], "candidate_id": candidate["id"], "rationale": "test"}],
        }).json()
        evidence = self.client.post(
            f"/api/v1/scans/{job['id']}/findings/{candidate['id']}/evidence",
            headers=HEADERS,
            json={"file": candidate["file"], "start_line": candidate["line"],
                  "end_line": candidate["line"], "note": "source evidence"},
        )
        self.assertEqual(evidence.status_code, 201, evidence.text)

        ops = self.app.state.operations
        operation = ops.create("validation", {
            "case_id": case["id"], "harness_id": "test_product_validator",
            "validation_scope": "product_level", "target_repository": "fixture/sample",
            "target_commit": self.commit, "product_validation_binding": {"candidate_id": "wrong"},
        })
        self.assertEqual(ops.claim(validation=True)["id"], operation["id"])
        manifest = {
            "validation_scope": "product_level", "harness_id": "test_product_validator",
            "target_repository": "fixture/sample", "target_commit": self.commit,
            "product_validation_binding": {"candidate_id": "wrong"},
        }
        raw_manifest = json.dumps(manifest, sort_keys=True).encode()
        manifest_path = ops.directory(operation["id"]) / "input-manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(raw_manifest)
        ops.finish(operation["id"], {
            "status": "completed_with_limitations", "validation_gate": "passed",
            "case_id": case["id"], "reachability_status": "verified",
            "validation_scope": "product_level", "harness_id": "test_product_validator",
            "target_repository": "fixture/sample", "target_commit": self.commit,
            "product_validation_binding": {"candidate_id": "wrong"},
            "input_manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        }, state="completed_with_limitations")

        with patch("src.workbench.operations_api.PRODUCT_LEVEL_VALIDATOR_IDS",
                   frozenset({"test_product_validator"})):
            rejected = self.client.post(f"/api/v1/cases/{case['id']}/assessments",
                headers=HEADERS, json={
                    "outcome": "confirmed", "reviewer_kind": "human", "reviewer": "reviewer:test",
                    "notes": "The product-validation manifest points to another candidate.",
                    "evidence_ids": [evidence.json()["id"]],
                    "validation_operation_ids": [operation["id"]],
                    "remaining_unknowns": ["Product source and affected versions."],
                })
        self.assertEqual(rejected.status_code, 409, rejected.text)
        self.assertEqual(self.client.get(f"/api/v1/cases/{case['id']}/report.json").json()
                         ["validated_vulnerability"], 0)
