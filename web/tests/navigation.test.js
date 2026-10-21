import test from "node:test";
import assert from "node:assert/strict";
import { auditLinks, detailTab, jobDetailPath, resolveRoute, retainRiskSource, riskQueuePath, settingsTab } from "../src/features/workbench/navigation.js";
test("three audit entries are distinct forms, with no intermediate new-audit page", () => {
  assert.equal(auditLinks.length, 3);
  assert.equal(auditLinks[0].title, "仓库审计");
  assert.deepEqual(auditLinks.map((link) => link.path), ["/audits/repository", "/audits/time", "/audits/versions"]);
});
test("legacy links retain their destination and task identity", () => {
  for (const [old, current] of [["/new", "/audits/repository"], ["/repositories", "/settings/sources"], ["/cases", "/investigations"], ["/capabilities", "/settings/capabilities"]]) assert.equal(resolveRoute(old).path, current);
  assert.equal(resolveRoute("/tasks/original-job").path, "/tasks/original-job");
  assert.equal(resolveRoute("/operations").path, "/operations");
  assert.equal(resolveRoute("/does-not-exist").path, "/does-not-exist");
});
test("source report and operation deep links select the right navigation section", () => {
  const route = resolveRoute(jobDetailPath("original-job", "reports"));
  assert.equal(route.section, "/tasks"); assert.equal(detailTab(route.query.get("tab")), "reports");
  assert.equal(resolveRoute("/tasks/operations/operation-id").section, "/tasks");
  assert.equal(resolveRoute("/settings/capabilities").section, "/settings");
  assert.equal(detailTab("untrusted-tab"), "findings");
});

test("settings deep links keep the selected tab, including progressive triage policy", () => {
  assert.equal(settingsTab("policy"), "policy");
  assert.equal(settingsTab("agent"), "agent");
  assert.equal(settingsTab("untrusted"), "sources");
});

test("candidate context survives route normalization without becoming an execution request", () => {
  const route = resolveRoute("/cases?job_id=job-1&candidate_id=candidate-2&repository_id=repo-3");
  assert.equal(route.path, "/investigations");
  assert.equal(route.query.get("job_id"), "job-1");
  assert.equal(route.query.get("candidate_id"), "candidate-2");
  assert.equal(route.query.get("repository_id"), "repo-3");
});

test("new reports cannot steal the risk source currently under review", () => {
  const initial = [{ id: "running", report_sha256: null }, { id: "old", report_sha256: "old-hash" }];
  const selected = retainRiskSource(undefined, initial);
  assert.equal(selected, "old");
  assert.equal(retainRiskSource(selected, [{ id: "new", report_sha256: "new-hash" }, ...initial]), "old");
  assert.equal(retainRiskSource(selected, []), "old");
  assert.equal(retainRiskSource(undefined, []), undefined);
});

test("risk filter changes produce shareable, encoded URLs and defaults reset cleanly", () => {
  assert.equal(riskQueuePath({
    scan_limit: "10",
    risk_tier: "further_validation",
    triage_state: "",
    repository: "openharmony/sample",
    detector_id: "ohscanner.cpp.null_dereference",
    q: "ipc path",
  }), "/risks?scan_limit=10&risk_tier=further_validation&repository=openharmony%2Fsample&detector_id=ohscanner.cpp.null_dereference&q=ipc+path");
  assert.equal(riskQueuePath({
    scan_limit: "20", risk_tier: "", triage_state: "", repository: "", detector_id: "", q: "",
  }), "/risks");
});

test("risk queue deep links preserve dashboard filters", () => {
  const route = resolveRoute("/risks?scan_limit=10&risk_tier=further_validation&repository=openharmony%2Fsample&detector_id=ohscanner.cpp.null_dereference&q=ipc");
  assert.equal(route.path, "/risks");
  assert.equal(route.section, "/risks");
  assert.equal(route.query.get("scan_limit"), "10");
  assert.equal(route.query.get("risk_tier"), "further_validation");
  assert.equal(route.query.get("repository"), "openharmony/sample");
  assert.equal(route.query.get("detector_id"), "ohscanner.cpp.null_dereference");
  assert.equal(route.query.get("q"), "ipc");
});
