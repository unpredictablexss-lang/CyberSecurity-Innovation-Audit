import test from "node:test";
import assert from "node:assert/strict";
import { auditLinks, detailTab, jobDetailPath, resolveRoute } from "../src/features/workbench/navigation.js";
test("three audit entries are distinct forms, with no intermediate new-audit page", () => {
  assert.equal(auditLinks.length, 3);
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

test("candidate context survives route normalization without becoming an execution request", () => {
  const route = resolveRoute("/cases?job_id=job-1&candidate_id=candidate-2&repository_id=repo-3");
  assert.equal(route.path, "/investigations");
  assert.equal(route.query.get("job_id"), "job-1");
  assert.equal(route.query.get("candidate_id"), "candidate-2");
  assert.equal(route.query.get("repository_id"), "repo-3");
});
