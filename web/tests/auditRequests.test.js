import test from "node:test";
import assert from "node:assert/strict";
import { approvedDetectorIds, datePreviewPayload, includePaths, operationPayload, recentRange, requestGate, snapshotPayload, planPayload } from "../src/features/audits/model.js";
const detectors = [
  { id: "test.cpp", version: "2", kind: "research_candidate", supported_languages: ["cpp"] },
  { id: "test.example", version: "1", kind: "example", supported_languages: ["cpp"] },
  { id: "test.unapproved", version: "1", kind: "unreviewed", supported_languages: ["cpp"] },
];
const values = { repository_id: "repo", revision: "refs/tags/a", include_text: "src\ninclude", timeout_seconds: 60, memory_mb: 512, approval: true, forged: "do not send" };
test("automatic rule IDs come from approved service metadata and exclude examples", () => {
  assert.deepEqual(approvedDetectorIds(detectors), ["test.cpp"]);
  assert.throws(() => approvedDetectorIds(detectors.slice(1)), /没有可用/);
  assert.throws(() => approvedDetectorIds([detectors[0], detectors[0]]), /重复/);
});
test("snapshot delegates automatic rule selection to the server and drops UI-only controls", () => {
  assert.deepEqual(snapshotPayload(values, detectors), { repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"], timeout_seconds: 60, memory_mb: 512 });
});
test("invalid include scopes and budgets fail before submission", () => {
  for (const value of ["../escape", "/absolute", "a/../b", "a\\b", "src,src", ""]) assert.throws(() => includePaths(value));
  assert.throws(() => snapshotPayload({ ...values, memory_mb: 1 }, detectors), /预算/);
  assert.throws(() => snapshotPayload({ ...values, revision: "" }, detectors), /版本|Commit/);
});
test("date preview excludes detector/scope/budget fields required only for execution", () => {
  const fields = { repository_id: "repo", branch: "refs/heads/main", start: "2026-10-15T00:00", end: "2026-10-17T00:00", timezone: "Asia/Shanghai" };
  assert.deepEqual(datePreviewPayload({ ...values, ...fields }), fields);
  assert.deepEqual(operationPayload("date", { ...values, ...fields }, detectors), { ...fields, include_paths: ["src", "include"], detector_ids: ["test.cpp"], timeout_seconds: 60, memory_mb: 512 });
  assert.throws(() => datePreviewPayload({ ...fields, end: fields.start }), /结束/);
});
test("matrix drops commits_text and uses complete distinct source IDs", () => {
  const a = "a".repeat(40), b = "b".repeat(40);
  const body = operationPayload("matrix", { ...values, case_id: "case", commits_text: a + "\n" + b }, detectors);
  assert.deepEqual(body.commits, [a, b]); assert.equal(body.case_id, "case");
  assert.equal("commits_text" in body, false); assert.equal("revision" in body, false); assert.equal("include_text" in body, false);
  for (const text of [a, a + "," + a, "abc,def", [a,b,a,b,a,b,a,b,a].join(",")]) assert.throws(() => operationPayload("matrix", { ...values, case_id: "case", commits_text: text }, detectors));
});
test("branch comparison permits refs and SHA but rejects identical endpoints", () => {
  const body = operationPayload("branches", { ...values, baseline_ref: "refs/tags/a", endpoint_ref: "b".repeat(40) }, detectors);
  assert.equal(body.baseline_ref, "refs/tags/a"); assert.equal("case_id" in body, false);
  assert.throws(() => operationPayload("branches", { ...values, baseline_ref: "main", endpoint_ref: "main" }, detectors), /不同/);
});
test("quick date range uses the selected timezone across a UTC day boundary", () => {
  assert.deepEqual(recentRange(7, "Asia/Shanghai", new Date("2026-10-16T16:30:00Z")), { start: "2026-10-10T00:30:00", end: "2026-10-17T00:30:00" });
});
test("late ref or preview responses cannot restore invalidated form input", async () => {
  const gate = requestGate(); let resolve; let displayed = null;
  const ticket = gate.next();
  const pending = new Promise((done) => { resolve = done; }).then((result) => { if (gate.current(ticket)) displayed = result; });
  gate.invalidate(); resolve({ branch: "old repo" }); await pending;
  assert.equal(displayed, null);
  const fresh = gate.next(); assert.equal(gate.current(fresh), true);
});

test("plan preview sends source selection only, with no browser-chosen rule list", () => {
  assert.deepEqual(planPayload(values, detectors), { repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"] });
});

test("explicit-only research rules are not silently requested by normal UI flows", () => {
  assert.deepEqual(approvedDetectorIds([...detectors, { ...detectors[0], id: "test.research-only", default_enabled: false }]), ["test.cpp"]);
});

test("D sensitive exposure rule stays off by default and is sent only after explicit selection", () => {
  const id = "ohscanner.data.sensitive_exposure";
  const d = { id, version: "0.15.0", kind: "research_candidate", default_enabled: false,
    supported_languages: ["c", "cpp"] };
  assert.deepEqual(approvedDetectorIds([...detectors, d]), ["test.cpp"]);
  assert.deepEqual(approvedDetectorIds([...detectors, d], [id]), [id, "test.cpp"]);
  assert.deepEqual(snapshotPayload(values, [...detectors, d], [id]).detector_ids, [id, "test.cpp"]);
  assert.deepEqual(planPayload(values, [...detectors, d], [id]), {
    repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"], detector_ids: [id, "test.cpp"]
  });
  assert.throws(() => approvedDetectorIds([...detectors, d], ["test.example"]), /实验规则/);
});

test("D disclosed-CVE source rule is sent to preview and scan only after explicit selection", () => {
  const id = "ohscanner.known_disclosed_cves";
  const d = { id, version: "0.12.0", kind: "research_candidate", default_enabled: false,
    supported_languages: ["c", "cpp"] };
  const catalog = [...detectors, d];
  assert.deepEqual(approvedDetectorIds(catalog), ["test.cpp"]);
  assert.deepEqual(approvedDetectorIds(catalog, [id]), [id, "test.cpp"]);
  assert.deepEqual(snapshotPayload(values, catalog, [id]).detector_ids, [id, "test.cpp"]);
  assert.deepEqual(planPayload(values, catalog, [id]), {
    repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"], detector_ids: [id, "test.cpp"]
  });
});
