import test from "node:test";
import assert from "node:assert/strict";
import { approvedDetectorIds, researchDetectorIds, datePreviewPayload, defaultRepositoryRevision, includePaths, operationPayload, recentRange, requestGate, snapshotPayload, planPayload, auditErrorMessage, taskAuthorizationPayload, auditWorkflowLabel, selectedAuditModeValues } from "../src/features/audits/model.js";
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
  assert.deepEqual(snapshotPayload(values, detectors), { repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"], audit_mode: "standard_review", timeout_seconds: 60, memory_mb: 512 });
});
test("invalid include scopes and budgets fail before submission", () => {
  for (const value of ["../escape", "/absolute", "a/../b", "a\\b", "src,src", ""]) assert.throws(() => includePaths(value));
  assert.throws(() => snapshotPayload({ ...values, memory_mb: 1 }, detectors), /预算/);
  assert.throws(() => snapshotPayload({ ...values, revision: "" }, detectors), /版本|Commit/);
  assert.throws(() => snapshotPayload({ ...values, audit_mode: "automatic_external" }, detectors), /审计方式/);
  assert.equal(snapshotPayload({ ...values, audit_mode: "static_only" }, detectors).audit_mode, "static_only");
});
test("date preview excludes detector/scope/budget fields required only for execution", () => {
  const fields = { repository_id: "repo", branch: "refs/heads/main", start: "2026-10-15T00:00", end: "2026-10-17T00:00", timezone: "Asia/Shanghai" };
  assert.deepEqual(datePreviewPayload({ ...values, ...fields }), fields);
  assert.deepEqual(operationPayload("date", { ...values, ...fields }, detectors), { ...fields,
    audit_mode: "standard_review", auto_triage: false, max_triage_candidates: 3,
    max_r2_candidates: 0,
    include_paths: ["src", "include"], detector_ids: ["test.cpp"], timeout_seconds: 60, memory_mb: 512 });
  assert.throws(() => datePreviewPayload({ ...fields, end: fields.start }), /结束/);
});
test("matrix drops commits_text and uses complete distinct source IDs", () => {
  const a = "a".repeat(40), b = "b".repeat(40);
  const body = operationPayload("matrix", { ...values, case_id: "case", commits_text: a + "\n" + b }, detectors);
  assert.deepEqual(body.commits, [a, b]); assert.equal(body.case_id, "case");
  assert.equal("commits_text" in body, false); assert.equal("revision" in body, false); assert.equal("include_text" in body, false);
  for (const text of [a, a + "," + a, "abc,def", [a,b,a,b,a,b,a,b,a].join(",")]) assert.throws(() => operationPayload("matrix", { ...values, case_id: "case", commits_text: text }, detectors));
});
test("recent window comparison includes fixed time, timezone, and bounded N-day selection", () => {
  const body = operationPayload("recent", { ...values, branch: "refs/heads/main",
    lookback_days: 7, reference_time: "2026-10-20T12:00", timezone: "Asia/Shanghai" }, detectors);
  assert.equal(body.branch, "refs/heads/main");
  assert.equal(body.lookback_days, 7);
  assert.equal(body.reference_time, "2026-10-20T12:00");
  assert.equal(body.timezone, "Asia/Shanghai");
  assert.throws(() => operationPayload("recent", { ...values, branch: "main",
    lookback_days: 91, reference_time: "2026-10-20T12:00", timezone: "UTC" }, detectors), /2 到 90/);
});
test("branch comparison permits refs and SHA but rejects identical endpoints", () => {
  const body = operationPayload("branches", { ...values, baseline_ref: "refs/tags/a", endpoint_ref: "b".repeat(40) }, detectors);
  assert.equal(body.baseline_ref, "refs/tags/a"); assert.equal(body.audit_mode, "standard_review"); assert.equal("case_id" in body, false);
  assert.throws(() => operationPayload("branches", { ...values, baseline_ref: "main", endpoint_ref: "main" }, detectors), /不同/);
});

test("date, range, branch, and matrix operations freeze the selected audit mode", () => {
  const staticValues = { ...values, audit_mode: "static_only" };
  assert.equal(operationPayload("date", { ...staticValues, branch: "main", start: "2026-01-01T00:00:00", end: "2026-01-02T00:00:00", timezone: "UTC" }, detectors).audit_mode, "static_only");
  assert.equal(operationPayload("range", { ...staticValues, baseline: "a".repeat(40), endpoint: "b".repeat(40) }, detectors).audit_mode, "static_only");
  assert.equal(operationPayload("branches", { ...staticValues, baseline_ref: "main", endpoint_ref: "feature" }, detectors).audit_mode, "static_only");
  assert.equal(operationPayload("matrix", { ...staticValues, case_id: "case", commits_text: "a".repeat(40) + "," + "b".repeat(40) }, detectors).audit_mode, "static_only");
  assert.throws(() => operationPayload("branches", { ...values, audit_mode: "automatic_external", baseline_ref: "main", endpoint_ref: "feature" }, detectors), /审计方式/);
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

test("audit preview errors show field validation and API messages in plain language", () => {
  assert.equal(auditErrorMessage({ errorFields: [{ name: ["revision"], errors: ["请选择或填写版本"] }] }),
    "请先修正表单：请选择或填写版本");
  assert.equal(auditErrorMessage(new Error("扫描计划生成超时")), "扫描计划生成超时");
  assert.equal(auditErrorMessage({}), "审计计划预览失败，请检查必填项和扫描范围后重试。");
});

test("task-level authorization binds candidate counts without a platform cumulative cost cap", () => {
  assert.deepEqual(taskAuthorizationPayload({ audit_mode: "standard_review" }), {
    auto_triage: false, max_triage_candidates: 3, max_r2_candidates: 0,
  });
  assert.deepEqual(taskAuthorizationPayload({
    audit_mode: "standard_review", auto_triage: true, max_triage_candidates: 3,
    auto_r2: true, max_r2_candidates: 5, max_cost_usd: "0.10",
  }), {
    auto_triage: true, max_triage_candidates: 3, max_r2_candidates: 3,
  });
  assert.equal("max_cost_usd" in taskAuthorizationPayload({
    audit_mode: "static_only", auto_triage: true, max_cost_usd: "0.10",
  }), false);
});

test("plan preview sends source selection only, with no browser-chosen rule list", () => {
  assert.deepEqual(planPayload(values, detectors), { repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"], audit_mode: "standard_review", timeout_seconds: 60, memory_mb: 512 });
});

test("explicit-only research rules are not silently requested by normal UI flows", () => {
  assert.deepEqual(approvedDetectorIds([...detectors, { ...detectors[0], id: "test.research-only", default_enabled: false }]), ["test.cpp"]);
});
test("D sensitive exposure rule stays off by default and is sent only after explicit selection", () => {
  const id = "ohscanner.data.sensitive_exposure";
  const d = { id, version: "0.17.0", kind: "research_candidate", default_enabled: false,
    supported_languages: ["c", "cpp"] };
  assert.deepEqual(approvedDetectorIds([...detectors, d]), ["test.cpp"]);
  assert.deepEqual(approvedDetectorIds([...detectors, d], [id]), [id, "test.cpp"]);
  assert.deepEqual(snapshotPayload(values, [...detectors, d], [id]).detector_ids, [id, "test.cpp"]);
  assert.deepEqual(planPayload(values, [...detectors, d], [id]), {
    repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"], audit_mode: "standard_review", detector_ids: [id, "test.cpp"], timeout_seconds: 60, memory_mb: 512
  });
  assert.throws(() => approvedDetectorIds([...detectors, d], ["test.example"]), /实验规则/);
});

test("C Ark Runtime rule stays off by default and is sent only after explicit selection", () => {
  const id = "ohscanner.ark.runtime.type_safety";
  const c = { id, version: "0.6.2", kind: "research_candidate", default_enabled: false,
    supported_languages: ["cpp"], admission_reason: "research_only_explicit_selection" };
  const catalog = [...detectors, c];
  assert.deepEqual(approvedDetectorIds(catalog), ["test.cpp"]);
  assert.deepEqual(approvedDetectorIds(catalog, [id]), [id, "test.cpp"]);
  assert.deepEqual(snapshotPayload(values, catalog, [id]).detector_ids, [id, "test.cpp"]);
  assert.deepEqual(planPayload(values, catalog, [id]).detector_ids, [id, "test.cpp"]);
});

test("D disclosed-CVE source rule is sent to preview and scan only after explicit selection", () => {
  const id = "ohscanner.known_disclosed_cves";
  const d = { id, version: "0.17.0", kind: "research_candidate", default_enabled: false,
    supported_languages: ["c", "cpp"] };
  const catalog = [...detectors, d];
  assert.deepEqual(approvedDetectorIds(catalog), ["test.cpp"]);
  assert.deepEqual(approvedDetectorIds(catalog, [id]), [id, "test.cpp"]);
  assert.deepEqual(snapshotPayload(values, catalog, [id]).detector_ids, [id, "test.cpp"]);
  assert.deepEqual(planPayload(values, catalog, [id]), {
    repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"], audit_mode: "standard_review", detector_ids: [id, "test.cpp"], timeout_seconds: 60, memory_mb: 512
  });
});

test("explicit full-rules research selects disabled approved rules and freezes that selection", () => {
  const catalog = [...detectors, { id: "test.null", version: "3", kind: "research_candidate", default_enabled: false, supported_languages: ["cpp"], admission_reason: "weak candidates" }];
  assert.deepEqual(researchDetectorIds(catalog), ["test.cpp", "test.null"]);
  const valuesWithResearch = { ...values, full_rules_research: true };
  assert.deepEqual(snapshotPayload(valuesWithResearch, catalog), {
    repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"],
    audit_mode: "standard_review", detector_ids: ["test.cpp", "test.null"], timeout_seconds: 60, memory_mb: 512,
  });
  assert.deepEqual(planPayload(valuesWithResearch, catalog), {
    repository_id: "repo", revision: "refs/tags/a", include_paths: ["src", "include"],
    audit_mode: "standard_review", detector_ids: ["test.cpp", "test.null"], timeout_seconds: 60, memory_mb: 512,
  });
  const ops = operationPayload("date", { ...valuesWithResearch, branch: "main", start: "2026-01-01T00:00:00", end: "2026-01-02T00:00:00", timezone: "UTC" }, catalog);
  assert.deepEqual(ops.detector_ids, ["test.cpp", "test.null"]);
});

test("repository selection prefers only the server-verified default ref", () => {
  assert.equal(defaultRepositoryRevision([
    { ref: "refs/heads/feature", is_default: false },
    { ref: "refs/remotes/origin/main", is_default: true },
  ]), "refs/remotes/origin/main");
  assert.equal(defaultRepositoryRevision([{ ref: "refs/tags/v1", is_default: false }]), "");
  assert.equal(defaultRepositoryRevision(null), "");
});

test("audit workflow label uses the task-level mode when an older nested plan omits it", () => {
  assert.equal(auditWorkflowLabel({}, "static_only"), "仅静态扫描");
  assert.equal(auditWorkflowLabel({ workflow: null }, "standard_review"),
    "标准研判：静态扫描后，候选需逐批预览并授权模型调用");
  assert.equal(auditWorkflowLabel({}, undefined), "历史扫描任务：未记录审计方式");
});

test("audit workflow label describes the frozen conditional triage scope", () => {
  assert.equal(auditWorkflowLabel({ workflow: {
    triage_stage: "task_authorized_r1_conditional_continuous_r2",
    candidate_limit_per_authorized_batch: 3,
    conditional_r2_candidate_limit: 2,
  } }, "standard_review"),
  "标准研判：静态扫描后，最多 3 条候选初步研判；高/严重且仍有源码义务未解决时，最多补充核查 2 条持续追查");
});


test("all comparison modes serialize consented automatic model review only when enabled", () => {
  const a = "a".repeat(40), b = "b".repeat(40);
  const withAI = { ...values, auto_triage: true, auto_r2: true, max_triage_candidates: 5,
    max_r2_candidates: 2, max_cost_usd: "5.00" };
  const inputs = [
    ["date", { branch: "main", start: "2026-10-01T00:00", end: "2026-10-05T00:00", timezone: "UTC" }],
    ["range", { baseline: a, endpoint: b }],
    ["branches", { baseline_ref: "main", endpoint_ref: "dev" }],
    ["matrix", { case_id: "case", commits_text: a + "\n" + b }],
  ];
  for (const [kind, extra] of inputs) {
    const body = operationPayload(kind, { ...withAI, ...extra }, detectors);
    assert.equal(body.audit_mode, "standard_review", kind);
    assert.equal(body.auto_triage, true, kind);
    assert.equal(body.max_triage_candidates, 5, kind);
    assert.equal(body.max_r2_candidates, 2, kind);
    assert.equal("max_cost_usd" in body, false, kind);
    assert.equal("triage_approvals" in body, false, kind);
    const noAI = operationPayload(kind, { ...withAI, ...extra, audit_mode: "static_only" }, detectors);
    assert.equal("auto_triage" in noAI, false, kind);
    assert.equal("max_cost_usd" in noAI, false, kind);
  }
});

test("selected audit mode directly determines whether Agent authorization is included", () => {
  const staticValues = selectedAuditModeValues({ audit_mode: "static_only", auto_triage: true });
  assert.deepEqual(taskAuthorizationPayload(staticValues), {
    auto_triage: false, max_triage_candidates: 3, max_r2_candidates: 0,
  });
  const smartValues = selectedAuditModeValues({ audit_mode: "standard_review", max_triage_candidates: 4,
    auto_r2: true, max_r2_candidates: 2 });
  assert.deepEqual(taskAuthorizationPayload(smartValues), {
    auto_triage: true, max_triage_candidates: 4, max_r2_candidates: 2,
  });
});