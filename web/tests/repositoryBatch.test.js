import test from "node:test";
import assert from "node:assert/strict";
import { repositoryAuditEntries, prepareRepositoryAudits, repositoryBatchConsent, createRepositoryAudits } from "../src/features/audits/repositoryBatch.js";
const detectors = [{ id: "cpp", version: "1", kind: "research_candidate", supported_languages: ["cpp"] }];
const repositories = [{ id: "tiff", name: "openharmony/third_party_libtiff" }, { id: "contacts", name: "openharmony/applications_contacts_data" }];
const values = { repository_ids: ["tiff", "contacts"], audit_mode: "static_only", timeout_seconds: 600, memory_mb: 2048,
  repositories: { tiff: { revision: "a".repeat(40), include_text: "libtiff/tif_getimage.c" }, contacts: { revision: "b".repeat(40), include_text: "src/contact.cpp\nsrc/helper.cpp" } } };
const plan = (body) => ({ commit: body.revision, plan_sha256: body.repository_id + "-plan", workflow_sha256: body.repository_id + "-workflow",
  triage_authorization_preview: { eligible: true, consent_sha256: body.repository_id + "-consent", consent_nonce: body.repository_id + "-nonce", provider: { endpoint_host: "example.test" }, manifest: { binding: { repository: body.repository_id, commit: body.revision, include_paths: body.include_paths } } } });

test("multi-repository entries keep each repository's version and scope independent", () => {
  const entries = repositoryAuditEntries(values, repositories, detectors);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].payload.revision, "a".repeat(40));
  assert.equal(entries[1].payload.revision, "b".repeat(40));
  assert.deepEqual(entries[1].payload.include_paths, ["src/contact.cpp", "src/helper.cpp"]);
  assert.equal(entries.every((row) => row.authorization.auto_triage === false), true);
  assert.equal(repositoryBatchConsent(entries), null);
});
test("single-repository selection uses the same validated request path", () => {
  assert.equal(repositoryAuditEntries({ ...values, repository_ids: ["tiff"] }, repositories, detectors).length, 1);
});
test("empty, duplicate, unavailable and invalid scopes are rejected before API calls", () => {
  for (const ids of [[], ["tiff", "tiff"], ["unavailable"]]) assert.throws(() => repositoryAuditEntries({ ...values, repository_ids: ids }, repositories, detectors));
  assert.throws(() => repositoryAuditEntries({ ...values, repositories: { ...values.repositories, contacts: { revision: "main", include_text: "../escape" } } }, repositories, detectors), /contacts/);
});
test("all selected repositories are planned without creating scans and errors name the failing repository", async () => {
  const requests = [];
  await assert.rejects(prepareRepositoryAudits(repositoryAuditEntries(values, repositories, detectors), async (path, body) => {
    requests.push(path); if (body.repository_id === "contacts") throw new Error("missing Git object"); return plan(body);
  }), /contacts.*missing Git object.*尚未创建/);
  assert.deepEqual(requests, ["/audit-plans", "/audit-plans"]);
});
test("invalidated planning cannot restore an old batch or request the remaining repositories", async () => {
  let active = true, requests = 0;
  const result = await prepareRepositoryAudits(repositoryAuditEntries(values, repositories, detectors), async (_, body) => {
    requests++; active = false; return plan(body);
  }, undefined, () => active);
  assert.equal(result, null); assert.equal(requests, 1);
});
test("smart batch shows all scopes and submits each repository's own consent and pinned plan", async () => {
  const entries = repositoryAuditEntries({ ...values, audit_mode: "standard_review", auto_r2: true }, repositories, detectors);
  const prepared = await prepareRepositoryAudits(entries, async (_, body) => plan(body));
  const consent = repositoryBatchConsent(prepared);
  assert.equal(consent.scans.length, 2);
  assert.deepEqual(consent.scans[1].manifest.binding.include_paths, ["src/contact.cpp", "src/helper.cpp"]);
  const calls = [];
  const rows = await createRepositoryAudits(prepared, async (path, body) => { calls.push({ path, body }); return { id: body.repository_id + "-job" }; });
  assert.equal(rows.every((row) => row.state === "created"), true);
  assert.deepEqual(calls.map((row) => row.body.expected_triage_consent_sha256), ["tiff-consent", "contacts-consent"]);
  assert.deepEqual(calls.map((row) => row.body.expected_plan_sha256), ["tiff-plan", "contacts-plan"]);
});
test("partial creation retains successful IDs and never automatically retries an uncertain response", async () => {
  const prepared = await prepareRepositoryAudits(repositoryAuditEntries(values, repositories, detectors), async (_, body) => plan(body));
  let calls = 0;
  const rows = await createRepositoryAudits(prepared, async (_, body) => { calls++; if (body.repository_id === "contacts") throw new Error("connection interrupted"); return { id: "created-job" }; });
  assert.equal(calls, 2); assert.equal(rows[0].job_id, "created-job"); assert.equal(rows[1].state, "check_required");
});
test("smart planning fails closed when one repository has no valid source consent", async () => {
  const entries = repositoryAuditEntries({ ...values, audit_mode: "standard_review" }, repositories, detectors);
  await assert.rejects(prepareRepositoryAudits(entries, async (_, body) => ({ ...plan(body), triage_authorization_preview: { eligible: false, reason: "scope unavailable" } })), /scope unavailable/);
});
test("a provider change between repository previews requires a new aggregate consent", async () => {
  const entries = repositoryAuditEntries({ ...values, audit_mode: "standard_review" }, repositories, detectors);
  await assert.rejects(prepareRepositoryAudits(entries, async (_, body) => {
    const result = plan(body);
    if (body.repository_id === "contacts") result.triage_authorization_preview.provider.endpoint_host = "changed.test";
    return result;
  }), /模型配置.*变化/);
});
