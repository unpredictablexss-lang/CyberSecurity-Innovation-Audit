import { selectedAuditModeValues, snapshotPayload, taskAuthorizationPayload } from "./model.js";

export function repositoryAuditEntries(values, repositories, detectors) {
  const ids = values.repository_ids;
  if (!Array.isArray(ids) || !ids.length) throw new Error("请至少选择一个可用仓库。");
  if (new Set(ids).size !== ids.length) throw new Error("仓库不能重复选择。");
  return ids.map((id) => {
    const repository = repositories.find((item) => item.id === id);
    if (!repository) throw new Error("所选仓库已变化，请刷新后重新选择。");
    const fields = values.repositories?.[id] || {};
    try {
      const selected = selectedAuditModeValues({ ...values, ...fields, repository_id: id });
      const payload = snapshotPayload(selected, detectors);
      const authorization = taskAuthorizationPayload(selected);
      return { id, name: repository.name, payload, authorization };
    } catch (error) {
      throw new Error(`${repository.name}：${error.message}`);
    }
  });
}

export async function prepareRepositoryAudits(entries, request, progress = () => {}, current = () => true) {
  const prepared = [];
  for (const [index, entry] of entries.entries()) {
    if (!current()) return null;
    progress(index + 1, entries.length, entry.name);
    let plan;
    try {
      plan = await request("/audit-plans", { ...entry.payload, ...entry.authorization });
      if (!current()) return null;
      if (!plan?.plan_sha256 || !plan?.workflow_sha256) throw new Error("缺少固定扫描计划摘要。");
      const consent = plan.triage_authorization_preview;
      if (entry.authorization.auto_triage && (!consent?.eligible || !consent.consent_sha256 || !consent.consent_nonce)) {
        throw new Error(consent?.reason || "模型外发授权预览不可用。");
      }
      if (entry.authorization.auto_triage && prepared.length) {
        const previous = prepared[0].plan.triage_authorization_preview.provider || {};
        const provider = consent.provider || {};
        const identity = (value) => JSON.stringify(value, Object.keys(value).sort());
        if (identity(previous) !== identity(provider)) throw new Error("模型配置在准备期间发生变化，请重新预览整批授权。");
      }
    } catch (error) {
      throw new Error(`${entry.name}：${error.message} 本批尚未创建任何扫描任务。`);
    }
    prepared.push({ ...entry, plan });
  }
  return prepared;
}

export function repositoryScanRequest(entry) {
  const consent = entry.plan.triage_authorization_preview;
  return {
    ...entry.payload, ...entry.authorization,
    expected_plan_sha256: entry.plan.plan_sha256,
    expected_workflow_sha256: entry.plan.workflow_sha256,
    ...(entry.authorization.auto_triage ? {
      expected_triage_consent_sha256: consent.consent_sha256,
      triage_consent_nonce: consent.consent_nonce,
    } : {}),
  };
}

export function repositoryBatchConsent(entries) {
  if (!entries.length || entries.some((item) => !item.authorization.auto_triage)) return null;
  const previews = entries.map((item) => item.plan.triage_authorization_preview);
  return {
    eligible: previews.every((item) => item?.eligible === true),
    provider: previews[0].provider,
    scans: previews.map((item, index) => ({ ...item, repository: entries[index].name })),
  };
}

export async function createRepositoryAudits(entries, request, progress = () => {}) {
  const results = [];
  for (const entry of entries) {
    progress({ id: entry.id, name: entry.name, state: "submitting" });
    let result;
    try {
      const job = await request("/scans", repositoryScanRequest(entry));
      if (!job?.id) throw new Error("服务端没有返回任务编号。");
      result = { id: entry.id, name: entry.name, state: "created", job_id: job.id };
    } catch (error) {
      // A transport failure may follow successful server creation. Never replay it automatically.
      result = { id: entry.id, name: entry.name, state: "check_required", error: error.message };
    }
    results.push(result);
    progress(result);
  }
  return results;
}
