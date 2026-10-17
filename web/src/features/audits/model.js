// Request builders match the existing strict /api/v1 request schemas.
export function approvedDetectorIds(detectors) {
  const approved = detectors.filter((d) => d.kind === "research_candidate" && d.default_enabled !== false &&
    typeof d.id === "string" && typeof d.version === "string" && d.version.length &&
    Array.isArray(d.supported_languages) && d.supported_languages.length);
  const ids = approved.map((d) => d.id).sort();
  if (!ids.length) throw new Error("当前没有可用的已批准研究规则，请查看系统设置。");
  if (new Set(ids).size !== ids.length) throw new Error("规则配置出现重复身份，请刷新能力配置。");
  return ids;
}
export function includePaths(value = ".") {
  const paths = String(value).split(/[\n,]/).map((p) => p.trim()).filter(Boolean);
  if (!paths.length || paths.length > 100) throw new Error("请填写 1–100 个纳入路径。");
  if (new Set(paths).size !== paths.length) throw new Error("纳入路径不能重复。");
  if (paths.some((p) => p !== "." && (p.startsWith("/") || p.includes("\\") ||
      p.split("/").some((s) => !s || s === "." || s === ".."))))
    throw new Error("纳入路径必须是仓库内相对路径，不能包含 .. 或绝对路径。");
  return paths;
}
function common(values, detectors) {
  if (!values.repository_id) throw new Error("请选择已登记仓库。");
  const timeout = Number(values.timeout_seconds ?? 600);
  const memory = Number(values.memory_mb ?? 2048);
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600 ||
      !Number.isInteger(memory) || memory < 256 || memory > 8192)
    throw new Error("执行预算超出允许范围。");
  return { repository_id: values.repository_id, include_paths: includePaths(values.include_text),
    detector_ids: approvedDetectorIds(detectors), timeout_seconds: timeout, memory_mb: memory };
}
export function snapshotPayload(values, detectors) {
  if (!values.revision?.trim()) throw new Error("请选择或填写分支、Tag 或完整 Commit。");
  const { detector_ids, ...payload } = common(values, detectors);
  return { ...payload, revision: values.revision.trim() };
}
export function planPayload(values, detectors) {
  const { timeout_seconds, memory_mb, ...payload } = snapshotPayload(values, detectors);
  return payload;
}
export function datePreviewPayload(values) {
  const { repository_id, branch, start, end, timezone } = values;
  if (!repository_id || !branch || !start || !end || !timezone)
    throw new Error("请先填写仓库、分支、时间范围和时区。");
  if (start >= end) throw new Error("结束时间必须晚于起始时间。");
  new Intl.DateTimeFormat("en", { timeZone: timezone });
  return { repository_id, branch, start, end, timezone };
}
export function operationPayload(kind, values, detectors) {
  const payload = common(values, detectors);
  if (kind === "date") return { ...payload, ...datePreviewPayload(values) };
  if (kind === "branches") {
    if (!values.baseline_ref || !values.endpoint_ref) throw new Error("请填写两个版本。");
    if (values.baseline_ref === values.endpoint_ref) throw new Error("请选择两个不同的版本。");
    return { ...payload, baseline_ref: values.baseline_ref.trim(), endpoint_ref: values.endpoint_ref.trim() };
  }
  if (kind === "range") return { ...payload, baseline: values.baseline.trim(), endpoint: values.endpoint.trim() };
  if (kind === "matrix") {
    const commits = String(values.commits_text || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (commits.length < 2 || commits.length > 8 || new Set(commits).size !== commits.length ||
        commits.some((s) => !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(s)))
      throw new Error("版本矩阵需要 2–8 个不同的完整小写 SHA。");
    if (!values.case_id) throw new Error("版本矩阵需先关联调查案例。");
    return { ...payload, case_id: values.case_id, commits };
  }
  throw new Error("未知审计类型。");
}
export function localDateTime(date, timezone) {
  const fields = Object.fromEntries(new Intl.DateTimeFormat("en-CA", {
    timeZone: timezone, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
  }).formatToParts(date).map(({ type, value }) => [type, value]));
  return `${fields.year}-${fields.month}-${fields.day}T${fields.hour}:${fields.minute}:${fields.second}`;
}
export function recentRange(days, timezone, now = new Date()) {
  return { start: localDateTime(new Date(now.getTime() - days * 86400000), timezone),
    end: localDateTime(now, timezone) };
}
// Shared with the UI: changing ANY preview input invalidates in-flight responses.
export function requestGate() {
  let sequence = 0;
  return { next: () => ++sequence, invalidate: () => { sequence++; }, current: (id) => id === sequence };
}
