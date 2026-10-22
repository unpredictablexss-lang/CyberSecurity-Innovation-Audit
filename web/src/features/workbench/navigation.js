export const auditLinks = [
  { path: "/audits/repository", title: "仓库审计", description: "先做静态扫描，再授权模型辅助研判" },
  { path: "/audits/time", title: "时间增量扫描", description: "按日期选择同一分支的提交并对照候选" },
  { path: "/audits/versions", title: "跨版本安全审计", description: "比较指定提交、分支或 Tag" },
];
const aliases = { "/": "/overview", "/new": "/audits/repository", "/reposcan": "/audits/repository",
  "/deltascan": "/audits/time", "/versions": "/audits/versions", "/cases": "/investigations", "/agent": "/investigations",
  "/repositories": "/settings/sources", "/capabilities": "/settings/capabilities", "/fix": "/impact" };
export function resolveRoute(value) {
  const raw = (value || "/overview").replace(/^#/, "");
  const [pathname, query = ""] = raw.split("?", 2);
  const path = aliases[pathname] || pathname;
  const section = path.startsWith("/audits/") ? path : path.startsWith("/tasks") ? "/tasks" :
    path.startsWith("/risks") ? "/risks" : path.startsWith("/settings") || path === "/operations" ? "/settings" : path;
  return { path, query: new URLSearchParams(query), canonical: path + (query ? "?" + query : ""), section };
}
export function jobDetailPath(id, tab = "findings") {
  return "/tasks/" + encodeURIComponent(id) + "?tab=" + encodeURIComponent(tab);
}
export function detailTab(value) {
  return ["findings", "clusters", "coverage", "source", "events", "reports"].includes(value) ? value : "findings";
}

export function settingsTab(value) {
  return ["sources", "capabilities", "policy", "agent", "runtime"].includes(value) ? value : "sources";
}

export function riskQueuePath(filters) {
  const params = new URLSearchParams();
  if (filters.scan_limit && filters.scan_limit !== "20") params.set("scan_limit", filters.scan_limit);
  for (const key of ["risk_tier", "triage_state", "repository", "detector_id", "q"]) {
    if (filters[key]) params.set(key, filters[key]);
  }
  const query = params.toString();
  return "/risks" + (query ? "?" + query : "");
}

export function retainRiskSource(selected, jobs) {
  return selected || jobs.find((job) => job.report_sha256)?.id;
}
