export const terminal = new Set([
  "completed",
  "completed_with_limitations",
  "blocked",
  "failed",
  "cancelled",
  "interrupted",
  "timed_out",
]);
export async function api(path: string, body?: unknown): Promise<any> {
  const r = await fetch(
    "/api/v1" + path,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-OHScanner-Client": "workbench-v1",
          },
          body: JSON.stringify(body),
        },
  );
  if (!r.ok) {
    const e = await r.json().catch(() => ({ detail: r.statusText }));
    const detail = typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail);
    const lower = detail.toLowerCase();
    const messages: Array<[string, string]> = [
      ["outside configured target roots", "该仓库尚未通过管理员的目录访问校验。请前往“系统设置 → 仓库与源码管理”，在已批准的源码根目录中发现并登记仓库。"],
      ["cannot be a symlink", "仓库或 Git 元数据包含符号链接，未通过目录安全校验。请登记真实的 Git 仓库目录。"],
      ["git metadata is outside", "仓库的 Git 元数据指向已批准目录之外，已拒绝读取。"],
      ["alternate objects are outside", "仓库引用了批准目录之外的 Git 对象，已拒绝读取。"],
      ["configured source root is unavailable", "配置的源码根目录当前不可访问，请检查服务端配置。"],
      ["source root selection is invalid", "所选源码根目录不存在，请刷新设置页后重试。"],
      ["configured source root is unavailable", "源码根目录已经移动、权限变化或无法读取，请到设置页重新校验。"],
      ["managed source-root registry", "本机受控源码根目录配置无法读取；请联系本机管理员检查工作台数据目录。"],
      ["not a local git repository", "该目录不是可读取的本地 Git 仓库，请重新选择仓库根目录。"],
      ["register the repository root, not a subdirectory", "登记路径不是 Git 仓库根目录，请选择包含 .git 的仓库目录。"],
      ["invalid revision; select a local branch, tag or commit", "无法识别该版本。请从本地分支、标签中选择，或输入完整 Commit SHA。"],
      ["source or rule plan changed since preview", "仓库源码或规则计划在预览后发生变化，请重新预览扫描计划。"],
      ["audit workflow changed since preview", "审计方式在预览后发生变化，请重新检查扫描设置。"],
      ["planning deadline exceeded", "扫描计划生成超时；未创建任务。请缩小仓库范围后重试。"],
      ["planning failed within source/resource limits", "扫描计划生成失败；未创建任务。请检查目录范围和服务端资源限制。"],
      ["no applicable approved detector", "当前仓库范围没有适用的已批准检测器；未创建任务，安全状态仍为未知。"],
    ];
    const translated = messages.find(([needle]) => lower.includes(needle));
    throw new Error(translated ? translated[1] : detail);
  }
  return r.json();
}

export async function apiGet(path: string): Promise<any> {
  const r = await fetch("/api/v1" + path, { headers: { Accept: "application/json" } });
  if (!r.ok) {
    const e = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail));
  }
  return r.json();
}
export const artifact = (id: string, kind: string) =>
  "/api/v1/scans/" + id + "/artifacts/" + kind;


export async function apiDelete(path: string): Promise<any> {
  const response = await fetch("/api/v1" + path, {
    method: "DELETE",
    headers: { "X-OHScanner-Client": "workbench-v1" },
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(typeof error.detail === "string" ? error.detail : JSON.stringify(error.detail));
  }
  return response.json();
}
