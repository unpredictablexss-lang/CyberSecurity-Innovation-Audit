export function redactionNotice(preview = {}) {
  const categories = Array.isArray(preview?.sensitive_redactions)
    ? preview.sensitive_redactions.filter((item) => typeof item === "string")
    : [];
  const version = typeof preview?.redaction_policy_version === "string"
    ? preview.redaction_policy_version
    : "unknown";
  const detection = categories.length
    ? "已检测并遮蔽的凭据类别：" + categories.join("、") + "。"
    : "未检测到已知凭据格式；这不代表源码中没有秘密。";
  return detection + "规则版本：" + version +
    "。脱敏是有限模式匹配，不是完整 DLP。请检查完整初始上下文和 R2 可能追加发送的数据范围，确认没有不应外发的内容后再授权。";
}

export function disclosureReviewed(openKeys, requiredKeys) {
  if (!Array.isArray(requiredKeys) || requiredKeys.length === 0) return false;
  const opened = new Set(Array.isArray(openKeys) ? openKeys.map(String) : []);
  return requiredKeys.every((key) => opened.has(String(key)));
}

export function disclosureSelectionMatches(selectedKeys, previewKeys) {
  if (!Array.isArray(selectedKeys) || !Array.isArray(previewKeys)
      || selectedKeys.length === 0 || selectedKeys.length !== previewKeys.length) return false;
  const selected = new Set(selectedKeys.map(String));
  const preview = new Set(previewKeys.map(String));
  return selected.size === selectedKeys.length && preview.size === previewKeys.length
    && selected.size === preview.size && [...selected].every((key) => preview.has(key));
}
