const FULL_COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
function isSafeRepositorySlug(value) {
  if (typeof value !== "string" || [...value].length < 1 || [...value].length > 100 ||
      value === "." || value === ".." || value.includes("/") || value.includes("\\")) {
    return false;
  }
  return ![...value].some((char) => {
    const codePoint = char.codePointAt(0);
    return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
  });
}

export function canPreviewOfficialRepository({ loading, stale, slug }) {
  return !loading && !stale && isSafeRepositorySlug(slug);
}

export function pinnedRepositoryImportRequest(preview) {
  if (!preview || !isSafeRepositorySlug(preview.slug) || !preview.default_branch ||
      !FULL_COMMIT.test(preview.commit || "") || !SHA256.test(preview.preview_sha256 || "")) {
    throw new Error("请先刷新并确认有效的扫描版本预览");
  }
  return {
    slug: preview.slug,
    branch: preview.default_branch,
    commit: preview.commit,
    preview_sha256: preview.preview_sha256,
    include_paths: ["."],
  };
}
