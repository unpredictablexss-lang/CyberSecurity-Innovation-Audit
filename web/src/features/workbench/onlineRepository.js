const FULL_COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SLUG = /^[A-Za-z0-9_-]{1,100}$/;

export function canPreviewOfficialRepository({ loading, stale, slug }) {
  return !loading && !stale && typeof slug === "string" && SLUG.test(slug);
}

export function pinnedRepositoryImportRequest(preview) {
  if (!preview || !SLUG.test(preview.slug || "") || !preview.default_branch ||
      !FULL_COMMIT.test(preview.commit || "") || !SHA256.test(preview.preview_sha256 || "")) {
    throw new Error("请先刷新并确认有效的固定版本预览");
  }
  return {
    slug: preview.slug,
    branch: preview.default_branch,
    commit: preview.commit,
    preview_sha256: preview.preview_sha256,
    include_paths: ["."],
  };
}
