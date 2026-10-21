export function canPreviewOfficialRepository(input: {
  loading: boolean;
  stale: boolean | undefined;
  slug: string | undefined;
}): boolean;

export function pinnedRepositoryImportRequest(preview: {
  slug?: string;
  default_branch?: string;
  commit?: string;
  preview_sha256?: string;
} | null | undefined): {
  slug: string;
  branch: string;
  commit: string;
  preview_sha256: string;
  include_paths: string[];
};
