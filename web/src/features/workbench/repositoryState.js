export function canUseCatalog({ loading, error }) {
  return loading !== true && !error;
}

export function canUseVerifiedRepository({ loading, error, status }) {
  return canUseCatalog({ loading, error }) && status === "available";
}

export function filterManagedRepositories(repositories, catalog, query = "") {
  if (!Array.isArray(repositories)) return [];
  const needle = String(query || "").trim().toLocaleLowerCase();
  if (!needle) return repositories;
  const byId = new Map((Array.isArray(catalog) ? catalog : []).map((row) => [row.id, row]));
  return repositories.filter((repo) => {
    const checked = byId.get(repo.id) || {};
    return [repo.id, repo.name, repo.path, checked.display_name, checked.root_alias,
      checked.status, checked.reason]
      .some((value) => typeof value === "string" && value.toLocaleLowerCase().includes(needle));
  });
}
