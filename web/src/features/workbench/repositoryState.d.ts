export function canUseCatalog(state: { loading: boolean; error?: string | null }): boolean;
export function canUseVerifiedRepository(state: { loading: boolean; error?: string | null; status?: string | null }): boolean;
export function filterManagedRepositories(repositories: any[], catalog: any[], query?: string): any[];
