export const auditLinks: { path: string; title: string; description: string }[];
export function resolveRoute(value: string): { path: string; query: URLSearchParams; canonical: string; section: string };
export function jobDetailPath(id: string, tab?: string): string;
export function detailTab(value: string | null): string;
