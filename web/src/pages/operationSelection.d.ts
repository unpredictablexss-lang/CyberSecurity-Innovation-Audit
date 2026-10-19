export function refreshSelectedOperation<T>(
  operationId: string,
  load: (id: string) => Promise<T>,
  getSelectedId: () => string | null,
  apply: (item: T) => void,
): Promise<T>;
