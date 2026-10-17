/** Load an operation detail without allowing an older response to replace a newer selection. */
export async function refreshSelectedOperation(operationId, load, getSelectedId, apply) {
  const item = await load(operationId);
  if (getSelectedId() === operationId) apply(item);
  return item;
}
