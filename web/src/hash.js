/**
 * Keep optional source/report hashes safe to render when older or partial
 * records do not contain one.
 * @param {string | null | undefined} value
 */
export function hashPresentation(value) {
  const display = typeof value === "string" && value.length > 0 ? value : null;
  return {
    text: display ? display.slice(0, 12) : "未知",
    copyable: display ? { text: display } : false,
  };
}
