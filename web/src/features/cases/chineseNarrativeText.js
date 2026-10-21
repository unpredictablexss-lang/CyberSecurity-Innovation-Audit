const HAN = /[\u3400-\u9fff]/;
const ENGLISH_WORD = /\b[A-Za-z]{3,}\b/g;

export function chineseNarrative(value) {
  const original = typeof value === "string" ? value.trim() : "";
  if (!original) return { text: "", original: "", isChinese: true };
  const hanCount = (original.match(HAN) || []).length;
  const englishWordCount = (original.match(ENGLISH_WORD) || []).length;
  const mostlyEnglish = hanCount === 0 || (englishWordCount >= 3 && hanCount < englishWordCount * 2);
  if (!mostlyEnglish) return { text: original, original: "", isChinese: true };
  return {
    text: "该说明主要为英文，已折叠原文；展开可查看完整内容。",
    original,
    isChinese: false,
  };
}
