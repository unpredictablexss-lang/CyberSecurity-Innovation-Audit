export const INITIAL_ANALYSIS_LABEL = 'AI 初步分析（看当前片段）';
export const DEEP_ANALYSIS_LABEL = 'AI 深入追查（查相关链）';
export const ANALYSIS_DESCRIPTION = '初步分析只分析提供的代码；深入追查会继续查找相关源码。两种方式都不会修改代码。';

// Normalize display text only. Stored operation types, source evidence and hashes stay unchanged.
export function readableAnalysisText(value) {
  if (typeof value !== 'string') return '';
  return value.replace(/\bL0\s*[/–-]\s*L1\b/g, '本地候选整理')
    .replace(/\b[LR]0\b/g, '人工静态复核')
    .replace(/\bL1\b/g, '本地筛选').replace(/\bR1\b|\bL2\b/g, 'AI 初步分析')
    .replace(/\bR2\b|\bL3\b/g, 'AI 深入追查')
    .replace(/快速研判/g, 'AI 初步分析')
    .replace(/AI 初步分析\s*AI 初步分析/g, 'AI 初步分析');
}
