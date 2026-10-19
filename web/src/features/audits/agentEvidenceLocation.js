function splitSourceLines(text, firstLine = 1) {
  const rawLines = String(text || "").replace(/\r\n?/g, "\n").split("\n");
  const lineNumbers = [];
  const sourceLines = rawLines.map((line, index) => {
    const numbered = line.match(/^\s*(\d+):\s?(.*)$/);
    if (numbered) {
      lineNumbers.push(Number(numbered[1]));
      return numbered[2];
    }
    lineNumbers.push(firstLine + index);
    return line;
  });
  return { sourceLines, lineNumbers };
}

function quoteRange(text, quote, firstLine = 1) {
  const cleanQuote = String(quote || "").replace(/\r\n?/g, "\n")
    .split("\n").map((line) => line.replace(/^\s*\d+:\s?/, "")).join("\n");
  if (!cleanQuote) return null;
  const { sourceLines, lineNumbers } = splitSourceLines(text, firstLine);
  const normalizedSource = sourceLines.join("\n");
  const offset = normalizedSource.indexOf(cleanQuote);
  if (offset < 0) return null;
  const startIndex = normalizedSource.slice(0, offset).split("\n").length - 1;
  const endIndex = startIndex + cleanQuote.split("\n").length - 1;
  return {
    start: lineNumbers[startIndex],
    end: lineNumbers[Math.min(endIndex, lineNumbers.length - 1)],
  };
}

function formatRange(file, start, end) {
  if (!file) return "";
  if (!start || start < 1) return file;
  return `${file}:${start}-${end && end >= start ? end : start}`;
}

export function evidenceSourceLocation(result, evidenceId, quote = "", lineReference = null) {
  if (lineReference?.file && Number(lineReference.line_start) > 0) {
    return { file: lineReference.file, line: Number(lineReference.line_start) };
  }
  const binding = result?.binding || {};
  if (evidenceId === result?.initial_evidence?.evidence_id) {
    const context = result.initial_evidence;
    const source = String(context.source_excerpt || context.context?.source_excerpt || "");
    const range = quoteRange(source, quote, Number(context.source_excerpt_start_line || 1));
    const line = range?.start || Number(context.source_excerpt_start_line || 0);
    return binding.file && line > 0 ? { file: binding.file, line } : null;
  }
  const tool = (result?.tool_calls || []).find((item) => item.evidence_id === evidenceId);
  if (!tool) return null;
  const source = tool.result || {};
  if (source.file && Number(source.start_line) > 0) {
    const range = quoteRange(source.text, quote, Number(source.start_line));
    return { file: source.file, line: range?.start || Number(source.start_line) };
  }
  if (!Array.isArray(source.matches)) return null;
  const candidates = source.matches.map((match) => ({
    match,
    range: quoteRange(match.text, quote, Number(match.context_start_line || match.line || 1)),
  }));
  const selected = candidates.find((item) => item.range) || candidates[0];
  if (!selected?.match?.file) return null;
  const line = selected.range?.start || Number(selected.match.line || selected.match.context_start_line || 0);
  return line > 0 ? { file: selected.match.file, line } : null;
}

export function evidenceLocation(result, evidenceId, quote = "", lineReference = null) {
  if (lineReference?.file && Number(lineReference.line_start) > 0) {
    const start = Number(lineReference.line_start);
    const end = Number(lineReference.line_end || start);
    return formatRange(lineReference.file, start, end);
  }
  const binding = result?.binding || {};
  if (evidenceId === result?.initial_evidence?.evidence_id) {
    const context = result.initial_evidence;
    const start = Number(context.source_excerpt_start_line || 0);
    const end = Number(context.source_excerpt_end_line || 0);
    const range = quoteRange(context.source_excerpt || context.context?.source_excerpt, quote, start || 1);
    if (range) return `${formatRange(binding.file, range.start, range.end)} · 初始候选`;
    return start && end ? `${binding.file}:${start}-${end} · 初始候选` : binding.file || "初始上下文";
  }
  const tool = (result?.tool_calls || []).find((item) => item.evidence_id === evidenceId);
  if (!tool) return "证据记录不可用";
  const source = tool.result || {};
  if (source.file && source.start_line && source.end_line) {
    const range = quoteRange(source.text, quote, Number(source.start_line));
    const start = range?.start || Number(source.start_line);
    const end = range?.end || Number(source.end_line);
    return `${formatRange(source.file, start, end)} · 固定提交`;
  }
  if (Array.isArray(source.matches) && source.matches.length > 0) {
    const resolved = source.matches.map((match) => {
      const start = Number(match.context_start_line || match.line || 0);
      const range = quoteRange(match.text, quote, start || 1);
      if (!match.file) return null;
      if (range) return formatRange(match.file, range.start, range.end);
      const textLineCount = String(match.text || "").split(/\r?\n/).length;
      return start > 0 ? formatRange(match.file, start, start + textLineCount - 1) : match.file;
    }).filter(Boolean);
    if (resolved.length > 0) {
      const extra = source.matches.length > resolved.length ? `；另有${source.matches.length - resolved.length} 处` : "";
      return `${resolved.slice(0, 3).join("；")}${extra} · 固定提交`;
    }
  }
  if (source.file) return `${source.file} · 固定提交历史`;
  return tool.tool || "只读工具证据";
}
