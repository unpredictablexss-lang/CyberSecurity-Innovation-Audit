import React from "react";
import { useState } from "react";
import { chineseNarrative } from "./chineseNarrativeText.js";

export default function ChineseNarrative({ value }: { value: unknown }) {
  const [expanded, setExpanded] = useState(false);
  const presentation = chineseNarrative(value);
  if (presentation.isChinese) return <>{presentation.text}</>;
  return <>
    {presentation.text}
    <button type="button" style={{ border: 0, padding: 0, marginLeft: 6, background: "none", color: "#1677ff", cursor: "pointer" }} onClick={() => setExpanded((current) => !current)}>
      {expanded ? "收起原文" : "查看原文"}
    </button>
    {expanded && <span className="raw" style={{ display: "block", whiteSpace: "pre-wrap" }}>{presentation.original}</span>}
  </>;
}
