"""Small, local BM25 retrieval over the curated OHScanner closeout bundle.

This module is deliberately read-only: it never follows paths outside the
delivery package, never executes corpus files, and keeps no persistent index.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import hashlib
import json
import math
import re


PACKAGE_RELATIVE = Path("research/deliveries/OHScanner结项交付_20261021/实验材料包")
ALLOWED_SUFFIXES = frozenset({
    ".md", ".markdown", ".json", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh",
    ".hpp", ".hxx", ".py", ".js", ".mjs", ".cjs", ".txt", ".text",
})
MAX_FILE_BYTES = 512 * 1024
MAX_REFERENCE_CHARS = 1200
MAX_REFERENCES = 4
_CVE = re.compile(r"\bCVE\s*[-_]\s*(\d{4})\s*[-_]\s*(\d{4,})\b", re.I)
_CWE = re.compile(r"\bCWE\s*[-_]\s*(\d+)\b", re.I)
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_HAN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")
_LINK = re.compile(r"\]\(([^)#?]+)(?:#[^)]*)?\)")
_FILE_REF = re.compile(
    r"[\w.\-/\\（）()\[\] #:-]+\.(?:md|markdown|json|c|cc|cpp|cxx|h|hh|hpp|hxx|py|js|mjs|cjs|txt|text)\b",
    re.I,
)
_RELEVANT_PATH = re.compile(r"(?:cve|poc|harness)", re.I)


def tokenize(value: str) -> list[str]:
    """Tokenize CVE/CWE identifiers, code names, and Chinese bigrams."""
    text = str(value or "")
    tokens: list[str] = []
    for match in _CVE.finditer(text):
        tokens.append(f"cve-{match.group(1)}-{match.group(2)}".lower())
    for match in _CWE.finditer(text):
        tokens.append(f"cwe-{match.group(1)}".lower())
    for match in _IDENTIFIER.finditer(text):
        identifier = match.group(0).lower()
        tokens.append(identifier)
        tokens.extend(part for part in re.split(r"[_$]+|(?<=[a-z])(?=[A-Z])", match.group(0))
                      if len(part) > 1 and part.lower() != identifier)
        # Also split camelCase and acronym boundaries without losing the full symbol.
        tokens.extend(part.lower() for part in re.findall(
            r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[0-9]+", match.group(0))
            if part.lower() != identifier)
    for match in _HAN.finditer(text):
        phrase = match.group(0)
        if len(phrase) == 1:
            tokens.append(phrase)
        else:
            tokens.extend(phrase[index:index + 2] for index in range(len(phrase) - 1))
    return tokens


def _query_text(candidate: dict, report: dict) -> str:
    fields: list[str] = []
    preferred = {
        "cve", "cve_id", "cwe", "cwe_candidate", "detector_id", "detector_version",
        "rule", "rule_id", "file", "path", "component", "component_path",
        "symbol", "title", "summary", "description", "evidence", "obligation_description",
        "obligations", "kind", "rationale", "name", "label", "issue", "finding",
    }

    def collect(value, key=""):
        if isinstance(value, dict):
            for child_key, child in value.items():
                if str(child_key).lower() in preferred or isinstance(child, (dict, list)):
                    collect(child, str(child_key).lower())
        elif isinstance(value, list):
            for child in value:
                collect(child, key)
        elif isinstance(value, (str, int, float)) and key in preferred:
            fields.append(str(value))

    collect(candidate)
    collect(report.get("candidate_context", {}))
    return "\n".join(fields)


def _eligible_path(package_root: Path, path: Path) -> bool:
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        return False
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(package_root.resolve(strict=True))
        relative = resolved.relative_to(package_root.resolve(strict=True)).as_posix()
    except (OSError, ValueError):
        return False
    if not resolved.is_file():
        return False
    # The package's CVE/PoC/Harness subtree and explicitly named indexes are
    # the seed set. Adjacent package-local references are added below.
    return bool(_RELEVANT_PATH.search(relative))


def _line_chunks(path: str, text: str, max_chars: int = MAX_REFERENCE_CHARS):
    lines = text.splitlines()
    current: list[str] = []
    current_chars = 0
    start_line = 1
    for line_number, line in enumerate(lines, start=1):
        segments = [line[index:index + max_chars] for index in range(0, len(line), max_chars)] or [""]
        for segment in segments:
            added = len(segment) + (1 if current else 0)
            if current and current_chars + added > max_chars:
                yield {
                    "path": path, "start_line": start_line,
                    "end_line": line_number if len(segments) > 1 else line_number - 1,
                    "text": "\n".join(current),
                }
                current, current_chars = [], 0
                start_line = line_number
            if not current:
                start_line = line_number
            current.append(segment)
            current_chars += len(segment) + (1 if len(current) > 1 else 0)
            if len(segment) >= max_chars:
                yield {"path": path, "start_line": line_number,
                       "end_line": line_number, "text": segment[:max_chars]}
                current, current_chars = [], 0
                start_line = line_number + 1
    if current:
        yield {"path": path, "start_line": start_line,
               "end_line": len(lines), "text": "\n".join(current)}


def _summary(text: str) -> str:
    for line in text.splitlines():
        cleaned = re.sub(r"^\s{0,3}(?:#{1,6}\s*|[-*+]\s*|>\s*)", "", line).strip()
        if cleaned:
            return cleaned[:240]
    return "材料片段"


def _collect_corpus(package_root: Path):
    try:
        root = package_root.resolve(strict=True)
        if not root.is_dir():
            return None, "unavailable"
    except OSError:
        return None, "unavailable"
    files: dict[Path, tuple[str, str]] = {}
    for path in root.rglob("*"):
        if not _eligible_path(root, path):
            continue
        try:
            raw = path.read_bytes()
            if len(raw) > MAX_FILE_BYTES or b"\0" in raw:
                continue
            text = raw.decode("utf-8-sig")
        except (OSError, UnicodeError):
            continue
        relative = path.resolve().relative_to(root).as_posix()
        files[path.resolve()] = (text, hashlib.sha256(raw).hexdigest())

    # Follow only explicit file references from the seed documents, and only
    # when their resolved targets remain inside this package.
    pending = list(files)
    seen = set(files)
    while pending:
        source_path = pending.pop()
        source_text = files[source_path][0]
        references = [match.group(1).strip() for match in _LINK.finditer(source_text)]
        if source_path.suffix.lower() in {".md", ".markdown", ".json", ".txt", ".text"}:
            references.extend(match.group(0).strip() for match in _FILE_REF.finditer(source_text))
        for reference in references:
            reference = reference.replace("\\", "/")
            if reference.startswith(("http:", "https:", "#")):
                continue
            target = (source_path.parent / reference).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                continue
            if target in seen or target.suffix.lower() not in ALLOWED_SUFFIXES:
                continue
            if not target.is_file():
                # Some indexes cite sibling files by basename.
                matches = list(root.rglob(Path(reference).name))
                target = next((item.resolve() for item in matches
                               if item.is_file() and item.suffix.lower() in ALLOWED_SUFFIXES), target)
            try:
                target.relative_to(root)
                if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
                    continue
                raw = target.read_bytes()
                if b"\0" in raw:
                    continue
                target_text = raw.decode("utf-8-sig")
            except (OSError, UnicodeError, ValueError):
                continue
            seen.add(target)
            files[target] = (target_text, hashlib.sha256(raw).hexdigest())
            pending.append(target)

    if not files:
        return {"root": root, "files": [], "chunks": []}, "empty"
    file_rows = []
    chunks = []
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix().casefold()):
        content, digest = files[path]
        relative = path.relative_to(root).as_posix()
        file_rows.append({"path": relative, "sha256": digest, "bytes": path.stat().st_size})
        title = path.stem
        for chunk in _line_chunks(relative, content):
            chunk["tokens"] = Counter(tokenize(chunk["text"]))
            chunk["sha256"] = digest
            chunk["title"] = title
            chunks.append(chunk)
    corpus_sha256 = hashlib.sha256(json.dumps(
        file_rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return {"root": root, "files": file_rows, "chunks": chunks,
            "corpus_sha256": corpus_sha256}, "ready"


def retrieve_knowledge(repo_root: str | Path, candidate: dict, report: dict | None = None,
                       *, max_references: int = MAX_REFERENCES) -> dict:
    """Return consent-preview-ready retrieval metadata and up to four snippets."""
    report = report if isinstance(report, dict) else {}
    package_root = Path(repo_root) / PACKAGE_RELATIVE
    corpus, state = _collect_corpus(package_root)
    result = {
        "status": state,
        "algorithm": "bm25-k1.5-b0.75-v1",
        "corpus_sha256": corpus.get("corpus_sha256") if corpus else None,
        "indexed_files": len(corpus["files"]) if corpus else 0,
        "references": [],
        "disclaimer": (
            "以下是结项包中的不可信类比参考资料，只用于调查线索；不能证明当前候选，"
            "不能满足当前源码证据义务，也不能作为当前漏洞结论的引用。"
        ),
    }
    if state != "ready":
        return result
    query_tokens = Counter(tokenize(_query_text(candidate, report)))
    if not query_tokens:
        result["status"] = "no_match"
        return result
    chunks = corpus["chunks"]
    document_frequency = Counter()
    for chunk in chunks:
        document_frequency.update(chunk["tokens"].keys())
    count = max(1, len(chunks))
    average_length = (sum(sum(chunk["tokens"].values()) for chunk in chunks) / count) or 1
    scored = []
    for chunk in chunks:
        length = sum(chunk["tokens"].values())
        score = 0.0
        for token, query_frequency in query_tokens.items():
            frequency = chunk["tokens"].get(token, 0)
            if not frequency:
                continue
            df = document_frequency[token]
            inverse = math.log(1 + (count - df + 0.5) / (df + 0.5))
            denominator = frequency + 1.5 * (1 - 0.75 + 0.75 * length / average_length)
            score += inverse * frequency * (1.5 + 1) / denominator * min(query_frequency, 3)
        if score > 0:
            scored.append((score, chunk["path"].casefold(), chunk["start_line"], chunk))
    scored.sort(key=lambda row: (-row[0], row[1], row[2]))
    selected = []
    used = set()
    for score, _, _, chunk in scored:
        if chunk["path"] in used:
            continue
        used.add(chunk["path"])
        selected.append({
            "title": chunk["title"],
            "path": chunk["path"],
            "summary": _summary(chunk["text"]),
            "start_line": chunk["start_line"],
            "end_line": chunk["end_line"],
            "sha256": chunk["sha256"],
            "score": round(score, 6),
            "excerpt": chunk["text"][:MAX_REFERENCE_CHARS],
        })
        if len(selected) >= max(0, min(int(max_references), MAX_REFERENCES)):
            break
    result["references"] = selected
    result["status"] = "matched" if selected else "no_match"
    return result
