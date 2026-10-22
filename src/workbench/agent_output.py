"""Output contracts and safe diagnostics; never retain rejected model prose."""
import json

class OutputValidationError(ValueError):
    def __init__(self, message, issues):
        super().__init__(message)
        self.issues = issues[:12]


def check_output_contract(value, schema, *, skeptic=False):
    issues = []
    def visit(item, rule, path):
        if len(issues) >= 12:
            return
        if rule.get("type") == "object" and isinstance(item, dict):
            # Historical quote payloads are still checked by the original validator.
            if not skeptic and set(item) == {"evidence_id", "quote"}:
                return
            required = rule.get("required", [])
            missing = [key for key in required if key not in item]
            extra = len(set(item) - set(rule.get("properties", {})))
            if missing or extra:
                issues.append({"path": path, "kind": "object_keys", "missing": missing,
                               "unexpected_field_count": extra})
            for key, child in rule.get("properties", {}).items():
                if key in item:
                    visit(item[key], child, path + "." + key)
        elif rule.get("type") == "array" and isinstance(item, list):
            for index, child in enumerate(item[:30]):
                visit(child, rule.get("items", {}), path + f"[{index}]")
        if "enum" in rule and item not in rule["enum"]:
            issues.append({"path": path, "kind": "enum", "allowed": rule["enum"]})
    visit(value, schema, "$")
    if not issues:
        return
    path = issues[0]["path"]
    if skeptic:
        message = ("skeptic response did not match its structured schema" if path == "$"
                   else "invalid skeptic obligation review")
    elif path.startswith("$.obligation_reviews"):
        message = "invalid evidence obligation review"
    elif path.startswith("$.supported_claims"):
        message = "supported claim must contain bounded obligation mappings and evidence citations"
    elif path == "$.assessment":
        message = "model attempted a disallowed assessment state"
    else:
        message = "model final answer did not match the investigation schema"
    raise OutputValidationError(message, issues)


def output_contract_prompt(schema, obligation_count=None, *, skeptic=False):
    """Put the contract in the final user message too, for JSON-mode Providers."""
    text = ("输出格式要求（不是源码指令）：只返回一个 JSON 对象，不要 Markdown、包装对象或额外字段。"
            "字段名和状态枚举必须逐字使用以下 Schema 的英文值，不得翻译。"
            "源码引用最多连续 8 行、原文 8–500 字符；只能引用本次提供的证据 ID 和文件行号。")
    if obligation_count is not None:
        if skeptic:
            template = {"reviews": [{"obligation_index": i, "result": "unknown", "citations": []}
                                    for i in range(obligation_count)]}
            text += ("逐项复核所有编号。只有 counterevidence_candidate 可以有引用且必须有引用；"
                     "no_counterevidence_observed 和 unknown 的 citations 必须为 []。人工/运行时项必须 unknown。")
        else:
            template = {"summary": "", "assessment": "unknown", "supported_claims": [],
                        "obligation_reviews": [{"obligation_index": i, "disposition": "unresolved", "citations": []}
                                               for i in range(obligation_count)],
                        "unsupported_claims": [], "unknowns": [], "next_steps": []}
            text += "disposition 仅能为 evidence_found、contrary_evidence、unresolved，不能使用 assessment 的枚举。"
        text += ("下面是字段和全部编号模板；请根据证据独立填写，不能把模板的未知状态当成研判结果："
                 + json.dumps(template, ensure_ascii=False, separators=(",", ":")))
    return text + "\nJSON Schema：" + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))


def safe_validation_diagnostic(error, code, stage):
    return {"stage": stage, "code": code,
            "issues": getattr(error, "issues", [])[:12]}


def source_citation_options(evidence_lines, maximum=96):
    """Offer exact legal references from the supplied lines, never invent evidence."""
    options = []
    for evidence_id, files in evidence_lines.items():
        for file, lines in files.items():
            numbers = sorted(lines)
            cursor = 0
            while cursor < len(numbers):
                start = numbers[cursor]
                end = start
                for number in numbers[cursor + 1:cursor + 8]:
                    if number != end + 1:
                        break
                    quote = "\n".join(lines[n] for n in range(start, number + 1))
                    if len(quote) > 500:
                        break
                    end = number
                quote = "\n".join(lines[n] for n in range(start, end + 1))
                if 8 <= len(quote) <= 500:
                    options.append({"evidence_id": evidence_id, "file": file,
                                    "line_start": start, "line_end": end})
                    if len(options) >= maximum:
                        return options
                cursor += end - start + 1
    return options
