"""Provider adapter registry and one unified normalization entry point."""

from typing import Any, Dict

from src.benchmark.tool_result import ToolRunResult
from src.providers.base import AdapterContext, ToolAdapter
from src.providers.clang_sa import ClangSAAdapter
from src.providers.codeql import CodeQLAdapter
from src.providers.cppcheck import CppcheckAdapter
from src.providers.joern import JoernAdapter
from src.providers.semgrep import SemgrepAdapter


_ADAPTERS: Dict[str, ToolAdapter] = {
    "semgrep": SemgrepAdapter(),
    "codeql": CodeQLAdapter(),
    "clang": ClangSAAdapter(),
    "clang_sa": ClangSAAdapter(),
    "clang-static-analyzer": ClangSAAdapter(),
    "cppcheck": CppcheckAdapter(),
    "joern": JoernAdapter(),
    "joern-cpg": JoernAdapter(),
}


def get_adapter(provider: str) -> ToolAdapter:
    key = provider.strip().lower()
    try:
        return _ADAPTERS[key]
    except KeyError as error:
        raise ValueError(f"unsupported provider adapter: {provider}") from error


def normalize_tool_output(
    provider: str,
    payload: Any,
    context: AdapterContext,
) -> ToolRunResult:
    return get_adapter(provider).normalize(payload, context)
