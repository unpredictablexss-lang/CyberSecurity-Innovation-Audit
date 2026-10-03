"""Historical vulnerability benchmark helpers.

This package replays published security-fix pairs as ground truth for measuring
what the project can and cannot detect. Public historical cases demonstrate
tool capability; they are never counted as new vulnerability discoveries.
"""

from .tool_result import ToolDiagnostic, ToolRunResult
from .historical import (
    HistoricalBenchmarkResult,
    HistoricalSample,
    load_sample,
    run_historical_benchmark,
    write_reports,
)

__all__ = [
    "ToolDiagnostic",
    "ToolRunResult",
    "HistoricalBenchmarkResult",
    "HistoricalSample",
    "load_sample",
    "run_historical_benchmark",
    "write_reports",
]
