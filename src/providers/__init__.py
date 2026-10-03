"""Normalized provider adapters for static-analysis benchmark evidence."""

from .base import AdapterContext, ToolAdapter
from .registry import get_adapter, normalize_tool_output

__all__ = [
    "AdapterContext",
    "ToolAdapter",
    "get_adapter",
    "normalize_tool_output",
]
