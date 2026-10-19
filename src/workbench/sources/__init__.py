"""Read-only adapters for the existing fixed-source engine."""
from .manifest import SourceFile, SourceManifest, manifest_from_context

__all__ = ["SourceFile", "SourceManifest", "manifest_from_context"]
