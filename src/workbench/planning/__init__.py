"""Deterministic proposals; no execution, catalog registration, or verdicts."""
from .audit import PLANNER_VERSION, plan_audit, metadata_from_detectors

__all__ = ["PLANNER_VERSION", "plan_audit", "metadata_from_detectors"]
