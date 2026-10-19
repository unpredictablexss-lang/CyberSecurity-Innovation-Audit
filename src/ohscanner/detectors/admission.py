"""Owner-reviewed pending deliveries; no factories or execution fallback.

These records explain missing evidence. They are not approved detectors, do
not expand default selection, and cannot authorize partial-AST execution.
"""
from copy import deepcopy

_PENDING = (
)


def pending_admissions():
    """Return detached descriptive metadata. Never instantiate pending code."""
    return deepcopy(list(_PENDING))


def pending_admission(detector_id):
    return next((row for row in pending_admissions() if row["id"] == detector_id), None)
