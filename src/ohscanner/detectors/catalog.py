"""Explicit first-party detector catalog; never import user-supplied module paths.

To ship teammate detectors: review code, tests, sample provenance and
licenses; then explicitly register the imported factory in this file.
"""
from .admission import pending_admission
from .example import CppCopyCallExampleDetector
from .cpp.bounds_detector import CppBoundsDetector
from .cpp.integer_bounds_detector import CppIntegerBoundsDetector
from .cpp.m2_adapter import M2LifetimeDetector, M2SharedPtrRaceDetector
from .cpp.null_dereference_detector import NullDereferenceDetector
from .cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from .cpp.unsafe_memory_call_detector import CppUnsafeMemoryCallDetector
from .interface.m2_adapter import M2IpcInterfaceDetector
from .interface.arkts_js import ArkTsJsInterfaceDetector
from .data.sensitive_exposure import SensitiveExposureDetector

_APPROVED = {
    "ohscanner.oh.arkts_js": {
        "factory": ArkTsJsInterfaceDetector,
        "kind": "research_candidate",
        "summary": "B: bounded JS/TS/ArkTS surface candidates; syntax gaps remain unknown",
    },
    "ohscanner.interface.ipc": {
        "factory": M2IpcInterfaceDetector,
        "kind": "research_candidate",
        "summary": "B: bounded IPC trust-boundary candidates; partial syntax is unknown, not safe",
    },
    "ohscanner.data.sensitive_exposure": {
        "factory": SensitiveExposureDetector,
        "kind": "research_candidate",
        "default_enabled": False,
        "admission_reason": "explicit_selection_required: reviewed source profiles plus blocked candidate-only fallback for unknown revisions; partial coverage remains unknown",
        "summary": "D: sensitive-data exposure candidates; unknown revisions remain blocked/partial, not a vulnerability verdict",
    },
    CppCopyCallExampleDetector.detector_id: {
        "factory": CppCopyCallExampleDetector,
        "kind": "example",
        "summary": "C/C++ AST call-site inventory; no vulnerability verdict",
    },
    "ohscanner.cpp.lifetime": {
        "factory": M2LifetimeDetector,
        "kind": "research_candidate",
        "summary": "A: narrow unique_ptr owner-reset/raw-alias candidate; not a proven UAF",
    },
    "ohscanner.cpp.bounds": {
        "factory": CppBoundsDetector,
        "kind": "research_candidate",
        "summary": "A: bounded direct C/C++ element-access candidate; default unassessed, never safe",
    },
    "ohscanner.cpp.integer_bounds": {
        "factory": CppIntegerBoundsDetector,
        "kind": "research_candidate",
        "summary": "A: bounded integer narrowing/index candidate; default unassessed, never safe",
    },
    "ohscanner.cpp.null_dereference": {
        "factory": NullDereferenceDetector,
        "kind": "research_candidate",
        "default_enabled": False,
        "admission_reason": "explicit_selection_required: unknown-return nullability produces broad weak candidates; review a bounded scope first",
        "summary": "A: narrow same-function C/C++ null-source/deref candidate; default unassessed",
    },
    "ohscanner.cpp.resource_lifetime": {
        "factory": CppResourceLifetimeDetector,
        "kind": "research_candidate",
        "summary": "A: bounded resource allocation/release path candidate; default unassessed",
    },
    "ohscanner.cpp.unsafe_memory_call": {
        "factory": CppUnsafeMemoryCallDetector,
        "kind": "research_candidate",
        "summary": "A: reviewed unsafe memory-call candidate with explicit proof obligations",
    },    "ohscanner.cpp.shared_ptr_race": {
        "factory": M2SharedPtrRaceDetector,
        "kind": "research_candidate",
        "summary": "A: narrow non-atomic shared_ptr member candidate (CWE-362); not confirmed",
    },
}


def default_detector_ids():
    """Approved security research detectors selected for ordinary scans.

    The example detector is intentionally excluded and must remain an explicit
    demonstration-only choice.
    """
    return tuple(
        name for name, spec in sorted(_APPROVED.items())
        if spec["kind"] != "example" and spec.get("default_enabled", True)
    )


def resolve_detector_ids(detector_ids=None):
    """Resolve an optional user selection to an explicit immutable ID tuple."""
    if detector_ids is None or len(tuple(detector_ids)) == 0:
        return default_detector_ids()
    names = tuple(detector_ids)
    if len(names) != len(set(names)):
        raise ValueError("duplicate detector identifier")
    return names

def catalog_metadata():
    return {
        name: {key: value for key, value in spec.items() if key != "factory"}
        for name, spec in sorted(_APPROVED.items())
    }


def build_registry(detector_ids, *, allow_examples=False):
    from src.ohscanner.runner import DetectorRegistry

    names = tuple(detector_ids)
    if not names:
        raise ValueError("M2 requires at least one explicitly selected first-party detector")
    if len(names) != len(set(names)):
        raise ValueError("duplicate detector identifier")
    registry = DetectorRegistry()
    for name in names:
        spec = _APPROVED.get(name)
        if spec is None:
            pending = pending_admission(name)
            if pending:
                raise ValueError("not-yet-approved detector admission blocked: " + name + "; "
                                 + "; ".join(pending["missing_evidence"]))
            raise ValueError(
                "unknown or not-yet-approved detector: "
                + str(name) + "; available: " + ", ".join(sorted(_APPROVED))
            )
        if spec["kind"] == "example" and not allow_examples:
            raise ValueError("example detector requires --allow-example-detectors")
        registry.register(spec["factory"]())
    return registry
