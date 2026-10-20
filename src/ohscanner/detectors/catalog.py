"""Explicit first-party detector catalog; never import user-supplied module paths.

To ship teammate detectors: review code, tests, sample provenance and
licenses; then explicitly register the imported factory in this file.
"""
from .admission import pending_admission
from .example import CppCopyCallExampleDetector
from .cpp.bounds_detector import CppBoundsDetector
from .cpp.integer_bounds_detector import CppIntegerBoundsDetector
from .cpp.m2_adapter import M2LifetimeDetector, M2SharedPtrRaceDetector
from .ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from .ark_runtime.model import c_line_static_model
from .cpp.null_dereference_detector import NullDereferenceDetector
from .cpp.path_traversal_detector import CppPathTraversalDetector
from .cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from .cpp.unsafe_memory_call_detector import CppUnsafeMemoryCallDetector
from .interface.m2_adapter import M2IpcInterfaceDetector
from .interface.arkts_js import ArkTsJsInterfaceDetector
from .data.sensitive_exposure import SensitiveExposureDetector
from .known_cves import KnownDisclosedCveDetector

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
    "ohscanner.ark.runtime.type_safety": {
        "factory": lambda: ArkRuntimeTypeSafetyDetector(model=c_line_static_model()),
        "kind": "research_candidate",
        "default_enabled": False,
        "admission_reason": "research_only_explicit_selection: exact C1 repository/commit/target/creator blob profile only; partial or unsupported source remains unknown; product impact and independent holdout remain unverified",
        "summary": "C: source-bound Ark Runtime TypedArray static candidates; product impact is unverified",
    },
    "ohscanner.data.sensitive_exposure": {
        "factory": SensitiveExposureDetector,
        "kind": "research_candidate",
        "default_enabled": False,
        "admission_reason": "explicit_selection_required: reviewed source profiles plus blocked candidate-only fallback for unknown revisions; partial coverage remains unknown",
        "summary": "D: sensitive-data exposure candidates; unknown revisions remain blocked/partial, not a vulnerability verdict",
    },
    "ohscanner.known_disclosed_cves": {
        "factory": KnownDisclosedCveDetector,
        "kind": "research_candidate",
        "default_enabled": False,
        "admission_reason": "explicit_selection_required: public-CVE rule development corpus is not an independent holdout; product reachability and impact remain unverified",
        "summary": "Narrow source signatures for selected public CVEs; product reachability remains unverified",
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
        "default_enabled": True,
        "summary": "A: bounded C/C++ copy, element access, unsigned pointer offset, and vector index candidates; not a safety verdict",
    },
    "ohscanner.cpp.integer_bounds": {
        "factory": CppIntegerBoundsDetector,
        "kind": "research_candidate",
        "default_enabled": True,
        "summary": "A: bounded integer range, arithmetic, truncation, and narrowing-index candidates; not a safety verdict",
    },
    "ohscanner.cpp.null_dereference": {
        "factory": NullDereferenceDetector,
        "kind": "research_candidate",
        "default_enabled": False,
        "admission_reason": "explicit_selection_required: unknown-return nullability is a weak observation and may produce broad candidate volumes; use bounded research scope",
        "summary": "A: bounded same-function NULL candidates plus separately identified weak unknown-return observations; default disabled",
    },
    "ohscanner.cpp.path_traversal": {
        "factory": CppPathTraversalDetector,
        "kind": "research_candidate",
        "default_enabled": False,
        "admission_reason": "explicit_selection_required: bounded lexical source-to-file-sink candidates; path semantics, fixed source and product impact remain unverified",
        "summary": "A: bounded C/C++ path traversal candidates; syntax matches do not prove taint, containment or impact",
    },
    "ohscanner.cpp.resource_lifetime": {
        "factory": CppResourceLifetimeDetector,
        "kind": "research_candidate",
        "default_enabled": True,
        "summary": "A: bounded double-free, use-after-free, recursive cleanup, tree amplification, and recursive compare-cost candidates; not a safety verdict",
    },
    "ohscanner.cpp.unsafe_memory_call": {
        "factory": CppUnsafeMemoryCallDetector,
        "kind": "research_candidate",
        "default_enabled": True,
        "summary": "A: reviewed unsafe memory-call candidate with explicit proof obligations",
    },
    "ohscanner.cpp.shared_ptr_race": {
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
        pending = pending_admission(name)
        if pending:
            raise ValueError("not-yet-approved detector admission blocked: " + name + "; "
                             + "; ".join(pending["missing_evidence"]))
        spec = _APPROVED.get(name)
        if spec is None:
            raise ValueError(
                "unknown or not-yet-approved detector: "
                + str(name) + "; available: " + ", ".join(sorted(_APPROVED))
            )
        if spec["kind"] == "example" and not allow_examples:
            raise ValueError("example detector requires --allow-example-detectors")
        registry.register(spec["factory"]())
    return registry
