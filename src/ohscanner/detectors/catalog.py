"""Explicit first-party detector catalog; never import user-supplied module paths.

To ship teammate detectors: review code, tests, sample provenance and
licenses; then explicitly register the imported factory in this file.
"""
from .example import CppCopyCallExampleDetector
from .cpp.m2_adapter import M2LifetimeDetector, M2SharedPtrRaceDetector

_APPROVED = {
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
    "ohscanner.cpp.shared_ptr_race": {
        "factory": M2SharedPtrRaceDetector,
        "kind": "research_candidate",
        "summary": "A: narrow non-atomic shared_ptr member candidate (CWE-362); not confirmed",
    },
}


def catalog_metadata():
    return {
        name: {"kind": spec["kind"], "summary": spec["summary"]}
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
            raise ValueError(
                "unknown or not-yet-approved detector: "
                + str(name) + "; available: " + ", ".join(sorted(_APPROVED))
            )
        if spec["kind"] == "example" and not allow_examples:
            raise ValueError("example detector requires --allow-example-detectors")
        registry.register(spec["factory"]())
    return registry
