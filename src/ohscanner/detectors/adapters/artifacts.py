from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class ArtifactDisposition:
    path: str
    kind: str
    recognition: str
    disposition: str
    limitation: str


def _normalized_path(path: str) -> str:
    value = path.replace("\\", "/").strip()
    if not value or value.startswith("/") or ".." in PurePosixPath(value).parts:
        raise ValueError("artifact path must be bounded and relative")
    return value


def classify_artifact(path: str, data: bytes) -> ArtifactDisposition:
    """Identify a small set of non-C/C++ artifacts without parsing their semantics.

    Recognition is deliberately bounded. A P12 suffix plus DER envelope is only
    a PKCS#12 candidate, JSON5 is configuration syntax rather than a supported
    scanner language, and Rust remains outside the current C/C++ detector scope.
    """
    normalized = _normalized_path(path)
    suffix = PurePosixPath(normalized).suffix.lower()
    sample = bytes(data[:4096])

    if suffix in (".p12", ".pfx"):
        der_envelope = bool(sample) and sample[0] == 0x30 and len(sample) > 2
        return ArtifactDisposition(
            normalized,
            "pkcs12-der-candidate" if der_envelope else "pkcs12-by-name-only",
            "suffix+bounded-der-envelope" if der_envelope else "suffix-only",
            "explicit-unknown-unsupported-binary-artifact",
            "P12/PFX is identified only as an opaque signing artifact; keys, trust, provenance, and build use are not interpreted.",
        )

    if suffix == ".json5":
        try:
            text = sample.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        has_container = "{" in text or "[" in text
        return ArtifactDisposition(
            normalized,
            "json5-config-candidate" if has_container else "json5-by-name-only",
            "suffix+bounded-container-scan" if has_container else "suffix-only",
            "explicit-unknown-unsupported-config-language",
            "JSON5 may describe build/signing configuration but is not C/C++ source and cannot establish product inclusion or signing behavior.",
        )

    if suffix == ".rs":
        try:
            text = sample.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        rust_marker = bool(re.search(r"\b(?:fn|impl|trait|unsafe|mod)\b", text))
        return ArtifactDisposition(
            normalized,
            "rust-source-candidate" if rust_marker else "rust-by-name-only",
            "suffix+bounded-token-scan" if rust_marker else "suffix-only",
            "explicit-unknown-unsupported-language",
            "Rust source is recognized for coverage accounting only; this C/C++ detector does not analyze Rust ownership, async, or permission semantics.",
        )

    return ArtifactDisposition(
        normalized,
        "unrecognized-artifact",
        "bounded-suffix-scan",
        "explicit-unknown-unrecognized-artifact",
        "The artifact is outside the bounded P12/JSON5/Rust adapters and receives no security conclusion.",
    )


def limitation_message(disposition: ArtifactDisposition) -> str:
    return (
        f"{disposition.path}: adapter={disposition.kind}; "
        f"recognition={disposition.recognition}; disposition={disposition.disposition}; "
        f"limitation={disposition.limitation}"
    )
