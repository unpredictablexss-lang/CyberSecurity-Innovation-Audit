"""Semantic Ark Runtime model for unseen source identities.

This model deliberately contains no source commit, path, blob, or content-hash
bindings. Its applicability is defined by repository identity, C++ language,
and the declared owner/method/signature contract inherited from the reviewed
local analysis model. It does not claim whole-program or build-profile proof.
"""
from dataclasses import dataclass

from .model import RuntimeTypeModel


UNSEEN_VERSION = "0.8.10"


@dataclass(frozen=True)
class UnseenRuntimeTypeModel(RuntimeTypeModel):
    """Versioned semantic contract that accepts new source revisions/paths."""

    version: str = UNSEEN_VERSION
    source_repository: str = "openharmony/arkcompiler_ets_runtime"
    effect_summary_revision: str = "semantic-contract-v11"
    target_bindings: tuple = ()
    source_dependencies: tuple = ()
    exception_guard_bindings: tuple = ()
    exception_guard_dependencies: tuple = ()
    receiver_guard_bindings: tuple = ()
    effect_summary_sources: tuple = ()

