"""Reviewed API semantics, separate from syntax and historical verdicts.

The model describes data arguments, not the presence of a vulnerability.
All symbol resolution is bounded to the declared owner/namespace/signatures.
"""
from dataclasses import dataclass
from hashlib import sha256
import json

DETECTOR_ID = 'ohscanner.ark.runtime.type_safety'
RULE_ID = 'ark.runtime.typedarray-store-type-origin'
VERSION = '0.1.0'
NAMESPACE = 'panda::ecmascript::kungfu'
OWNER = NAMESPACE + '::BuiltinsTypedArrayStubBuilder'
CALLER = OWNER + '::Filter'


@dataclass(frozen=True)
class RuntimeTypeModel:
    """Explicitly versioned assumptions; no historical labels are consumed."""
    version: str = '0.1.0'
    caller: str = CALLER
    caller_types: tuple = ('GateRef', 'GateRef', 'GateRef', 'Variable*', 'Label*', 'Label*')
    store_name: str = 'StoreTypedArrayElement'
    store_types: tuple = ('GateRef',) * 5
    target_argument: int = 1  # zero based, excluding implicit C++ this
    token_argument: int = 4
    creator_owner: str = NAMESPACE + '::NewObjectStubBuilder'
    creator_name: str = 'NewTypedArray'
    creator_arguments: int = 4
    species_may_change_type: bool = True

    @property
    def digest(self):
        return sha256(json.dumps(self.__dict__, sort_keys=True).encode()).hexdigest()

    @property
    def sources(self):
        return (
            ('a0e30483ab3e4aead67ecfb5c708489915e447f9',
             'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp',
             '95f54f2875f401afe3167c62f8c1e7799782be8c'),
            ('a0e30483ab3e4aead67ecfb5c708489915e447f9',
             'ecmascript/compiler/new_object_stub_builder.cpp',
             '757b8d050d306d349822600deacb295c7a54245e'),
        )


@dataclass(frozen=True)
class AnalysisBudget:
    max_source_bytes: int = 1024 * 1024
    max_instructions: int = 4096
    max_states: int = 2048
    max_steps: int = 8192
    max_seconds: float = 5.0
