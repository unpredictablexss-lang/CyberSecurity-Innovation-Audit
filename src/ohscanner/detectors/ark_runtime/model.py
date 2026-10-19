"""Reviewed API semantics, separate from syntax and historical verdicts.

The model describes data arguments, not the presence of a vulnerability.
All symbol resolution is bounded to the declared owner/namespace/signatures.
"""
from dataclasses import dataclass
from hashlib import sha256
import json

DETECTOR_ID = 'ohscanner.ark.runtime.type_safety'
RULE_ID = 'ark.runtime.typedarray-store-type-origin'
VERSION = '0.2.0'
NAMESPACE = 'panda::ecmascript::kungfu'
OWNER = NAMESPACE + '::BuiltinsTypedArrayStubBuilder'
CALLER = OWNER + '::Filter'


@dataclass(frozen=True)
class RuntimeTypeModel:
    """Explicitly versioned assumptions; no historical labels are consumed."""
    version: str = '0.2.0'
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
    caller_profiles: tuple = (OWNER + '::CopyWithin', OWNER + '::Set', OWNER + '::With')
    host_constructors: tuple = (
        ('Label', (1,)), ('NewObjectStubBuilder', (1,)), ('BuiltinsArrayStubBuilder', (1,)),
        ('JSCallArgs', (0, 1)), ('CallStubBuilder', (1, 8)),
    )
    # Passing GateRef by value preserves the caller's binding. It does NOT
    # establish runtime purity or revalidate a previously sampled type token.
    by_value_operations: tuple = (
        ('TaggedIsUndefinedOrNull', 1), ('TaggedIsHeapObject', 1), ('TaggedIsProtoChangeMarker', 1),
        ('IsEcmaObject', 1), ('IsFastTypeArray', 1), ('IsCallable', 1), ('HasConstructor', 1),
        ('GetViewedArrayBuffer', 1), ('IsDetachedBuffer', 1), ('GetPrototypeFromHClass', 1),
        ('GetProtoChangeMarkerFromHClass', 1), ('GetAccessorHasChanged', 1),
        ('GetCallArg0', 1), ('GetCallArg1', 1), ('GetArrayLength', 1), ('FastGetPropertyByIndex', 4),
    )
    readonly_operations: tuple = (('HasPendingException', 1),)
    build_profile: str = 'assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;not_product_build_verified'
    effect_summary_sources: tuple = (
        ('ecmascript/compiler/stub_builder.h', 'b784eb0812c27f11c1bfd8673cda4bf884a6a9cd'),
        ('ecmascript/compiler/stub_builder-inl.h', '8658e6ee729c3b171639772ad3a1ada06442abd0'),
        ('ecmascript/compiler/stub_builder.cpp', '8aae4bfa151e8b8dbd58d03a5cd881f3315151c2'),
        ('ecmascript/compiler/hcr_circuit_builder.h', '176dd0a5ee320f814049c2b671119515c746380d'),
        ('ecmascript/compiler/mcr_circuit_builder.h', '631911dec663addd62533d6a6808ffe699a6f884'),
        ('ecmascript/compiler/lcr_circuit_builder.cpp', 'af4d27bcd46ea0a4a2980a805dd7de77970ffb56'),
        ('ecmascript/compiler/circuit_builder.cpp', 'b4bf452cac6bdeb820b78334be98cb3dc11330cb'),
        ('ecmascript/compiler/new_object_stub_builder.h', 'f411d72cbca7915e56b9d851beeb57b788e438ac'),
        ('ecmascript/compiler/builtins/builtins_stubs.cpp', '715c5d65164369bc93a82aa4a6cc1d19b7970143'),
        ('ecmascript/compiler/builtins/builtins_array_stub_builder.h', '88e131561f756db9bd9e57b3078df22ac3c34c6a'),
        ('ecmascript/compiler/call_stub_builder.h', 'f1f44f44679a9a6d648c8dd0182864d4af7c24f7'),
        ('ecmascript/compiler/profiler_operation.h', 'e68a2db48f222945629adb637cd50be8a0f93651'),
    )
    scalar_operations: tuple = (
        ('GetEnvironment', 0), ('Int32', 1), ('Int64', 1), ('IntPtr', 1), ('Boolean', 1),
        ('True', 0), ('False', 0), ('Hole', 0), ('Undefined', 0), ('Exception', 0),
        ('Int32Add', 2), ('Int64Add', 2), ('Int64Sub', 2), ('Int32LessThan', 2),
        ('Int64LessThan', 2), ('Int64Equal', 2), ('Int32Equal', 2), ('Equal', 2),
        ('ZExtInt32ToInt64', 1), ('TruncInt64ToInt32', 1), ('SExtInt32ToInt64', 1),
        ('VariableType::INT32', 0), ('VariableType::INT64', 0), ('VariableType::JS_ANY', 0),
    )

    @property
    def callers(self):
        # The census reviewed these exact owner/signature profiles. No substring
        # matching and no automatic admission of arbitrary TypedArray methods.
        if self.caller == CALLER:
            return (CALLER,) + self.caller_profiles
        return (self.caller,)

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
    max_scope_depth: int = 128
    max_states: int = 2048
    max_steps: int = 8192
    max_seconds: float = 5.0
