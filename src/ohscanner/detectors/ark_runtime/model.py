"""Reviewed API semantics, separate from syntax and historical verdicts.

The model describes data arguments, not the presence of a vulnerability.
All symbol resolution is bounded to the declared owner/namespace/signatures.
"""
from dataclasses import dataclass
from hashlib import sha256
import json

DETECTOR_ID = 'ohscanner.ark.runtime.type_safety'
RULE_ID = 'ark.runtime.typedarray-store-type-origin'
EXCEPTION_GUARD_RULE_ID = 'ark.runtime.typedarray-allocation-exception-guard'
VERSION = '0.6.3'
NAMESPACE = 'panda::ecmascript::kungfu'
OWNER = NAMESPACE + '::BuiltinsTypedArrayStubBuilder'
CALLER = OWNER + '::Filter'


@dataclass(frozen=True)
class RuntimeTypeModel:
    """Explicitly versioned assumptions; no historical labels are consumed."""
    version: str = '0.6.3'
    source_repository: str = 'openharmony/arkcompiler_ets_runtime'
    effect_summary_revision: str = 'a0e30483ab3e4aead67ecfb5c708489915e447f9'
    target_bindings: tuple = (
        ('830e85b40240677039719fcbf14f721ad3b19050', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '054451b1be4f39254d56a1683cc9d1c1b5e55018', '847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422'),
        ('a0e30483ab3e4aead67ecfb5c708489915e447f9', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '95f54f2875f401afe3167c62f8c1e7799782be8c', '8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e'),
    )
    source_dependencies: tuple = (('ecmascript/compiler/new_object_stub_builder.cpp', '757b8d050d306d349822600deacb295c7a54245e'),)
    # Independent historical pair for exception-path hardening. These bindings
    # authorize only the narrowly modeled NewTypedArray -> LoadHClass check.
    exception_guard_bindings: tuple = (
        ('c758818dbfd0b146a908d43d21f6ca1706c33783', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '857ad416bc102fcd5d462e9702d2ba7c51f29b6d', '984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9'),
        ('81ca57487d04ea30cd11c271e86494a4e130f43e', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '3b9de9d915d767d7a67316145451da2446162884', '4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0'),
    )
    # C3 snapshot is deliberately denied until all model dependencies are
    # semantically reviewed. The digest identifies the immutable comparison
    # manifest, not a claim that the observed dependencies are safe/equivalent.
    blocked_dependency_snapshots: tuple = (
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656',
         '8781f036a3e7e04d8e0b34970d5f623b42875016',
         '7f1c19c5ba21a311fba7f018df8fff077c6c9a60ee81c3ce348bb5b0a9f017d2',
         'c920f31bc6fe4c05d0d64b210b26dacc8b01d277aeb86ca552ddf52ce83f8d2d',
         'unknown_unreviewed_semantics'),
    )
    exception_guard_creator: tuple = ('NewTypedArray', 4)
    exception_guard_callers: tuple = (OWNER + '::Filter', OWNER + '::Map')
    exception_guard_caller_types: tuple = ('GateRef', 'GateRef', 'GateRef', 'Variable*', 'Label*', 'Label*')
    exception_guard_sink: tuple = ('LoadHClass', 2, 0, 1)
    exception_guard_dependencies: tuple = (
        ('c758818dbfd0b146a908d43d21f6ca1706c33783', 'ecmascript/compiler/new_object_stub_builder.cpp', '05dda56de74949f07a241942be6465beaf94b52a', 'c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e'),
        ('81ca57487d04ea30cd11c271e86494a4e130f43e', 'ecmascript/compiler/new_object_stub_builder.cpp', '05dda56de74949f07a241942be6465beaf94b52a', 'c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e'),
    )
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
    # Reviewed only for preserving a TypedArray's class/type identity. This is
    # not a general purity claim; unsupported calls still invalidate all facts.
    type_stable_operations: tuple = (
        ('TaggedIsHeapObject', 1), ('IsFastTypeArray', 1), ('IsTypedArray', 1), ('IsJsCOWArray', 1),
        ('HasConstructor', 1),
        ('GetArrayLength', 1), ('GetCallArg0', 1), ('GetCallArg1', 1), ('GetCallArg2', 1),
        ('TaggedIsInt', 1), ('TaggedGetInt', 1), ('GetInt64OfTInt', 1),
        ('Int64GreaterThan', 2), ('Int64GreaterThanOrEqual', 2), ('BitOr', 2),
        ('CalculatePositionWithLength', 2), ('FastGetPropertyByIndex', 4),
        ('StoreTypedArrayElement', 5),
    )
    same_type_creator: tuple = (NAMESPACE + '::NewObjectStubBuilder', 'NewTypedArraySameType', 4, 1, 2)
    copy_buffer_runtime: tuple = ('CallNGCRuntime', 'CopyTypedArrayBuffer', 3, 6)
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
        ('ecmascript/base/typed_array_helper-inl.h', '3adadba4324927a18ff715efa99b2aa9cd15bc41'),
        ('ecmascript/base/typed_array_helper.cpp', '17f4b8f50ea126eb646ef011e9b7fa7e461394dc'),
        ('ecmascript/stubs/runtime_stubs.cpp', 'c7ce18a76e25289ee7274354fd85950fa9b17af8'),
        ('ecmascript/js_typed_array.cpp', '892e376de57c08c768831936503a8e4dac4b39bb'),
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
        # Compatibility view; the source bindings are also digest inputs.
        return (tuple((revision, path, blob) for revision, path, blob, _ in self.target_bindings)
                + tuple((revision, path, blob) for revision, path, blob, _ in self.exception_guard_bindings)
                + tuple((self.effect_summary_revision, path, blob) for path, blob in self.source_dependencies)
                + tuple((revision, path, blob) for revision, path, blob, _ in self.exception_guard_dependencies))


@dataclass(frozen=True)
class AnalysisBudget:
    max_source_bytes: int = 1024 * 1024
    max_instructions: int = 4096
    max_scope_depth: int = 128
    max_states: int = 2048
    max_steps: int = 8192
    max_seconds: float = 5.0
