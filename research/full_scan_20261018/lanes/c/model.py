"""Reviewed API semantics, separate from syntax and historical verdicts.

The model describes data arguments, not the presence of a vulnerability.
All symbol resolution is bounded to the declared owner/namespace/signatures.
"""
from dataclasses import dataclass
from hashlib import sha256
import json

DETECTOR_ID = 'ohscanner.ark.runtime.type_safety'
RULE_ID = 'ark.runtime.typedarray-store-type-origin'
VERSION = '0.3.10'
MODEL_REPOSITORY = 'openharmony/arkcompiler_ets_runtime'
NAMESPACE = 'panda::ecmascript::kungfu'
OWNER = NAMESPACE + '::BuiltinsTypedArrayStubBuilder'
CALLER = OWNER + '::Filter'


@dataclass(frozen=True)
class RuntimeTypeModel:
    """Explicitly versioned assumptions; no historical labels are consumed."""
    version: str = '0.3.10'
    # Parser versions are part of the model identity. Tree-sitter grammar/runtime
    # drift can change recovery nodes and must fail closed before partial replay.
    parser_environment: tuple = (
        ('tree-sitter', '0.26.0'),
        ('tree-sitter-cpp', '0.23.4'),
        ('cpp_grammar_abi', '14'),
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
    # A false HasPendingException branch guards reads of objects just created
    # by a potentially throwing creator; unknown calls invalidate that fact.
    readonly_operations: tuple = (('HasPendingException', 1),)
    build_profile: str = 'assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;not_product_build_verified'
    # Only the independently replayed parent/fix pair is modeled. Other commits
    # must fail closed even when they contain the same API spellings.
    source_profiles: tuple = (
        ('830e85b40240677039719fcbf14f721ad3b19050',
         '579712c1ebbb703d17cea422b1572023bed5d8a4',
         '054451b1be4f39254d56a1683cc9d1c1b5e55018',
         '757b8d050d306d349822600deacb295c7a54245e'),
        ('a0e30483ab3e4aead67ecfb5c708489915e447f9',
         '82af11ced4297818410ccf61906b703d25b69165',
         '95f54f2875f401afe3167c62f8c1e7799782be8c',
         '757b8d050d306d349822600deacb295c7a54245e'),
    )
    additional_source_dependencies: tuple = (
        ('ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h', 'dec0677003a9209cb61e2a692a0995201aca7428'),
        ('ecmascript/compiler/builtins/builtins_call_signature_list.h', '86eedb54583556006e755325e8ae1e5653bd9785'),
        ('ecmascript/compiler/BUILD.gn', 'bff0145a50065bad462beb5a1feb567ae1aea517'),
        ('ecmascript/compiler/builtins/builtins_stubs.h', 'a7c8afb9523efdd39837f2eb405f1e5cf3ea7563'),
        ('ecmascript/js_typed_array.h', '245a848947dd3f11be2488b64602c7c4d16ebcbf'),
        ('ecmascript/js_arraybuffer.h', '126259c9b6a51599751bcee384a44bd636ec6770'),
        ('ecmascript/js_dataview.h', 'c93f078ecd4ef400ba035b996e776c3759f6e56e'),
        ('ecmascript/base/typed_array_helper-inl.h', '3adadba4324927a18ff715efa99b2aa9cd15bc41'),
        ('ecmascript/compiler/gate.h', 'e1f47a40708012e5d42995fe82e4be097cc2cd19'),
        ('ecmascript/compiler/share_gate_meta_data.h', 'acba13274a3485fea764aa9e2be575bb58a0c4e6'),
        ('ecmascript/compiler/circuit_builder_helper.h', '543c442ac4cabcde84ff82abc3d8ca267d2c0a6b'),
        ('ecmascript/compiler/circuit_builder.h', 'c4ac896e9bb6798762b1be8d889ad87f80e63180'),
        ('ecmascript/compiler/rt_call_signature.h', '41628e7484312d79ce41f25e167428b6ae9166b7'),
        ('ecmascript/compiler/variable_type.h', '72008694c6a16f6532b261d0d9d2493273e383ce'),
        ('ecmascript/js_hclass.h', 'c16dcd8a88ba22f935b2b7543b8d05a20cbcb978'),
        ('ecmascript/ecma_runtime_call_info.h', 'f3c6fcb23559fcb00b0f7954ddba2024e1afc878'),
        ('ecmascript/js_typed_array.cpp', '892e376de57c08c768831936503a8e4dac4b39bb'),
        ('ecmascript/builtins/builtins_arraybuffer.cpp', '44ca29e3d4b3ba83e8b458bf64dc285303dd7da0'),
        ('ecmascript/stubs/runtime_stubs.cpp', 'c7ce18a76e25289ee7274354fd85950fa9b17af8'),
        ('ecmascript/stubs/runtime_stub_list.h', '3a973fac5092e206ea263c84635d8df451981abd'),
        ('ecmascript/builtins/builtins_arraybuffer.h', '574e10ee1805466b54889a3befca4846022a4f14'),
        ('ecmascript/base/typed_array_helper.cpp', '17f4b8f50ea126eb646ef011e9b7fa7e461394dc'),
        ('ecmascript/builtins/builtins_typedarray.cpp', '8d8184928db803f3aa26971e5a15c22ce0ade41f'),
        ('ecmascript/builtins/builtins_typedarray.h', '79b3e415414b53e163f59c443773094292f471df'),
        ('ecmascript/object_operator.cpp', 'a192003108694900f1c39a4263a77a782f7c67c4'),
        ('ecmascript/global_env.h', '74dac4fbb5dcb3ce61726948ee6d2e334a1c9167'),
    )
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
        # Only Filter has the frozen source/token interpretation. The other
        # methods are review controls, not analyzable targets under this model.
        return (self.caller,)

    @property
    def digest(self):
        return sha256(json.dumps(self.__dict__, sort_keys=True).encode()).hexdigest()

    @property
    def sources(self):
        return tuple(binding for commit, _, target_blob, creator_blob in self.source_profiles
                     for binding in ((commit, 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', target_blob),
                                     (commit, 'ecmascript/compiler/new_object_stub_builder.cpp', creator_blob)))

    def bindings_for_commit(self, commit):
        for pinned_commit, _tree, target_blob, creator_blob in self.source_profiles:
            if pinned_commit == commit:
                core = (
                    (pinned_commit, 'ecmascript/compiler/new_object_stub_builder.cpp', creator_blob),
                    (pinned_commit, 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', target_blob),
                )
                effect_sources = tuple(
                    (pinned_commit,
                     path if path.startswith('ecmascript/') else 'ecmascript/compiler/' + path,
                     oid)
                    for path, oid in self.effect_summary_sources
                )
                declared_sources = tuple((pinned_commit, path, oid)
                                         for path, oid in self.additional_source_dependencies)
                # Preserve order while avoiding duplicate checks across the
                # summarized effect APIs and their declaration/macro sources.
                return tuple(dict.fromkeys(core + effect_sources + declared_sources))
        return ()

    @property
    def creator_dependency(self):
        """Exact source object required to interpret the modeled creator call."""
        return self.bindings_for_commit('a0e30483ab3e4aead67ecfb5c708489915e447f9')[0]

    @property
    def target_source(self):
        """Exact source object whose caller/creator semantics were reviewed."""
        return self.bindings_for_commit('a0e30483ab3e4aead67ecfb5c708489915e447f9')[1]


@dataclass(frozen=True)
class AnalysisBudget:
    max_source_bytes: int = 1024 * 1024
    max_instructions: int = 4096
    max_scope_depth: int = 128
    max_states: int = 2048
    max_steps: int = 8192
    max_seconds: float = 5.0
