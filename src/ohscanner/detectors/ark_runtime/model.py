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
SIZE_OVERFLOW_RULE_ID = 'ark.runtime.typedarray-buffer-size-multiplication-overflow'
RUNTIME_EXCEPTION_RULE_ID = 'ark.runtime.callback-exception-before-result-conversion'
CALL_INFO_EXCEPTION_RULE_ID = 'ark.runtime.call-info-construction-exception-guard'
RECEIVER_TYPE_GUARD_RULE_ID = 'ark.runtime.typedarray-receiver-type-guard'
LENGTH_NARROWING_RULE_ID = 'ark.runtime.typedarray-length-signed-to-unsigned-narrowing'
INDEX_BOUNDS_RULE_ID = 'ark.runtime.dataview-index-width-bounds'
NATIVE_EXCEPTION_RULE_ID = 'ark.runtime.native-inline-pending-exception-propagation'
GAP_RULE_VERSIONS = {
    LENGTH_NARROWING_RULE_ID: '1.1.0',
    INDEX_BOUNDS_RULE_ID: '1.1.0',
    NATIVE_EXCEPTION_RULE_ID: '1.1.0',
}
RULE_VERSIONS = {
    RULE_ID: '1.1.0',
    EXCEPTION_GUARD_RULE_ID: '1.1.0',
    RECEIVER_TYPE_GUARD_RULE_ID: '1.1.0',
    SIZE_OVERFLOW_RULE_ID: '1.1.0',
    RUNTIME_EXCEPTION_RULE_ID: '1.1.0',
    CALL_INFO_EXCEPTION_RULE_ID: '1.1.0',
    **GAP_RULE_VERSIONS,
}
VERSION = '0.6.2'
NAMESPACE = 'panda::ecmascript::kungfu'
OWNER = NAMESPACE + '::BuiltinsTypedArrayStubBuilder'
CALLER = OWNER + '::Filter'


@dataclass(frozen=True)
class RuntimeTypeModel:
    """Explicitly versioned assumptions; no historical labels are consumed."""
    version: str = '0.8.15'
    source_repository: str = 'openharmony/arkcompiler_ets_runtime'
    effect_summary_revision: str = 'c13-cross-file-contract-v1'
    target_bindings: tuple = (
        ('830e85b40240677039719fcbf14f721ad3b19050', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '054451b1be4f39254d56a1683cc9d1c1b5e55018', '847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422'),
        ('a0e30483ab3e4aead67ecfb5c708489915e447f9', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '95f54f2875f401afe3167c62f8c1e7799782be8c', '8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e'),
        # Exact D-drive current snapshot binding, admitted for explicit research only.
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '68fb3b0adc4f9062889a861be51b7be90362e37a', '76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c'),
    )
    source_dependencies: tuple = (('ecmascript/compiler/new_object_stub_builder.cpp', '757b8d050d306d349822600deacb295c7a54245e'),)
    # Reviewed declarations backing the glue-aware HClass read and builder
    # constructor overloads. These are semantic evidence inputs, not an
    # applicability allowlist and not proof that the product build used them.
    api_overload_evidence: tuple = (
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/circuit_builder.h',
         'df296de399f31a97417ed124f4ed8f8e4fd608b7',
         '41ce63da35d4f9abf5e32bcd417384fadcb018718d002b798e339da11a1a7d70'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/stub_builder.h',
         '9e2fbd3ede1da91133dcd936018285e597944515',
         'a11ca83c0a8bbe16ea4ce9dabb2ab3aca2ee9c680a95433371e79494e2a92cb0'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/new_object_stub_builder.h',
         'ecdf871b20e884e013ce0f26877ef404e4950cb0',
         'd84a72bb1a252fb9ea2b8ff01e702c3a0c952681e211d8f1a850f1880217778b'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656',
         'ecmascript/compiler/builtins/builtins_array_stub_builder.h',
         'c9b5a66c12c657533047286ec79406a639fb8232',
         '1804426bca64803a2a7b70c63004eb5236718daa075c67d74c68fd5f21ef151c'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656',
         'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h',
         '017286724e4cd6df1a369589293efe920660c4c6',
         'f5b25eed46bfe6e951c6ad8b79ff76bfee8d402868839d21e6d41cd84ef3f8e3'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/circuit_builder.cpp',
         '225f09385632bfc2a6ff20bbdf2bfd8694fcffb6',
         '33fac8872f897163ec8261674cad91e8722609e005732a30d675628145974a29'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/hcr_circuit_builder.h',
         'e66c414a7a739284b474c234e6f90bae0368cd11',
         '380940bddd7790a8c65e5297ed0646ff2dd5301b2a1197fa78b3766ab8653497'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/stub_builder.cpp',
         'c630a6200215705843d11c0dd86c565709e8c6c4',
         '978f507daa99982b115f2db4e63ce629c653f011b4b998ac9e20255ab786b25a'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/stub_builder-inl.h',
         'c0521ab7a55cd63850736c2db8a290115965373c',
         'e3e840771be228a2c5e6c15576ecdf3f06175622b5840525520345f1d22d76be'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/call_stub_builder.h',
         'd1fb1b9ef28ff8c928a6e8dfdd9aed67e42ef6aa',
         '18af6653e22c36dc1fce30d9b7b7eda9d616084add2b1c6d1faa6d89c6c895ae'),
    )
    # These glue-aware overloads lower to compiler graph reads and control
    # flow. They preserve the C++ GateRef argument binding; this is not a
    # claim that the object or its runtime type stays stable across callbacks.
    reviewed_graph_read_overloads: tuple = (
        ('IsEcmaObject', 2), ('GetViewedArrayBuffer', 2), ('IsDetachedBuffer', 2),
        ('HasConstructor', 2), ('GetPrototypeFromHClass', 2),
        ('GetProtoChangeMarkerFromHClass', 2), ('IsCallable', 2),
        ('IsTypedArray', 2), ('IsJsCOWArray', 2),
    )
    # Independent historical pair for exception-path hardening. These bindings
    # authorize only the narrowly modeled NewTypedArray -> LoadHClass check.
    exception_guard_bindings: tuple = (
        ('c758818dbfd0b146a908d43d21f6ca1706c33783', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '857ad416bc102fcd5d462e9702d2ba7c51f29b6d', '984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9'),
        ('81ca57487d04ea30cd11c271e86494a4e130f43e', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '3b9de9d915d767d7a67316145451da2446162884', '4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0'),
        ('a65a2853ccae13da167d9aa4720ab8b11ec16656', 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp', '68fb3b0adc4f9062889a861be51b7be90362e37a', '76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c'),
    )
    # Exact source identities authorize replay; the rule itself is based on
    # receiver/type data flow and generated branch dominance.
    receiver_guard_bindings: tuple = (
        ('c4c52fb57b6e204128e1520340c8e66c8e708981',
         'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp',
         'e1e4f6411df4733b8f1ba5b679189e29d904a63f',
         'f1cdd8d0707cab2ac9bb9e024383151435bfc279c6815c5eceb98925974ff1a4'),
        ('2a70904be0e21a37a666eb00cab49d02068260ea',
         'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp',
         'df765b9c212dc2e55c38dc385f85f183ce6606da',
         'b51826a74a89d6ee105c4087b4260363a7abfd632bb2c68d43c0ee9b17c883c5'),
    )
    # Exact local-object bindings are evidence/source-integrity gates only.
    # The size rule decides from arithmetic, allocation flow, and copy-loop
    # structure; no CVE, revision, path name, or function name is a predicate.
    size_overflow_bindings: tuple = (
        ('087449d3d657d081611cf1bf4c731ff048748812',
         'ecmascript/base/typed_array_helper.cpp',
         'caa5467917bbd9079a4d72cdfb419266e315a624',
         '170660d6f15ad88ddee04db4ded3e76932832631d0613e78318edf2b0ad6fc85'),
        ('1b0ac0aa076b91d92b5d5aba91e92bc6c2a06c50',
         'ecmascript/base/typed_array_helper.cpp',
         '319347a5ea62df52e8427ad6822f65e70c997a11',
         'f698f40394524b5b95a1bbef4fe8b1ccef05e52226d9d1f30ef54decca711a62'),
    )
    length_narrowing_bindings: tuple = (
        ('3c1a50cfb1206ce63afcd2d0ef2b1e81668f2e3c',
         'ecmascript/base/typed_array_helper.cpp',
         'c5153346369f0182e73098b8d008eca6d750b36d',
         '4be243a68180be845defbcc01b259070db68b18da8500d245eea4929e7b9eca5'),
        ('82c21d656880923800c94b53b035c76d219313b5',
         'ecmascript/base/typed_array_helper.cpp',
         '89ffed8b3ff112a271c8a074967b7b5e8ebe2f6f',
         '373f5babdd5dd2f93d01512901d02e6b39d6b57c636e72b07b8d80d27eb509ab'),
    )
    index_bounds_bindings: tuple = (
        ('d62f6de64daa7e11a7936a6153748a7c5fae9e41', 'ecmascript/base/atomic_helper.cpp',
         '7fd67717571c6d8fe7b10bf294998e952dc61e36',
         'f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541'),
        ('48fcec3686e45175f95b4600b579026a65149966', 'ecmascript/base/atomic_helper.cpp',
         '80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c',
         '39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b'),
        ('d62f6de64daa7e11a7936a6153748a7c5fae9e41', 'ecmascript/builtins/builtins_dataview.cpp',
         'e6bac984354292405ae62f7728170d7be5e3760e',
         'bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c'),
        ('48fcec3686e45175f95b4600b579026a65149966', 'ecmascript/builtins/builtins_dataview.cpp',
         'a2376e822e995333b2400520ca5b882de9578b5e',
         '39b1ed79451980ad85e1176805deaf6c6315bca09d7676ea5c63f5ff1c4bd65b'),
        ('d62f6de64daa7e11a7936a6153748a7c5fae9e41',
         'ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp',
         'aedb6d26681535371d1e9ed90b697b923b8100e6',
         'bd55a638db7292305dd7b564c5767657e105a48f064c66809934f5e3e6a5f548'),
        ('48fcec3686e45175f95b4600b579026a65149966',
         'ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp',
         'dce9388e8b7e33c87aec33ac4d067fe40370561b',
         '89fd548588f59a5f0756868957ff011609264b7d10437a8636c3f3262da1d386'),
    )
    runtime_exception_bindings: tuple = ()
    native_exception_bindings: tuple = (
        ('3fc1d0b960e0b1bb5bfe1aad8066bb8c9aa99724',
         'ecmascript/compiler/native_inline_lowering.cpp',
         'bdafa81ac797501852f639575d3a30f48b6ff25a',
         'fcf0b9c6371ed348f433f637130fef7ae886d7cc1d241bb072fc37e252f33463'),
        ('18d8532a200d0c9aa64a6dfe2b146dc841b52bf8',
         'ecmascript/compiler/native_inline_lowering.cpp',
         'df03fdce8a37cf2245577aec23c4c26deeebf02f',
         '6e5a248ec9b82a4955232845f08f02383d6b941caca2c80f0317f4ccba7d33ce'),
    )
    exception_guard_creator: tuple = ('NewTypedArray', 4)
    exception_guard_callers: tuple = (OWNER + '::Filter', OWNER + '::Map')
    exception_guard_caller_types: tuple = ('GateRef', 'GateRef', 'GateRef', 'Variable*', 'Label*', 'Label*')
    exception_guard_sink: tuple = ('LoadHClass', 2, 0, 1)
    exception_guard_dependencies: tuple = (
        ('c758818dbfd0b146a908d43d21f6ca1706c33783', 'ecmascript/compiler/new_object_stub_builder.cpp', '05dda56de74949f07a241942be6465beaf94b52a', 'c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e'),
        ('81ca57487d04ea30cd11c271e86494a4e130f43e', 'ecmascript/compiler/new_object_stub_builder.cpp', '05dda56de74949f07a241942be6465beaf94b52a', 'c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e'),
    )
    # A JS callback can complete abruptly. The result must not be converted
    # before the runtime thread's pending-exception state is checked.
    runtime_effect_calls: tuple = (('JSFunction::Call', 1, 'JSTaggedValue'),)
    runtime_sensitive_result_methods: tuple = ('ToBoolean',)
    runtime_call_info_creators: tuple = (
        ('EcmaInterpreter::NewRuntimeCallInfo', 5, 'EcmaRuntimeCallInfo*'),
    )
    runtime_call_info_sensitive_methods: tuple = ('SetCallArg',)
    runtime_exception_guards: tuple = (
        ('RETURN_EXCEPTION_IF_ABRUPT_COMPLETION', 1,
         'HasPendingException', 'JSTaggedValue::Exception'),
        ('RETURN_VALUE_IF_ABRUPT_COMPLETION', 2,
         'HasPendingException', 'return (value)'),
        ('RETURN_REJECT_PROMISE_IF_ABRUPT', 3,
         'HasPendingException', 'return (capability)->GetPromise()'),
    )
    caller: str = CALLER
    caller_types: tuple = ('GateRef', 'GateRef', 'GateRef', 'Variable*', 'Label*', 'Label*')
    store_name: str = 'StoreTypedArrayElement'
    store_types: tuple = ('GateRef',) * 5
    target_argument: int = 1  # zero based, excluding implicit C++ this
    token_argument: int = 4
    property_store: tuple = ('FastSetPropertyByIndex', 5, 2, 4)
    creator_owner: str = NAMESPACE + '::NewObjectStubBuilder'
    creator_name: str = 'NewTypedArray'
    creator_arguments: int = 4
    creation_may_change_runtime_type: bool = True
    caller_profiles: tuple = (OWNER + '::CopyWithin', OWNER + '::Set', OWNER + '::With')
    host_constructors: tuple = (
        # The two-argument builder forms only carry the parent's current global
        # environment into another graph builder; the reviewed constructor
        # bodies do not execute runtime code.
        ('Label', (1,)), ('NewObjectStubBuilder', (1, 2)), ('BuiltinsArrayStubBuilder', (1, 2)),
        ('JSCallArgs', (0, 1)), ('CallStubBuilder', (1, 7, 8)),
    )
    # Passing GateRef by value preserves the caller's binding. It does NOT
    # establish runtime purity or revalidate a previously sampled type token.
    by_value_operations: tuple = (
        ('TaggedIsUndefinedOrNull', 1), ('TaggedIsHeapObject', 1), ('TaggedIsProtoChangeMarker', 1),
        ('IsEcmaObject', 1), ('IsFastTypeArray', 1), ('IsFastTypedArray', 1),
        ('IsCallable', 1), ('HasConstructor', 1),
        ('GetViewedArrayBuffer', 1), ('IsDetachedBuffer', 1), ('GetPrototypeFromHClass', 1),
        ('GetProtoChangeMarkerFromHClass', 1), ('GetAccessorHasChanged', 1),
        ('GetCallArg0', 1), ('GetCallArg1', 1), ('GetArrayLength', 1), ('FastGetPropertyByIndex', 4),
    )
    readonly_operations: tuple = (('HasPendingException', 1),)
    # Reviewed only for preserving a TypedArray's class/type identity. This is
    # not a general purity claim; unsupported calls still invalidate all facts.
    type_stable_operations: tuple = (
        ('TaggedIsHeapObject', 1), ('IsFastTypeArray', 1), ('IsFastTypedArray', 1),
        ('IsTypedArray', 1), ('IsJsCOWArray', 1),
        ('HasConstructor', 1),
        ('GetArrayLength', 1), ('GetCallArg0', 1), ('GetCallArg1', 1), ('GetCallArg2', 1),
        ('TaggedIsInt', 1), ('TaggedGetInt', 1), ('GetInt64OfTInt', 1),
        ('Int64GreaterThan', 2), ('Int64GreaterThanOrEqual', 2), ('BitOr', 2),
        ('CalculatePositionWithLength', 2), ('FastGetPropertyByIndex', 4),
        ('FastSetPropertyByIndex', 5), ('StoreTypedArrayElement', 5),
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
        ('GetEnvironment', 0), ('GetCurrentGlobalEnv', 0), ('Int32', 1), ('Int64', 1), ('IntPtr', 1), ('Boolean', 1),
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
                + tuple((revision, path, blob) for revision, path, blob, _ in self.receiver_guard_bindings)
        + tuple((revision, path, blob) for revision, path, blob, _ in self.size_overflow_bindings)
        + tuple((revision, path, blob) for revision, path, blob, _ in self.length_narrowing_bindings)
        + tuple((revision, path, blob) for revision, path, blob, _ in self.index_bounds_bindings)
        + tuple((revision, path, blob) for revision, path, blob, _ in self.runtime_exception_bindings)
        + tuple((revision, path, blob) for revision, path, blob, _ in self.native_exception_bindings)
                + tuple((revision, path, blob) for revision, path, blob, _ in self.api_overload_evidence)
                + tuple((self.effect_summary_revision, path, blob) for path, blob in self.source_dependencies)
                + tuple((revision, path, blob) for revision, path, blob, _ in self.exception_guard_dependencies))


def c_line_static_model():
    """Return the reviewed C1 source profile for explicit static candidates."""
    from dataclasses import replace

    base = RuntimeTypeModel()
    return replace(
        base,
        version='0.8.15',
        effect_summary_revision='c13-cross-file-contract-v1',
        target_bindings=(base.target_bindings[-1],),
        exception_guard_bindings=(base.exception_guard_bindings[-1],),
        receiver_guard_bindings=(),
        size_overflow_bindings=base.size_overflow_bindings,
        length_narrowing_bindings=base.length_narrowing_bindings,
        index_bounds_bindings=base.index_bounds_bindings,
        runtime_exception_bindings=base.runtime_exception_bindings,
        native_exception_bindings=base.native_exception_bindings,
        source_dependencies=(
            ('ecmascript/compiler/new_object_stub_builder.cpp',
             '991ac5ac034a1a027e3200787ec25c55b3f15b69'),
        ),
    )


@dataclass(frozen=True)
class AnalysisBudget:
    max_source_bytes: int = 1024 * 1024
    max_instructions: int = 16384
    max_scope_depth: int = 128
    max_states: int = 2048
    max_steps: int = 8192
    max_seconds: float = 5.0
