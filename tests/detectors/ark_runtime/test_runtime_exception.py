import unittest

from src.ohscanner.detectors.ark_runtime.model import RUNTIME_EXCEPTION_RULE_ID
from src.ohscanner.detectors.ark_runtime.runtime_exception import (
    analyze_call_info_construction_guard,
    analyze_runtime_exception_propagation,
)
from src.ohscanner.detectors.ark_runtime.unseen_model import UnseenRuntimeTypeModel
from .support import unit


MACROS = r'''#define RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread) \
    do { \
        if ((thread)->HasPendingException()) { \
            return JSTaggedValue::Exception(); \
        } \
    } while (false)
'''


def source(result_name="callbackOutcome", body=""):
    return f'''class BuiltinsTypedArray {{
JSTaggedValue Filter(EcmaRuntimeCallInfo *argv) {{
    JSThread *thread = argv->GetThread();
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, thisArg, undefined, 3);
    JSTaggedValue {result_name} = JSFunction::Call(info);
{body}
    bool accepted = {result_name}.ToBoolean();
    return accepted ? JSTaggedValue::True() : JSTaggedValue::False();
}}
}};
'''


def assigned_source(result_name="callbackOutcome", body=""):
    return f'''class BuiltinsArray {{
JSTaggedValue Some(EcmaRuntimeCallInfo *argv) {{
    JSThread *thread = argv->GetThread();
    JSTaggedValue {result_name} = JSTaggedValue::False();
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, thisArg, undefined, 3);
    {result_name} = JSFunction::Call(info);
{body}
    bool accepted = {result_name}.ToBoolean();
    return accepted ? JSTaggedValue::True() : JSTaggedValue::False();
}}
}};
'''


class RuntimeExceptionPropagationTests(unittest.TestCase):
    def analyze(self, text, macro_source=MACROS):
        return analyze_runtime_exception_propagation(
            unit(text, "ecmascript/builtins/builtins_typedarray.cpp"),
            source_units=(unit(macro_source, "ecmascript/ecma_macros.h"),))

    def test_callback_result_conversion_before_exception_guard_is_candidate(self):
        result = self.analyze(source())
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].kind, "candidate")
        self.assertEqual(result.observations[0].target_identity, "callbackOutcome")

    def test_same_thread_exception_macro_before_conversion_guards_use(self):
        result = self.analyze(source(body="    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);"))
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())

    def test_early_exit_on_exception_result_guards_conversion(self):
        body = "    if (callbackOutcome.IsException()) return JSTaggedValue::Exception();"
        result = self.analyze(source(body=body))
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())

    def test_variable_rename_does_not_change_dataflow_result(self):
        result = self.analyze(source("renamedCompletion"))
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].target_identity, "renamedCompletion")

    def test_assigned_callback_result_without_guard_is_candidate(self):
        result = self.analyze(assigned_source())
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].target_identity, "callbackOutcome")

    def test_assigned_callback_result_with_same_thread_guard_is_safe(self):
        result = self.analyze(assigned_source(
            body="    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);"))
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())

    def test_assigned_callback_wrapper_remains_partial(self):
        wrapped = assigned_source().replace(
            "callbackOutcome = JSFunction::Call(info);",
            "callbackOutcome = Normalize(JSFunction::Call(info));")
        result = self.analyze(wrapped)
        self.assertEqual(result.file_outcome, "partial")
        self.assertEqual(result.observations, ())
        self.assertIn("callback_result_wrapper_semantics_unmodeled:BuiltinsArray::Some",
                      result.limitations)

    def test_prior_use_is_not_attributed_to_later_callback_result(self):
        text = '''class BuiltinsArray {
JSTaggedValue Some(EcmaRuntimeCallInfo *argv) {
    JSThread *thread = argv->GetThread();
    JSTaggedValue callbackOutcome = JSTaggedValue::False();
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, thisArg, undefined, 3);
    bool beforeCall = callbackOutcome.ToBoolean();
    callbackOutcome = JSFunction::Call(info);
    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);
    bool afterCall = callbackOutcome.ToBoolean();
    return afterCall ? JSTaggedValue::True() : JSTaggedValue::False();
}
};
'''
        result = self.analyze(text)
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())

    def test_loop_back_edge_remains_unknown(self):
        text = '''class BuiltinsArray {
JSTaggedValue Some(EcmaRuntimeCallInfo *argv) {
    JSThread *thread = argv->GetThread();
    JSTaggedValue callbackOutcome = JSTaggedValue::False();
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, thisArg, undefined, 3);
    while (condition) {
        bool beforeCall = callbackOutcome.ToBoolean();
        callbackOutcome = JSFunction::Call(info);
    }
    return JSTaggedValue::Undefined();
}
};
'''
        result = self.analyze(text)
        self.assertEqual(result.file_outcome, "partial")
        self.assertIn("callback_result_loop_backedge_unmodeled:BuiltinsArray::Some",
                      result.limitations)

    def test_unmodeled_wrapper_stays_partial_instead_of_becoming_safe(self):
        wrapped = source().replace(
            "JSTaggedValue callbackOutcome = JSFunction::Call(info);",
            "JSTaggedValue callbackOutcome = Normalize(JSFunction::Call(info));")
        result = self.analyze(wrapped)
        self.assertEqual(result.file_outcome, "partial")
        self.assertEqual(result.observations, ())
        self.assertIn("callback_result_wrapper_semantics_unmodeled:BuiltinsTypedArray::Filter",
                      result.limitations)

    def test_source_derived_helper_effect_reaches_caller_and_guard_fixes_it(self):
        helper = unit('''namespace panda::ecmascript {
class JSStableArray {
public:
static JSTaggedValue HandleEveryOfStable(JSThread *thread, JSHandle<JSTaggedValue> callback) {
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, undefined, undefined, 1);
    JSTaggedValue callResult = JSFunction::Call(info);
    RETURN_VALUE_IF_ABRUPT_COMPLETION(thread, callResult);
    return callResult;
}
};
}
''', "ecmascript/js_stable_array.cpp")
        macros = unit(MACROS + '''
#define RETURN_VALUE_IF_ABRUPT_COMPLETION(thread, value) \\
    do { if ((thread)->HasPendingException()) { return (value); } } while (false)
''', "ecmascript/ecma_macros.h")
        caller = unit('''class BuiltinsArray {
JSTaggedValue Every(JSThread *thread, JSHandle<JSTaggedValue> callback) {
    JSTaggedValue callResult = JSStableArray::HandleEveryOfStable(thread, callback);
    bool accepted = callResult.ToBoolean();
    return accepted ? JSTaggedValue::True() : JSTaggedValue::False();
}
};
''', "ecmascript/builtins/builtins_array.cpp")
        result = analyze_runtime_exception_propagation(
            caller, source_units=(helper, macros),
            guards=UnseenRuntimeTypeModel().runtime_exception_guards)
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(len(result.observations), 1)

        safe_caller = unit(caller.text.replace(
            "    bool accepted = callResult.ToBoolean();",
            "    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);\n    bool accepted = callResult.ToBoolean();"),
            caller.path)
        safe = analyze_runtime_exception_propagation(
            safe_caller, source_units=(helper, macros),
            guards=UnseenRuntimeTypeModel().runtime_exception_guards)
        self.assertEqual(safe.file_outcome, "complete")
        self.assertEqual(safe.observations, ())

    def test_wrapper_without_selected_helper_body_is_partial(self):
        caller = unit('''class BuiltinsArray {
JSTaggedValue Every(JSThread *thread, JSHandle<JSTaggedValue> callback) {
    JSTaggedValue callResult = JSStableArray::HandleEveryOfStable(thread, callback);
    bool accepted = callResult.ToBoolean();
    return accepted ? JSTaggedValue::True() : JSTaggedValue::False();
}
};
''', "ecmascript/builtins/builtins_array.cpp")
        result = analyze_runtime_exception_propagation(
            caller, source_units=(unit(MACROS, "ecmascript/ecma_macros.h"),),
            guards=UnseenRuntimeTypeModel().runtime_exception_guards)
        self.assertEqual(result.file_outcome, "partial")
        self.assertIn("callback_result_wrapper_summary_missing:BuiltinsArray::Every",
                      result.limitations)

    def test_missing_macro_definition_keeps_candidate_and_records_limit(self):
        result = self.analyze(source(), macro_source="// no macro definition in this source set\n")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].reason,
                         "callback_completion_may_reach_result_conversion_without_dominating_exception_exit")

    def test_unrelated_translation_unit_has_no_applicable_source(self):
        result = self.analyze("void unrelated() { int x = 1; (void)x; }")
        self.assertEqual(result.file_outcome, "not_analyzed")
        self.assertEqual(result.observations, ())

    def test_rule_identifier_is_stable(self):
        self.assertEqual(RUNTIME_EXCEPTION_RULE_ID,
                         "ark.runtime.callback-exception-before-result-conversion")

    def analyze_call_info(self, body, macro_source=None):
        source_text = f'''void Invoke(JSThread *thread, JSHandle<JSTaggedValue> next,
            JSHandle<JSTaggedValue> iter, JSHandle<JSTaggedValue> undefined,
            JSHandle<JSTaggedValue> value) {{
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, next, iter, undefined, 1);
{body}
    info->SetCallArg(value.GetTaggedValue());
}}
'''
        if macro_source is None:
            macro_source = MACROS + '''
#define RETURN_VALUE_IF_ABRUPT_COMPLETION(thread, value) \\
    do { if ((thread)->HasPendingException()) { return (value); } } while (false)
'''
        return analyze_call_info_construction_guard(
            unit(source_text, "ecmascript/js_iterator.cpp"),
            source_units=(unit(macro_source, "ecmascript/ecma_macros.h"),))

    def test_call_info_pointer_use_without_exception_guard_is_candidate(self):
        result = self.analyze_call_info("")
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].token_origin,
                         "EcmaInterpreter::NewRuntimeCallInfo")

    def test_call_info_pointer_use_with_value_macro_is_guarded(self):
        result = self.analyze_call_info(
            "    RETURN_VALUE_IF_ABRUPT_COMPLETION(thread, undefined);")
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())

    def test_call_info_pointer_use_with_pending_exception_early_exit_is_guarded(self):
        result = self.analyze_call_info(
            "    if (thread->HasPendingException()) { return; }")
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())

    def test_compound_condition_does_not_count_as_pending_exception_guard(self):
        result = self.analyze_call_info(
            "    if (thread->HasPendingException() && condition) { return; }")
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(len(result.observations), 1)

    def analyze_nested_call_info(self, guard):
        source_text = f'''void Invoke(JSThread *thread, JSHandle<JSTaggedValue> next,
            JSHandle<JSTaggedValue> iter, JSHandle<JSTaggedValue> undefined,
            JSHandle<JSTaggedValue> value, size_t length) {{
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, next, iter, undefined, 1);
{guard}
    for (size_t i = 0; i < length; ++i) {{
        info->SetCallArg(value.GetTaggedValue());
    }}
}}
'''
        macro_source = MACROS + '''
#define RETURN_VALUE_IF_ABRUPT_COMPLETION(thread, value) \\
    do { if ((thread)->HasPendingException()) { return (value); } } while (false)
'''
        return analyze_call_info_construction_guard(
            unit(source_text, "ecmascript/stubs/runtime_stubs-inl.h"),
            source_units=(unit(macro_source, "ecmascript/ecma_macros.h"),))

    def test_guard_in_parent_compound_dominates_loop_pointer_use(self):
        result = self.analyze_nested_call_info(
            "    RETURN_VALUE_IF_ABRUPT_COMPLETION(thread, undefined);")
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())

    def test_nested_pointer_use_without_dominating_guard_is_candidate(self):
        result = self.analyze_nested_call_info("")
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(len(result.observations), 1)

    def test_return_reject_macro_is_guarded_only_by_its_pending_branch(self):
        macro = MACROS + r'''
#define RETURN_REJECT_PROMISE_IF_ABRUPT(thread, value, capability) \\
    do { \\
        if ((value).GetTaggedValue().IsCompletionRecord()) { \\
            return (capability)->GetPromise(); \\
        } \\
        if ((thread)->HasPendingException()) { \\
            (thread)->ClearException(); \\
            return (capability)->GetPromise(); \\
        } \\
    } while (false)
'''
        result = self.analyze_call_info(
            "    RETURN_REJECT_PROMISE_IF_ABRUPT(thread, next, capability);", macro)
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())

    def test_return_reject_macro_with_unrelated_return_is_not_guarded(self):
        macro = MACROS + r'''
#define RETURN_REJECT_PROMISE_IF_ABRUPT(thread, value, capability) \\
    do { \\
        if ((thread)->HasPendingException()) { (thread)->ClearException(); } \\
        return (capability)->GetPromise(); \\
    } while (false)
'''
        result = self.analyze_call_info(
            "    RETURN_REJECT_PROMISE_IF_ABRUPT(thread, next, capability);", macro)
        self.assertEqual(result.file_outcome, "partial")
        self.assertEqual(result.observations, ())
        self.assertTrue(any("call_info_exception_guard_contract_unverified" in item
                            for item in result.limitations))


if __name__ == "__main__":
    unittest.main()
