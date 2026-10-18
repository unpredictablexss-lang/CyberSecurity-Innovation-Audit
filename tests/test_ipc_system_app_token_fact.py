"""Caller-class facts from full-token APIs stay distinct from permissions."""
import unittest

from test_ipc_detector import context
from src.ohscanner.detectors.interface.analysis import (Interpreter, State, Value,
    _returned_caller_class, _returned_fact)
from src.ohscanner.detectors.interface.models import IpcPolicy


def _nodes(node):
    yield node
    for child in node.named_children:
        yield from _nodes(child)


def _evaluate(text, function_name, call_name):
    ctx = context(text)
    interpreter = Interpreter(ctx.units, IpcPolicy(), ctx.request)
    fn = next(fn for fn in interpreter.functions if fn.name == function_name)
    interpreter.root = fn
    call = next(node for node in _nodes(fn.body)
                if node.type == "call_expression"
                and fn.text(node.child_by_field_name("function")) == call_name)
    return interpreter.value(fn, call, State(), 0), interpreter


def _system_app_helper(token_getter, multi_outcome=False):
    text = """
bool AccessTokenManagerStub::IsSystemAppCalling() const {
    uint64_t fullTokenId = IPCSkeleton::TOKEN_GETTER();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}
""".replace("TOKEN_GETTER", token_getter)
    gate = "IsSystemAppCalling"
    if multi_outcome:
        text += """
bool AccessTokenManagerStub::IsSystemAppAllowed() const {
    if (IsSystemAppCalling()) return true;
    return false;
}
"""
        gate = "IsSystemAppAllowed"
    text += f"""
bool AccessTokenManagerStub::Gate() const {{
    return {gate}();
}}
"""
    return text, gate


class CallerClassTokenFactTests(unittest.TestCase):
    def test_full_calling_token_wrapper_returns_system_app_fact(self):
        text, gate = _system_app_helper("GetCallingFullTokenID")
        value, interpreter = _evaluate(text, "Gate", gate)
        self.assertEqual(value.predicate, ("caller_class", "system_app", True))
        self.assertFalse(any("Unresolved multi-outcome helper return: "
                             "AccessTokenManagerStub::IsSystemAppCalling" in item
                             for item in interpreter.limitations))

    def test_first_token_is_not_substituted_for_full_calling_token(self):
        text, gate = _system_app_helper("GetFirstTokenID")
        value, _ = _evaluate(text, "Gate", gate)
        self.assertNotEqual(value.predicate, ("caller_class", "system_app", True))
        self.assertEqual(value.kind, "unknown")

    def test_caller_class_survives_a_multi_outcome_boolean_wrapper(self):
        text, gate = _system_app_helper("GetCallingFullTokenID", multi_outcome=True)
        value, _ = _evaluate(text, "Gate", gate)
        self.assertEqual(value.predicate, ("caller_class", "system_app", True))

    def test_system_app_role_propagates_through_stub_helper_to_sensitive_call(self):
        body = """
bool AccessTokenManagerStub::IsSystemAppCalling() const {
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}
void AccessTokenManagerStub::GetReqPermissionsInner() {
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (GetTokenType(callingTokenID) == TOKEN_HAP && !IsSystemAppCalling()) return;
    GetReqPermissions();
}
"""
        ctx = context(body)
        interpreter = Interpreter(ctx.units, IpcPolicy(), ctx.request)
        fn = next(fn for fn in interpreter.functions if fn.name == "GetReqPermissionsInner")
        interpreter.root = fn
        interpreter.block(fn, fn.body, [State()], 0)
        self.assertNotIn("ipc.auth.caller-class",
                         {observation.rule for observation in interpreter.observations})

    def test_first_token_does_not_authorize_sensitive_caller_class(self):
        body = """
bool AccessTokenManagerStub::IsSystemAppCalling() const {
    uint64_t fullTokenId = IPCSkeleton::GetFirstTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}
void AccessTokenManagerStub::GetReqPermissionsInner() {
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (GetTokenType(callingTokenID) == TOKEN_HAP && !IsSystemAppCalling()) return;
    GetReqPermissions();
}
"""
        ctx = context(body)
        interpreter = Interpreter(ctx.units, IpcPolicy(), ctx.request)
        fn = next(fn for fn in interpreter.functions if fn.name == "GetReqPermissionsInner")
        interpreter.root = fn
        interpreter.block(fn, fn.body, [State()], 0)
        self.assertIn("ipc.auth.caller-class",
                      {observation.rule for observation in interpreter.observations})

    def test_returned_caller_class_is_not_a_permission_fact(self):
        value = Value("predicate", predicate=("caller_class", "system_app", True))
        self.assertEqual(_returned_caller_class(value), frozenset({"system_app"}))
        self.assertEqual(_returned_fact(value), frozenset())


if __name__ == "__main__":
    unittest.main()
