"""Source-derived caller-class facts must retain their identity domain."""
import unittest

from test_ipc_detector import context
from src.ohscanner.detectors.interface.analysis import (
    Interpreter, State, Value, _returned_caller_class,
)
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


def _token_gate_text(token_getter, *, multi_outcome=False):
    wrapper = """
bool AccessTokenManagerStub::IsSystemAppCalling() const {
    uint64_t fullTokenId = IPCSkeleton::TOKEN_GETTER();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}
""".replace("TOKEN_GETTER", token_getter)
    if multi_outcome:
        wrapper += """
bool AccessTokenManagerStub::IsSystemAppAllowed() const {
    if (IsSystemAppCalling()) return true;
    return false;
}
"""
        gate_call = "IsSystemAppAllowed"
    else:
        gate_call = "IsSystemAppCalling"
    wrapper += f"""
bool AccessTokenManagerStub::Gate() {{
    return {gate_call}();
}}
"""
    return wrapper, gate_call


class CallerClassTokenFactTests(unittest.TestCase):
    def test_full_calling_token_wrapper_returns_system_app_fact(self):
        text, call = _token_gate_text("GetCallingFullTokenID")
        value, interpreter = _evaluate(text, "Gate", call)
        self.assertEqual(value.predicate, ("caller_class", "system_app", True))
        self.assertFalse(any("Unresolved multi-outcome helper return: "
                             "AccessTokenManagerStub::IsSystemAppCalling" in item
                             for item in interpreter.limitations))

    def test_first_token_is_not_substituted_for_full_calling_token(self):
        text, call = _token_gate_text("GetFirstTokenID")
        value, interpreter = _evaluate(text, "Gate", call)
        self.assertNotEqual(value.predicate, ("caller_class", "system_app", True))
        self.assertEqual(value.kind, "unknown")

    def test_caller_class_survives_a_multi_outcome_boolean_wrapper(self):
        text, call = _token_gate_text("GetCallingFullTokenID", multi_outcome=True)
        value, _ = _evaluate(text, "Gate", call)
        self.assertEqual(value.predicate, ("caller_class", "system_app", True))

    def test_returned_caller_class_stays_separate_from_permission_facts(self):
        self.assertEqual(
            _returned_caller_class(Value("predicate",
                predicate=("caller_class", "system_app", True))),
            frozenset({"system_app"}),
        )
        self.assertEqual(
            _returned_caller_class(Value("predicate",
                predicate=("auth", "ohos.permission.TEST", True))),
            frozenset(),
        )
        self.assertEqual(
            _returned_caller_class(Value("predicate",
                predicate=("caller_class", "system_app", False))),
            frozenset(),
        )


if __name__ == "__main__":
    unittest.main()
