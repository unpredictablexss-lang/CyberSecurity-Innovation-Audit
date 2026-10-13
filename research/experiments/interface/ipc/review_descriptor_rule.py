"""Control experiment for the AUTH-01 descriptor rule.

Hypothesis: `analysis.py:582-585` accepts `X::GetDescriptor()` only when the
qualifier X equals the enclosing function's owner class. Real OpenHarmony stubs
live in `FooStub` and compare against `IFoo::GetDescriptor()`, so the qualifier
never matches and the descriptor guard is recorded as UNKNOWN.

If the hypothesis is right, bypassing that qualifier test -- and nothing else --
should remove the AUTH-01 candidates from a file that plainly checks the token.
"""
import sys
import os

sys.path.insert(0, os.getcwd())

from src.ohscanner.detectors.interface import audit as audit_module
from src.ohscanner.detectors.interface.analysis import Interpreter, Value, terminal

original_value = Interpreter.value


def patched_value(self, fn, node, state, depth):
    if node is not None and node.type == "call_expression":
        callee = fn.text(node.child_by_field_name("function"))
        if terminal(callee) == "GetDescriptor":
            return Value("descriptor_expected", fn.owner)
    return original_value(self, fn, node, state, depth)


def run(label, patched):
    Interpreter.value = patched_value if patched else original_value
    repo = "/home/audit/openharmony-audit/perf-corpus/security_access_token"
    commit = "17d88bfb36bea6c9370ba919ac41a22d16dd66b3"
    report = audit_module.audit_component(
        repo, "openharmony/security_access_token", commit,
        includes=("interfaces/innerkits/accesstoken/src",),
        excerpt_context=0,
    )
    auth01 = [c for c in report["candidates"] if c["rule_id"] == "ipc.relay.descriptor-boundary"]
    print("%-30s candidates=%d  AUTH-01=%d" % (label, len(report["candidates"]), len(auth01)))
    for c in auth01[:4]:
        print("      ", c["file"], c["line"])


run("as shipped", False)
run("GetDescriptor qualifier relaxed", True)
