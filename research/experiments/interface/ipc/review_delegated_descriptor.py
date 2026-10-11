"""Second mechanism probe: the descriptor check done in a delegated inner call.

`ScreenSessionManagerStub::OnRemoteRequest` (line 38-44) only holds a lock and
calls `OnRemoteRequestInner`, which performs the descriptor check at line 50
before its switch. The AUTH-01 candidate is reported at line 42 -- the relay
call -- so the guard exists one call away, in the same file.
"""
import sys
import os

sys.path.insert(0, os.getcwd())

from src.ohscanner.detectors.interface import audit as audit_module
from src.ohscanner.detectors.interface.analysis import Interpreter

original_emit = Interpreter.emit


def tracing_emit(self, family, rule, fn, node, state, message, **kwargs):
    if rule == "ipc.relay.descriptor-boundary":
        print("--- AUTH-01 emit at line", node.start_point[0] + 1)
        print("    fn  :", fn.qualified)
        print("    root:", self.root.qualified)
        print("    text:", fn.text(node).replace("\n", " ")[:90])
        print("    descriptor state:", sorted(state.descriptor))
        for item in state.trace:
            print("        trace:", item)
    return original_emit(self, family, rule, fn, node, state, message, **kwargs)


Interpreter.emit = tracing_emit

repo = "/home/audit/openharmony-audit/perf-corpus/window_window_manager"
commit = "8b0d8fe1b973d865904c942c286b3d2a3b9b08e7"
report = audit_module.audit_component(
    repo, "openharmony/window_window_manager", commit,
    includes=("window_scene/screen_session_manager/src",),
    excerpt_context=0,
)
print("=== AUTH-01 candidates:",
      [c["line"] for c in report["candidates"] if c["rule_id"] == "ipc.relay.descriptor-boundary"])
