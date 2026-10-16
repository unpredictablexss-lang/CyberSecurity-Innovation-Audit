"""Record what identity class the analysis itself attributes to each permission predicate.

This is a measuring instrument, not a detector change. Put this directory on
PYTHONPATH and run the driver as usual:

    IPC_PROBE_LOG=<out>/<component>/predicates.jsonl \
    PYTHONPATH=<this directory> \
    <python> -m src.ohscanner.detectors.interface.audit --repo-dir ... --out-dir ...

Nothing is re-evaluated. The wrapper calls the original `Interpreter.value`, hands
back its return value untouched, and afterwards records two things the analysis has
already computed:

  subject  the value `analysis.py:1378` built -- the first argument whose kind is
           caller/self/request (`:1364`), or the name-specific default at `:1365`
  added    how many entries the call appended to `state.identity_issues`, which is
           what `analysis.py:1018-1021` later turns into an AUTH-03 candidate

One deviation from a bare `PYTHONPATH` run is necessary and is not hidden: at
sitecustomize time the working directory is not on `sys.path` yet, so the pinned
tree the driver is invoked from cannot be imported. The directory is added here,
which is the same module `-m` reaches a moment later. If the import still fails the
exception is written to stderr, never swallowed; a record that cannot be built is
recorded as an error rather than dropped.

Read-only with respect to the target: no file is opened for writing except the log.
"""
import atexit
import json
import os
import sys

_LOG = os.environ.get("IPC_PROBE_LOG")
_RECORDS = []

sys.path.insert(0, os.getcwd())

try:
    from src.ohscanner.detectors.interface import analysis
except Exception as exc:  # pragma: no cover - reported, not swallowed
    sys.stderr.write("ipc-probe: import failed: %r\n" % (exc,))
    analysis = None

if analysis is not None and _LOG:
    _original = analysis.Interpreter.value
    _terminal = analysis.terminal

    def _value(self, fn, node, state, depth):
        before = len(state.identity_issues)
        result = _original(self, fn, node, state, depth)
        try:
            if node is not None and node.type == "call_expression":
                function = node.child_by_field_name("function")
                callee = fn.text(function) if function is not None else ""
                name = _terminal(callee)
                if name in (self.policy.boolean_permissions
                            | self.policy.result_permissions):
                    _RECORDS.append({
                        "name": name,
                        "file": fn.file,
                        "function": fn.qualified,
                        "root": self.root.qualified if self.root else "",
                        "root_file": self.root.file if self.root else "",
                        "grade": self.root_grade,
                        "line": node.start_point[0] + 1,
                        "subject": getattr(result, "subject", None),
                        "kind": getattr(result, "kind", None),
                        "permission": getattr(result, "permission", None),
                        "reset": state.reset,
                        "identity_issues_added": len(state.identity_issues) - before,
                        "identity_issues_total": len(state.identity_issues),
                        "call": " ".join(callee.split())[:80],
                    })
        except Exception as exc:  # a probe must never change the measurement
            _RECORDS.append({"error": repr(exc)})
        return result

    analysis.Interpreter.value = _value

    @atexit.register
    def _dump():
        with open(_LOG, "w") as handle:
            for record in _RECORDS:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
