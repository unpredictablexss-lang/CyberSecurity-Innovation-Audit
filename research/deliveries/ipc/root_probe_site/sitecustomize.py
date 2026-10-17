"""One question: did the walk have entry roots at all in this component?

Scratch diagnostic, deliberately NOT the committed instrument. The committed
probe records only policy-named calls, so an empty record has two readings --
"no entry root" and "entry roots but never reached such a call". This wrapper
adds a single counter for every call `Interpreter.value` is asked about, so the
two can be told apart. It records nothing else and changes no value.

    IPC_ROOT_LOG=<path> PYTHONPATH=<this dir> <python> -m ...audit ...

Run from the pinned tree (cwd must be the tree the probe imports `src` from).
"""
import atexit
import json
import os
import sys

_LOG = os.environ.get("IPC_ROOT_LOG")
_STAT = {"value_calls": 0, "call_expressions": 0, "distinct_roots": set(),
         "distinct_root_files": set(), "distinct_functions": set()}

sys.path.insert(0, os.getcwd())

try:
    from src.ohscanner.detectors.interface import analysis
except Exception as exc:  # pragma: no cover
    sys.stderr.write("root-probe: import failed: %r\n" % (exc,))
    analysis = None

if analysis is not None and _LOG:
    _original = analysis.Interpreter.value

    def _value(self, fn, node, state, depth):
        _STAT["value_calls"] += 1
        if node is not None and node.type == "call_expression":
            _STAT["call_expressions"] += 1
        if self.root is not None:
            _STAT["distinct_roots"].add((self.root.file, self.root.qualified,
                                         self.root_grade))
            _STAT["distinct_root_files"].add(self.root.file)
        _STAT["distinct_functions"].add((fn.file, fn.qualified))
        return _original(self, fn, node, state, depth)

    analysis.Interpreter.value = _value

    @atexit.register
    def _dump():
        out = dict(_STAT)
        out["distinct_roots"] = sorted(out["distinct_roots"])
        out["distinct_root_files"] = sorted(out["distinct_root_files"])
        out["distinct_functions"] = sorted(out["distinct_functions"])
        out["n_distinct_roots"] = len(out["distinct_roots"])
        out["n_distinct_root_files"] = len(out["distinct_root_files"])
        out["n_distinct_functions"] = len(out["distinct_functions"])
        with open(_LOG, "w") as handle:
            json.dump(out, handle, indent=1)
