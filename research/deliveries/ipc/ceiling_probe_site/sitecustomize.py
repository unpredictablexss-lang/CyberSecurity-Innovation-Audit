"""Counterfactual: what would the silent rules emit if reachability were solved?

Read-only measurement instrument, NOT part of the detector. It answers one
question the lane's own census could not: the coverage causes have an upper
bound ("reachability + precondition"), and that bound had never been measured.

How it works -- it rewrites nothing except the entry-root set:

  _entry_roots()  is wrapped. After the detector's own roots are computed, every
                  function whose *body text* names a policy predicate this walk
                  could never reach is appended as an extra root. The rest of the
                  interpreter, including the sensitive-effect precondition, runs
                  untouched, and the report is produced by the real detector.

So the resulting per-rule candidate counts are the counts *this detector* would
produce under a permissive reachability assumption. They are an upper bound on
the payoff of the two coverage fixes, not detector behaviour and not a claim
that any such candidate is real.

Two modes, because an added root is a function that was never an entry, and how
its parameters are bound is a modelling choice rather than a fact:

  IPC_CEILING_MODE=permissive   the added function is walked as-is, so run()'s
                                env builder binds every parameter as a
                                request-derived value -- the permissive reading
                                (the IDL dispatcher handed it remote data).
  IPC_CEILING_MODE=strict       the added function is walked with params=() so
                                no name resolves to a request value: the call
                                becomes reachable and nothing else changes.

The gap between the two modes is exactly the part of the ceiling that comes
from parameter binding rather than from reachability.

A third variable splits the added roots by which side of the boundary they sit
on, because in this code base the two sides are not the same thing:

  IPC_CEILING_SIDE=all          (default) every added root
  IPC_CEILING_SIDE=services     only roots under a `services/` path
  IPC_CEILING_SIDE=interfaces   only roots under `interfaces/` or `frameworks/`

The OpenHarmony client proxies and kits are in-tree and carry the *same method
names* as the service handlers they call, and the hand-written callback stubs
are in-tree too, while a subsystem's *main* service dispatcher is generated from
IDL and is not in the source tree. So the `services/` bucket is what an IDL entry
model would actually make reachable, and the `interfaces/` bucket additionally
measures what a name-only sensitivity model would do with the client side.
Reporting them together would hide that.

    IPC_CEILING_LOG=<path> IPC_CEILING_MODE=strict IPC_CEILING_SIDE=services \
      PYTHONPATH=<this dir> <python> -m ...audit ...

A fourth variable tightens the root set to the shapes that could actually be an
IPC handler rather than any function that names a predicate:

  IPC_CEILING_OWNER=any      (default) every function kept by the side filter
  IPC_CEILING_OWNER=service  only methods of a class whose name ends in
                             `Service` or `Stub`

`service` is the reading closest to the fix that was actually proposed (make the
generated stub's handlers reachable); `any` additionally promotes free helpers
and manager classes that mention a predicate name, which no entry model would
turn into an entry.

Run from the pinned tree (cwd must be the tree the probe imports `src` from).
"""
import atexit
import dataclasses
import json
import os
import sys

_LOG = os.environ.get("IPC_CEILING_LOG")
_MODE = os.environ.get("IPC_CEILING_MODE", "permissive")
_SIDE = os.environ.get("IPC_CEILING_SIDE", "all")


def _side_of(path):
    if path.startswith("services/") or "/services/" in path:
        return "services"
    if path.startswith(("interfaces/", "frameworks/")) or "/interfaces/" in path \
            or "/frameworks/" in path:
        return "interfaces"
    return "other"


_OWNER = os.environ.get("IPC_CEILING_OWNER", "any")
_OWNER_SUFFIXES = ("Service", "Stub")

_STAT = {"mode": _MODE, "side": _SIDE, "owner": _OWNER, "functions_seen": 0,
         "added_roots": [], "already_roots": 0, "skipped_by_side": 0,
         "skipped_by_owner": 0}

sys.path.insert(0, os.getcwd())

try:
    from src.ohscanner.detectors.interface import analysis
except Exception as exc:  # pragma: no cover
    sys.stderr.write("ceiling-probe: import failed: %r\n" % (exc,))
    analysis = None

if analysis is not None and _LOG:
    _original = analysis.Interpreter._entry_roots
    _NAME_SETS = ("caller_class_sensitive_calls", "boolean_permissions",
                  "result_permissions", "caller_uid_calls", "caller_token_calls")

    def _targets(policy):
        names = set()
        for attribute in _NAME_SETS:
            names |= set(getattr(policy, attribute, ()) or ())
        return names

    def _entry_roots(self):
        roots = _original(self)
        seen = {(fn.file, fn.qualified) for fn, _grade, _note in roots}
        _STAT["already_roots"] += len(roots)
        targets = _targets(self.policy)
        if not targets:
            return roots
        for fn in self.functions:
            _STAT["functions_seen"] += 1
            if (fn.file, fn.qualified) in seen:
                continue
            body = fn.text(fn.body)
            hits = sorted(n for n in targets if n in body)
            if not hits:
                continue
            side = _side_of(fn.file)
            if _SIDE != "all" and side != _SIDE:
                _STAT["skipped_by_side"] += 1
                continue
            if _OWNER == "service" and not (fn.owner or "").endswith(_OWNER_SUFFIXES):
                # In this code base an in-tree IPC handler is a method of the
                # `*Service` class the generated stub dispatches to, or of a
                # `*Stub` class. A free function or a manager that merely names
                # a predicate is not an entry point on this transport.
                _STAT["skipped_by_owner"] += 1
                continue
            seen.add((fn.file, fn.qualified))
            _STAT["added_roots"].append({
                "file": fn.file, "function": fn.qualified, "names": hits,
                "side": side, "line": getattr(fn, "line", 0),
            })
            if _MODE == "strict":
                # params=() so no parameter name resolves to a request value; the
                # body still references the name, which then reads as an
                # unresolved value rather than an attacker-controlled one.
                # `ref_params` goes with them: this frame did not come from a
                # one-hop lookup, so there is no out-parameter to carry back.
                roots.append((dataclasses.replace(fn, params=(), parcel_params=(),
                                                  ref_params=()),
                              "ceiling-strict", "counterfactual root"))
            else:
                roots.append((fn, "ceiling-permissive", "counterfactual root"))
        return roots

    analysis.Interpreter._entry_roots = _entry_roots

    @atexit.register
    def _dump():
        with open(_LOG, "w") as handle:
            json.dump(_STAT, handle, indent=1)
