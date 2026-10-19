"""Model one identity-derived predicate on a copy of analysis.py.

What is being modelled: the family of predicates whose body is a single bit test
on the *caller's own* token -- `TokenIDAttributes::IsSystemApp(uint64_t id)` is
`(id & SYSTEM_APP_MASK) == SYSTEM_APP_MASK` with MASK folding to bit 32, and
`TokenIdKit::IsSystemAppByFullTokenID` is the same test behind another name.
The engine never reads those bodies (one is cross-TU, the other is a constexpr
fold), so a handler that calls one gets no `caller_class` fact, and the
caller-class rule -- which fires on the *absence* of that fact -- reports a
boundary that the source actually has.

Tier 1 (derived) is the narrow rule: the callee is not defined in this file, its
name is one of the reviewed bit-test names, and its argument is the caller's own
token id -- `Value(kind="caller", subject="token")`, which the engine already
derives from `GetCallingTokenID`/`GetCallingFullTokenID`
(analysis.py:1244-1245). Nothing is assumed about a body: the fact is derived
from the *argument's* provenance, which is why a call on a parcel-read id or on
the process's own token is not credited.

Tier 2 (assumed) additionally credits two reviewed names whose bodies are in
another translation unit and were never read (`CheckSystemApp` in
camera_util.cpp). It is built as a separate copy so the two effects stay
separable and the weaker one is never reported as the stronger.

Usage: cf_patch_pred.py <analysis.py> <1|2>
"""
import sys

path, tier = sys.argv[1], sys.argv[2]
if tier not in ("1", "2"):
    raise SystemExit("tier must be 1 or 2")
text = open(path, encoding="utf-8").read()
edits = []

# ---- module-level tables ----------------------------------------------------
old = '''_RELAY_LEAVES = ("return_statement", "throw_statement")
'''
new = '''_RELAY_LEAVES = ("return_statement", "throw_statement")

# CF-PREDICATE: reviewed identity-derived predicates. Each is a single bit test
# on the caller's own full token id -- `TokenIDAttributes::IsSystemApp` is
# `(id & SYSTEM_APP_MASK) == SYSTEM_APP_MASK`, with MASK folding across two
# constexprs to bit 32. The engine reads no part of that body, so a handler that
# calls one of these carried no `caller_class` fact and the caller-class rule
# reported the boundary it could not see.
_CF_TIER = ''' + tier + '''
# Derived: credited only when the argument is the caller's own token id, which
# the engine already tracks (analysis.py:1244), so this says nothing about a
# body it did not read -- it reads the argument.
_CF_CALLER_TOKEN_PREDICATES = frozenset({
    "IsSystemApp", "IsSystemAppByFullTokenID", "IsSystemAppByTokenID",
    "IsSystemAppByTokenId",
})
# Assumed (tier 2 only): reviewed names whose bodies live in another translation
# unit and are not read here. Kept separate on purpose -- crediting these is an
# assumption about the name, not a derivation from source.
_CF_ASSUMED_SYSTEM_APP_PREDICATES = frozenset({
    "CheckSystemApp", "CheckSystemAppByTokenID",
})
'''
edits.append(("tables", old, new))

# ---- the predicate itself ---------------------------------------------------
old = '''                    for role_name, role_kind, role_label in self.policy.caller_role_guards:
                        if role_name == name:
                            return Value("predicate", predicate=(role_kind, role_label, True))
'''
new = '''                    for role_name, role_kind, role_label in self.policy.caller_role_guards:
                        if role_name == name:
                            return Value("predicate", predicate=(role_kind, role_label, True))
                    # CF-PREDICATE tier 1: a bit test on the caller's own token.
                    # The argument's provenance is the whole warrant: a value the
                    # engine derives from GetCallingTokenID/GetCallingFullTokenID
                    # is the caller's token, and only that value makes this an
                    # identity-derived answer. A parcel-read id or the process's
                    # own token (kind "self") is not credited.
                    if (name in _CF_CALLER_TOKEN_PREDICATES and args
                            and args[0].kind == "caller" and args[0].subject == "token"):
                        return Value("predicate", predicate=("caller_class", "system_app", True))
                    if _CF_TIER >= 2 and name in _CF_ASSUMED_SYSTEM_APP_PREDICATES:
                        return Value("predicate", predicate=("caller_class", "system_app", True))
'''
edits.append(("predicate", old, new))

for label, old, new in edits:
    if text.count(old) != 1:
        raise SystemExit("edit %s: anchor matched %d times" % (label, text.count(old)))
    text = text.replace(old, new)

open(path, "w", encoding="utf-8").write(text)
print("applied %d edits (tier %s)" % (len(edits), tier))
