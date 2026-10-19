"""Remove the zero-iteration escape from `do { } while (0)` on a copy of analysis.py.

`analysis.py:1571-1578` forks every loop into two paths: a zero-iteration escape
with no guard applied, then the body. For `do_statement` the first path does not
exist in C semantics -- a `do` body executes at least once. That matters here
because the OHOS guard idiom wraps the check in exactly that construct
(`CHECK_RETURN_RET_ELOG(cond, ret, fmt, ...)` is
`do { if (COND) { return ret; } } while (0)`), so the only path that survives to
the sensitive call after the macro is the one that skipped the guard.

The edit is one condition on the fork; nothing else about the walk changes.

Usage: cf_patch_dw.py <analysis.py> <dw|dw+pred>
"""
import sys

path, mode = sys.argv[1], sys.argv[2]
if mode not in ("dw", "dw+pred", "dw+pred2"):
    raise SystemExit("mode must be dw, dw+pred or dw+pred2")
text = open(path, encoding="utf-8").read()
edits = []

old = '''            result=[];body=node.child_by_field_name("body")
            for s in active:
                result.append(s.fork())
'''
new = '''            result=[];body=node.child_by_field_name("body")
            for s in active:
                # CF-DOWHILE: a `do { ... } while (0)` body executes at least
                # once, so the zero-iteration escape this model forks for every
                # loop is not a path in C semantics. The idiom is the guard
                # wrapper OHOS uses around exactly these checks, so the escape is
                # what leaves the guarded operation after the macro reachable
                # with no guard credited.
                if kind != "do_statement":
                    result.append(s.fork())
'''
edits.append(("dowhile", old, new))

if mode in ("dw+pred", "dw+pred2"):
    assumed = mode == "dw+pred2"
    old = '''_RELAY_LEAVES = ("return_statement", "throw_statement")
'''
    new = '''_RELAY_LEAVES = ("return_statement", "throw_statement")

# CF-PREDICATE tier 1, same rule as cf_patch_pred.py: a reviewed identity-derived
# predicate on the caller's own token id yields caller_class=system_app.
_CF_CALLER_TOKEN_PREDICATES = frozenset({
    "IsSystemApp", "IsSystemAppByFullTokenID", "IsSystemAppByTokenID",
    "IsSystemAppByTokenId",
})
''' + ('''# Tier 2: the added half is an assumption about a name whose body is not read.
_CF_ASSUMED_SYSTEM_APP_PREDICATES = frozenset({"CheckSystemApp", "CheckSystemAppByTokenID"})
''' if assumed else '')
    edits.append(("pred-table", old, new))

    old = '''                    for role_name, role_kind, role_label in self.policy.caller_role_guards:
                        if role_name == name:
                            return Value("predicate", predicate=(role_kind, role_label, True))
'''
    new = '''                    for role_name, role_kind, role_label in self.policy.caller_role_guards:
                        if role_name == name:
                            return Value("predicate", predicate=(role_kind, role_label, True))
                    if (name in _CF_CALLER_TOKEN_PREDICATES and args
                            and args[0].kind == "caller" and args[0].subject == "token"):
                        return Value("predicate", predicate=("caller_class", "system_app", True))
''' + ('''                    if name in _CF_ASSUMED_SYSTEM_APP_PREDICATES:
                        return Value("predicate", predicate=("caller_class", "system_app", True))
''' if assumed else '')
    edits.append(("predicate", old, new))

for label, old, new in edits:
    if text.count(old) != 1:
        raise SystemExit("edit %s: anchor matched %d times" % (label, text.count(old)))
    text = text.replace(old, new)

open(path, "w", encoding="utf-8").write(text)
print("applied %d edits (%s)" % (len(edits), mode))
