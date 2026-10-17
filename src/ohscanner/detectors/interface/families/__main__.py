"""Print the family table: who answers for which rule, and what each one adds.

    .venv/bin/python -m src.ohscanner.detectors.interface.families

A line working in parallel checks ownership with one command instead of grepping
the kernel, and the last two lines show what the composition actually did to the
policy -- the catalogue's defaults plus the families' additions, which is the
object the detector runs with.
"""

from dataclasses import fields

from ..models import IpcPolicy
from . import default_policy, registry

_RULE_INDENT = 4


def changed_fields(base, merged):
    """Policy fields whose value the families changed, in declaration order."""
    return [f.name for f in fields(IpcPolicy) if getattr(base, f.name) != getattr(merged, f.name)]


def main():
    families = registry()
    width = max(len(f.family_id) for f in families)
    for family in families:
        print(family.family_id.ljust(width), family.cwe, family.fixture_dir + "/", family.title)
        for rule in family.rules:
            print(" " * width, " " * _RULE_INDENT + "rule " + rule)
        for name, addition in family.policy:
            print(" " * width, " " * _RULE_INDENT + "policy " + name + " +" + str(len(addition)))
    base = IpcPolicy()
    merged = default_policy()
    print()
    print(str(len(families)) + " families, "
          + str(sum(len(family.rules) for family in families)) + " rules")
    changed = changed_fields(base, merged)
    print("effective policy = catalogue defaults + " + str(len(changed)) + " changed field(s): "
          + (", ".join(changed) if changed else "(none)"))
    for name in changed:
        print("  ", name, "=", getattr(merged, name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
