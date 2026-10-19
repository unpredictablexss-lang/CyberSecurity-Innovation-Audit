"""One module per vulnerability family: what each line owns, and how it composes.

The interface detector is worked by six lines in parallel, one per family
(AUTH-01..04, DATA-01, CAP-01). Before this package existed, doing anything
inside a family meant editing `models.py` and `detector.py` -- the two files
every line touches -- so six lines editing one file is six conflicts a day. A
family now declares what it owns in its own module:

    FAMILY   the family id findings carry ("AUTH-02")
    TITLE    the trust boundary in one line
    CWE      the mechanism CWE this family's findings report
    RULES    the rule ids this family emits
    POLICY   optional: IpcPolicy field -> additions, for policy facts the
             family owns (a reviewed caller role, a sensitive call name, ...)

Nothing is registered by hand: every module in this package except the private
ones is imported and its declarations checked. A module that fails to import, or
that declares something inconsistent, raises here -- at import of the detector --
rather than silently leaving a family out of the run.

The checks are the framework's reason to exist, so they are strict:

* `RULES` across all families must be exactly the keys of
  `models.IMPACT_BY_RULE`: a rule with no family would never be assigned an
  owner and a rule in two families would let a line change another line's
  findings. The consequence catalogue stays the single source of truth for
  which rules exist; the family says who answers for them.
* A family id, its CWE shape and its fixture directory name
  (`Family.fixture_dir`) are validated here, so a family's tests have one
  place to look.
* Two families may not add the same value to the same policy field (the same
  caller role, the same sensitive call). That is the one cross-line conflict
  the compiler cannot see, and it is a review decision, not a merge order.
* `merge_policy` is idempotent: a policy that already carries a family's
  additions is unchanged by merging again. Any policy entering the interface
  kernel goes through it, so a hand-built `IpcPolicy` in a harness or a test
  sees the same rules the detector does -- otherwise a fixture could look clean
  under the detector and dirty in a harness, or the reverse.
"""

from dataclasses import dataclass, fields, replace
from functools import lru_cache
from typing import Mapping, Optional, Tuple
import importlib
import pkgutil
import re

from ..models import IMPACT_BY_RULE, IpcPolicy

_CWE_PATTERN = re.compile(r"^CWE-\d+$")
_POLICY_FIELDS = frozenset(f.name for f in fields(IpcPolicy))


@dataclass(frozen=True)
class Family:
    """What one family owns: its id, its rules, and its policy additions."""

    family_id: str
    title: str
    cwe: str
    rules: Tuple[str, ...]
    policy: Tuple[Tuple[str, tuple], ...]
    module: str

    @property
    def fixture_dir(self) -> str:
        """Fixture directory name for this family ("AUTH-01" -> "auth01").

        A convention rather than a lookup: a family's fixtures live in
        `tests/fixtures/ipc/<fixture_dir>/`, and the matrix test derives the
        expected family id from the directory name with the same rule.
        """
        return self.family_id.replace("-", "").lower()


def _declared(module):
    missing = [name for name in ("FAMILY", "TITLE", "CWE", "RULES")
               if not hasattr(module, name)]
    if missing:
        raise ValueError("family module " + module.__name__
                         + " does not declare " + ", ".join(sorted(missing)))
    policy = getattr(module, "POLICY", {})
    if not isinstance(policy, Mapping):
        raise ValueError("family module " + module.__name__
                         + " POLICY must be a mapping of IpcPolicy field -> additions")
    for name, addition in policy.items():
        if name not in _POLICY_FIELDS:
            raise ValueError("family " + module.FAMILY + " adds unknown policy field "
                             + repr(name))
        if not isinstance(getattr(IpcPolicy(), name), (tuple, frozenset)):
            raise ValueError("family " + module.FAMILY + " may not add to scalar policy field "
                             + name + "; a scalar is a value the catalogue owns")
        if isinstance(addition, (str, bytes)) or not isinstance(addition, (tuple, frozenset)):
            raise ValueError("family " + module.FAMILY + " must add a tuple or frozenset to "
                             + name + ", not " + type(addition).__name__)
    return Family(
        family_id=module.FAMILY,
        title=module.TITLE,
        cwe=module.CWE,
        rules=tuple(module.RULES),
        # Sorted so two imports of the same sources compose in one order; the
        # policy a finding cites must not depend on the filesystem's ordering.
        policy=tuple((name, tuple(policy[name])) for name in sorted(policy)),
        module=module.__name__,
    )


def _family_modules():
    found = []
    for info in pkgutil.iter_modules(__path__):
        if info.ispkg or info.name.startswith("_"):
            continue
        found.append(importlib.import_module(__name__ + "." + info.name))
    if not found:
        raise ValueError("no family modules found under " + __name__)
    return sorted(found, key=lambda module: module.__name__)


def _checked(families):
    by_id = {}
    rule_owner = {}
    for family in families:
        if family.family_id in by_id:
            raise ValueError("family id " + family.family_id + " is declared twice ("
                             + by_id[family.family_id].module + ", " + family.module + ")")
        by_id[family.family_id] = family
        if not _CWE_PATTERN.match(family.cwe):
            raise ValueError("family " + family.family_id + " has a malformed CWE "
                             + repr(family.cwe))
        if not family.rules:
            raise ValueError("family " + family.family_id + " declares no rules")
        for rule in family.rules:
            if rule not in IMPACT_BY_RULE:
                raise ValueError("family " + family.family_id + " declares rule " + repr(rule)
                                 + ", which the consequence catalogue does not list")
            if rule in rule_owner:
                raise ValueError("rule " + repr(rule) + " is claimed by both "
                                 + rule_owner[rule] + " and " + family.family_id)
            rule_owner[rule] = family.family_id
    unowned = sorted(set(IMPACT_BY_RULE) - set(rule_owner))
    if unowned:
        raise ValueError("no family claims catalogue rule(s) " + ", ".join(unowned)
                         + "; the families must partition IMPACT_BY_RULE")
    # Called for its check: a value two families both claim raises here.
    _policy_claims(families)
    return tuple(sorted(families, key=lambda family: family.family_id))


def _policy_claims(families):
    """Every `(field, value) -> claiming family`, with cross-family conflicts raised."""
    claims = []
    for family in families:
        for name, addition in family.policy:
            for element in addition:
                for other, other_family in claims:
                    if other[0] == name and other[1] == element:
                        raise ValueError("policy field " + name + " gets the same value from "
                                         + other_family + " and " + family.family_id
                                         + "; that is a review decision, not a merge order")
                claims.append(((name, element), family.family_id))
    return {claim: family for claim, family in claims}


@lru_cache(maxsize=1)
def registry() -> Tuple[Family, ...]:
    """Every family, validated, sorted by id. Raises if the set is inconsistent."""
    return _checked([_declared(module) for module in _family_modules()])


@lru_cache(maxsize=1)
def _by_id():
    return {family.family_id: family for family in registry()}


def family_of_rule(rule: str) -> Family:
    """The family that answers for a rule. Raises KeyError for an unclaimed rule."""
    for family in registry():
        if rule in family.rules:
            return family
    raise KeyError(rule)


def cwes() -> dict:
    """`{family_id: mechanism CWE}`, which is what a finding reports."""
    return {family.family_id: family.cwe for family in registry()}


def merge_policy(base: Optional[IpcPolicy] = None) -> IpcPolicy:
    """`base` with every family's policy additions applied.

    Idempotent, and that matters: any policy entering the kernel is merged, and
    the detector passes an already-merged policy down, so merging twice has to be
    the same policy. A field a family adds to must be a tuple or a frozenset --
    a scalar is a value the base owns, not a set a family extends.
    """
    base = IpcPolicy() if base is None else base
    updates = {}
    for family in registry():
        for name, addition in family.policy:
            current = updates.get(name, getattr(base, name))
            if isinstance(current, frozenset):
                updates[name] = current | frozenset(addition)
            elif isinstance(current, tuple):
                updates[name] = tuple(dict.fromkeys(current + tuple(addition)))
            else:
                raise ValueError("family " + family.family_id + " may not add to policy field "
                                 + name + " (" + type(current).__name__ + ")")
    return replace(base, **updates) if updates else base


@lru_cache(maxsize=1)
def default_policy() -> IpcPolicy:
    """The reviewed policy: the catalogue's defaults plus every family's facts."""
    return merge_policy(IpcPolicy())


# Validate at import rather than at the first scan. A family that claims a rule
# the catalogue does not list, or a value another family also claims, is a defect
# in this package: it must stop the detector from loading, not quietly leave one
# family's rules out of every run with nothing in the result saying so.
registry()
