"""Per-family depth controls: every catalogued rule now has a positive control.

The shared manifest asserts, per fixture, that a named rule is present or that no
candidate at all is raised. It does not assert *which* candidates a positive
raises, and it cannot state that a positive and its fixed control differ in one
line. Those are the assertions here, for the three reviewed rules the shared
manifest never exercised -- `ipc.auth.caller-class`, `ipc.auth.identity-domain`
and `ipc.parcel.position-underflow` -- together with the safe control AUTH-01 was
missing.

The fixtures live under `tests/fixtures/ipc/<family>/` with their own manifests,
so `test_ipc_family_matrix.FamilyFixtureMatrixTests` covers them too (directory
name fixes the family, a null expectation means no candidates, the run must
complete). What is added here is the per-rule exactness and the pair checks.

Whether a rule can be *triggered by a fixture* is not a claim that it fires on
real code, and a passing fixture is not product evidence. These are synthetic
design controls bound to the pinned policy in `models.py`.
"""
import difflib
import hashlib
import json
from pathlib import Path
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface import families
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import IMPACT_BY_RULE

BASE = Path(__file__).parent / 'fixtures/ipc'

# The reviewed rule each fixture of this unit was written against, and the exact
# candidate set the pinned policy produces for it. Written out rather than read
# from a run: a rule that starts or stops firing somewhere else has to change
# this table with a reviewer looking at both.
REVIEWED_POSITIVES = {
    'ipc.auth.caller-class': ('auth03', 'caller_class_positive.cpp'),
    'ipc.auth.identity-domain': ('auth03', 'identity_domain_positive.cpp'),
    'ipc.parcel.position-underflow': ('data01', 'position_underflow_positive.cpp'),
}
# A minimal pair: (positive, control) inside one family directory, and how many
# source lines the two files may differ by. One line means the suppressed
# candidates are attributable to that line and not to a widened guard set.
REVIEWED_PAIRS = (
    ('auth03', 'caller_class_positive.cpp', 'caller_class_fixed.cpp', 1),
    ('auth03', 'identity_domain_positive.cpp', 'identity_domain_fixed.cpp', 1),
    ('data01', 'position_underflow_positive.cpp', 'position_underflow_fixed.cpp', 1),
)


def context(text, path='sample.cpp'):
    index = parse_source(text, language='cpp')
    unit = SourceUnit(path, 'cpp', text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status)
    request = ScanRequest('ipc-test', 'fixture/ipc', 'synthetic-ipc-v1',
                          snapshot_digest((unit,)), 'current-component:fixture/ipc')
    return ScanContext(request, (unit,), {'ast': {path: index.to_dict()}})


def detect(family_dir, filename):
    text = (BASE / family_dir / filename).read_text()
    ctx = context(text, filename)
    run = IpcInterfaceDetector().detect(ctx, ctx.units)
    return run.status, sorted({f.rule_id for f in run.findings})


def body(path):
    """The fixture's program: the stub naming and the include are scaffolding."""
    lines = path.read_text().splitlines()
    return [line for line in lines if not line.startswith('#')]


def changed_lines(family_dir, left, right):
    """Program lines the two fixtures differ by, as difflib sees them.

    The `#define Stub ...` line names the fixture and necessarily differs, so it
    is not counted: the claim being checked is that the two programs differ in one
    line, not that two files of different names differ in two.
    """
    a = body(BASE / family_dir / left)
    b = body(BASE / family_dir / right)
    total = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b).get_opcodes():
        if tag != 'equal':
            total += max(i2 - i1, j2 - j1)
    return total


def family_manifests():
    """The manifests this unit owns, one directory per family."""
    for declared in families.registry():
        path = BASE / declared.fixture_dir / 'manifest.json'
        if path.exists():
            yield path


def all_manifests():
    """Every fixture manifest under tests/fixtures/ipc, shared one included."""
    yield BASE / 'manifest.json'
    yield from family_manifests()


class RuleControlCoverageTests(unittest.TestCase):
    """The invariant this unit exists to establish, checked against the manifests."""

    def rows(self):
        for path in all_manifests():
            for item in json.loads(path.read_text()):
                yield path, item

    def test_every_catalogued_rule_has_a_positive_control(self):
        """No rule may ship with only negative controls: a rule that has never
        been made to fire is indistinguishable from a rule that cannot fire."""
        positives = {item['expected_rule'] for _, item in self.rows()
                     if item['variant'] == 'positive'}
        self.assertEqual(positives, set(IMPACT_BY_RULE),
                         'rules without a positive control: '
                         + repr(sorted(set(IMPACT_BY_RULE) - positives)))

    def test_every_family_has_positive_fixed_and_safe_controls(self):
        """The three controls AGENTS.md requires, per family rather than in total,
        so a family cannot borrow another family's negative evidence."""
        by_family = {}
        for _, item in self.rows():
            by_family.setdefault(item['family'], set()).add(item['variant'])
        for declared in families.registry():
            with self.subTest(family=declared.family_id):
                self.assertEqual(by_family.get(declared.family_id, set()),
                                 {'positive', 'fixed', 'safe'})

    def test_a_positive_control_belongs_to_the_family_that_owns_its_rule(self):
        for path, item in self.rows():
            if item['variant'] != 'positive':
                continue
            with self.subTest(sample=item['sample_id']):
                self.assertEqual(item['family'],
                                 families.family_of_rule(item['expected_rule']).family_id)

    def test_a_family_directory_manifest_states_its_own_family(self):
        for declared in families.registry():
            path = BASE / declared.fixture_dir / 'manifest.json'
            if not path.exists():
                continue
            for item in json.loads(path.read_text()):
                with self.subTest(sample=item['sample_id']):
                    self.assertEqual(item['family'], declared.family_id)


class NegativeControlIsExactTests(unittest.TestCase):
    """A `fixed` or `safe` row means no candidate at all, not "not this rule"."""

    def detect_at(self, path, filename):
        text = (path.parent / filename).read_text()
        ctx = context(text, filename)
        run = IpcInterfaceDetector().detect(ctx, ctx.units)
        return run.status, sorted({f.rule_id for f in run.findings})

    def test_a_fixed_or_safe_fixture_raises_nothing(self):
        # Family directories only. The shared manifest's negative rows are
        # test_ipc_family_matrix's business, and a red test here for a fixture this
        # unit does not own would say nothing about the controls added here.
        for path in family_manifests():
            for item in json.loads(path.read_text()):
                if item['variant'] == 'positive':
                    continue
                with self.subTest(sample=item['sample_id']):
                    status, rules = self.detect_at(path, item['file'])
                    self.assertEqual(status, 'completed')
                    self.assertEqual(rules, [])


class ManifestContractTests(unittest.TestCase):
    """`variant` says what the row asserts, and nothing else in the suite reads it.

    A positive control asserts a candidate is raised; a fixed or safe one asserts
    none is. Those are opposite claims about the same field, so a row whose
    `expected_rule` disagrees with its `variant` is stating one thing and being
    checked for another -- and since the matrix test branches on `expected_rule`
    alone, a mislabelled row silently converts a negative control into a positive
    one with no test noticing.
    """

    def rows(self):
        for path in all_manifests():
            for item in json.loads(path.read_text()):
                yield path, item

    def test_variant_agrees_with_the_expectation(self):
        for path, item in self.rows():
            if item['variant'] == 'positive':
                with self.subTest(sample=item['sample_id']):
                    self.assertIsNotNone(item['expected_rule'],
                                         'a positive control must name the rule it raises')
            else:
                with self.subTest(sample=item['sample_id']):
                    self.assertIn(item['variant'], ('fixed', 'safe'))
                    self.assertIsNone(item['expected_rule'],
                                      'a ' + item['variant'] + ' control must expect no candidates')


class ReviewedRuleControlTests(unittest.TestCase):
    """The three rules this unit added a control for, pinned to one candidate set."""

    def test_each_reviewed_positive_raises_its_rule(self):
        for rule, (family_dir, filename) in REVIEWED_POSITIVES.items():
            with self.subTest(rule=rule):
                status, rules = detect(family_dir, filename)
                self.assertEqual(status, 'completed')
                self.assertIn(rule, rules)

    def test_the_caller_class_positive_raises_that_rule_alone(self):
        """A permission check is not a caller class. The permission fact is kept
        (so `ipc.auth.missing` is not raised) and the class question is the only
        one left open."""
        self.assertEqual(detect('auth03', 'caller_class_positive.cpp'),
                         ('completed', ['ipc.auth.caller-class']))

    def test_the_identity_domain_positive_also_loses_its_permission_credit(self):
        """A check that submits the wrong identity domain is not credited as
        caller authorization for the operation it guards, so the mis-domain and
        the missing-authorization candidate are raised together. Asserting only
        the identity rule would hide that coupling."""
        status, rules = detect('auth03', 'identity_domain_positive.cpp')
        self.assertEqual(status, 'completed')
        self.assertEqual(rules, ['ipc.auth.guard-coverage',
                                 'ipc.auth.identity-domain',
                                 'ipc.auth.missing'])

    def test_the_position_underflow_positive_raises_that_rule_alone(self):
        self.assertEqual(detect('data01', 'position_underflow_positive.cpp'),
                         ('completed', ['ipc.parcel.position-underflow']))


class MinimalPairTests(unittest.TestCase):
    """Each positive's fixed control differs from it in one line, so the
    suppression is attributable to that line rather than to the file being a
    different program."""

    def test_each_pair_differs_in_one_line(self):
        for family_dir, positive, fixed, budget in REVIEWED_PAIRS:
            with self.subTest(pair=(positive, fixed)):
                self.assertEqual(changed_lines(family_dir, positive, fixed), budget)

    def test_each_pair_suppresses_every_candidate(self):
        for family_dir, positive, fixed, _ in REVIEWED_PAIRS:
            with self.subTest(pair=(positive, fixed)):
                _, before = detect(family_dir, positive)
                self.assertTrue(before)
                self.assertEqual(detect(family_dir, fixed), ('completed', []))


if __name__ == '__main__':
    unittest.main()
