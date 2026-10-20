"""Per-family depth controls: every positive of this unit pinned to the exact
candidates the engine produces, and one test per engine case the lane acceptance
item names.

The shared manifest asserts, per fixture, that a named rule is present or that no
candidate at all is raised. It does not assert *which* candidates a positive
raises, it cannot state that a positive and its control differ in one line, and it
cannot state what the engine recorded on the way to not raising something. Those
are the assertions here.

The fixtures live under `tests/fixtures/ipc/<family>/` with their own manifests,
so `test_ipc_family_matrix.FamilyFixtureMatrixTests` covers them too (directory
name fixes the family, a null expectation means no candidates, the run must
complete). What is added here is the per-rule exactness, the pair checks and the
engine-case coverage.

`PinnedCandidateTests` holds the exact candidate set of every positive in this
unit, each line paired with the construct it must be pointing at.
`EngineCaseCoverageTests` holds one test per engine case the lane acceptance item
names -- const references, a non-unique host method, the propagation of a refused
one-hop limitation, a locally shadowed reviewed-role body, and non-zero line
numbers -- each asserting the side that shows the case and the side that does not.

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

# Every positive of this unit, keyed by family directory and fixture, against the
# exact candidates the pinned policy produces for it. Written out rather than read
# from a run: a rule that starts or stops firing somewhere else has to change this
# table with a reviewer looking at both, which is the point of the table.
#
# Each candidate is `(rule, line, token)`, and the token has to appear on that line
# of that fixture. The line number is pinned because a candidate that loses its line
# is not evidence, and the token is pinned because a line number is only meaningful
# if it points at the construct the candidate is about -- a detector that numbered
# from a preprocessed text rather than the file would satisfy the number and fail
# the token.
PINNED_POSITIVES = {
    ('data06', 'cj_array_allocation_width_positive.cpp'): (
        ('ipc.parcel.array-allocation-width', 6, 'CJ_ReadRemoteObjectArray'),),
    ('auth07', 'denial_transport_success_positive.cpp'): (
        ('ipc.auth.denial-transport-success', 7, 'return NETMANAGER_SUCCESS'),),
    ('auth06', 'peer_session_positive.cpp'): (
        ('ipc.network.auth-session-whitelist', 8, 'OnRequsetUpdateAuthChannel'),),
    ('data05', 'tlv_fixed_width_positive.cpp'): (
        ('ipc.tlv.fixed-width-length', 5, 'memcpy_s'),),
    ('auth03', 'caller_class_positive.cpp'): (
        ('ipc.auth.caller-class', 7, 'GetPermissionUsedRecordsAsync'),),
    # A check submitted in the wrong identity domain is not credited as caller
    # authorization for the operation it guards, so the mis-domain and the
    # missing-authorization candidate are raised together with guard-coverage for
    # the non-dominating check. Asserting only the identity rule would hide that
    # coupling, which is the rule's point.
    ('auth03', 'identity_domain_positive.cpp'): (
        ('ipc.auth.guard-coverage', 7, 'StartAbility'),
        ('ipc.auth.identity-domain', 6, 'VerifyAccessToken'),
        ('ipc.auth.missing', 7, 'StartAbility')),
    ('data01', 'position_underflow_positive.cpp'): (
        ('ipc.parcel.position-underflow', 7, 'RewindRead'),),
    # The reviewed caller-role name is also defined in the scanned sources, so the
    # name is not credited and the body is read instead. 4096 is not a reviewed
    # service-account value, so that body establishes nothing and the sensitive call
    # below it stays a candidate.
    ('auth02', 'caller_role_shadowed_positive.cpp'): (
        ('ipc.auth.missing', 20, 'DeleteUserData'),),
    # The same shadowed name defined at file scope instead of as a member of the
    # entry's class. The name is refused outright and its body is never used, which is
    # the form the member fixture is contrasted against.
    ('auth02', 'caller_role_shadowed_free_predicate_positive.cpp'): (
        ('ipc.auth.missing', 19, 'DeleteUserData'),),
    # The same entry with the parcel bound by const reference and by reference: the
    # two halves of the invariance pair, pinned separately because they are separate
    # files and a change to either one has to show up here.
    ('auth02', 'entry_const_reference_positive.cpp'): (
        ('ipc.auth.missing', 6, 'DeleteUserData'),),
    ('auth02', 'entry_reference_positive.cpp'): (
        ('ipc.auth.missing', 6, 'DeleteUserData'),),
    # A permission check whose failure branch falls through: the guard-coverage rule
    # records the non-dominating guard and the call below it is still a candidate for
    # missing authorization. Two candidates on one line is what that shape produces,
    # not two independent defects.
    ('auth04', 'guard_fallthrough_positive.cpp'): (
        ('ipc.auth.guard-coverage', 7, 'DeleteUserData'),
        ('ipc.auth.missing', 7, 'DeleteUserData')),
    ('cap01', 'export_positive.cpp'): (
        ('ipc.capability.export', 6, 'WriteRemoteObject'),),
    # The exported object is produced one class hop away, in the implementer of a
    # virtual call: an ungated implementer, then two gated ones the index refuses to
    # choose between, then the lane's macro-named stub the index cannot bind at all.
    ('cap01', 'onehop_ungated_positive.cpp'): (
        ('ipc.capability.export', 28, 'WriteRemoteObject'),),
    ('cap01', 'onehop_not_unique_positive.cpp'): (
        ('ipc.capability.export', 33, 'WriteRemoteObject'),),
    ('cap01', 'onehop_macro_renamed_stub_positive.cpp'): (
        ('ipc.capability.export', 28, 'WriteRemoteObject'),),
}
# A minimal pair: (positive, control) inside one family directory, and how many
# source lines the two files may differ by. One line means the suppressed
# candidates are attributable to that line and not to a widened guard set.
REVIEWED_PAIRS = (
    ('auth03', 'caller_class_positive.cpp', 'caller_class_fixed.cpp', 1),
    ('auth03', 'identity_domain_positive.cpp', 'identity_domain_fixed.cpp', 1),
    ('data01', 'position_underflow_positive.cpp', 'position_underflow_fixed.cpp', 1),
    ('auth02', 'caller_role_shadowed_positive.cpp', 'caller_role_shadowed_fixed.cpp', 1),
    ('auth02', 'caller_role_shadowed_positive.cpp',
     'caller_role_shadowed_unmodelled_safe.cpp', 1),
    ('auth04', 'guard_fallthrough_positive.cpp', 'guard_fallthrough_fixed.cpp', 1),
    ('auth04', 'guard_fallthrough_positive.cpp', 'guard_fallthrough_unmodelled_safe.cpp', 1),
    ('cap01', 'export_positive.cpp', 'export_guarded_fixed.cpp', 1),
    ('cap01', 'export_positive.cpp', 'export_null_safe.cpp', 1),
    ('cap01', 'onehop_ungated_positive.cpp', 'onehop_credited_fixed.cpp', 1),
)
# A pair that must *not* be suppressed: both halves have to produce the same
# candidates, so it is asserted by equality in both directions. The shared set also
# has to be non-empty -- two empty runs are equal for reasons that have nothing to
# do with the invariance being claimed.
INVARIANCE_PAIRS = (
    ('auth02', 'entry_const_reference_positive.cpp', 'entry_reference_positive.cpp', 1),
)


def context(text, path='sample.cpp', repository='fixture/ipc'):
    index = parse_source(text, language='cpp')
    unit = SourceUnit(path, 'cpp', text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status)
    request = ScanRequest('ipc-test', repository, 'synthetic-ipc-v1',
                          snapshot_digest((unit,)), 'current-component:' + repository)
    return ScanContext(request, (unit,), {'ast': {path: index.to_dict()}})


def run_of(family_dir, filename):
    """The detector's run for one fixture, limitations included."""
    text = (BASE / family_dir / filename).read_text()
    if family_dir == 'data06':
        ctx = context(text, 'interfaces/innerkits/cj/src/message_sequence_impl.cpp',
                      'openharmony/communication_ipc')
    else:
        ctx = context(text, filename)
    return IpcInterfaceDetector().detect(ctx, ctx.units)


def detect(family_dir, filename):
    run = run_of(family_dir, filename)
    return run.status, sorted({f.rule_id for f in run.findings})


def candidates(run):
    return sorted((f.rule_id, f.line) for f in run.findings)


def source_line(family_dir, filename, line):
    """The fixture's raw line, 1-based, as the detector numbered it."""
    return (BASE / family_dir / filename).read_text().splitlines()[line - 1]


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
        if path.parent.name == 'data06':
            ctx = context(text, 'interfaces/innerkits/cj/src/message_sequence_impl.cpp',
                          'openharmony/communication_ipc')
        else:
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


class PinnedCandidateTests(unittest.TestCase):
    """Every positive of this unit, against the exact candidates it produced.

    The matrix test covers the manifest's own claim (this rule is present, or
    nothing is). The claim here is the stronger one the fixture is worth: this
    positive raises these rules at these lines, and no others.
    """

    def test_each_pinned_positive_raises_exactly_its_pinned_candidates(self):
        for (family_dir, filename), pinned in sorted(PINNED_POSITIVES.items()):
            with self.subTest(fixture=filename):
                run = run_of(family_dir, filename)
                self.assertEqual(run.status, 'completed')
                self.assertEqual(candidates(run),
                                 sorted((rule, line) for rule, line, _ in pinned))

    def test_each_pinned_line_is_the_construct_the_candidate_is_about(self):
        """A line number is only evidence if it points at something. This also
        pins that the detector numbers file lines: a number derived from a
        preprocessed text would still be an int and would fail here."""
        for (family_dir, filename), pinned in sorted(PINNED_POSITIVES.items()):
            for rule, line, token in pinned:
                with self.subTest(fixture=filename, rule=rule):
                    self.assertIn(token, source_line(family_dir, filename, line))

    def test_every_positive_row_of_a_family_manifest_is_pinned(self):
        """Both directions: a positive row with no pin would be covered only by the
        matrix test's weaker claim, and a pin with no row would be a fixture that
        nothing declares."""
        rows = {}
        for path in family_manifests():
            for item in json.loads(path.read_text()):
                if item['variant'] == 'positive':
                    rows[(path.parent.name, item['file'])] = item['expected_rule']
        self.assertEqual(set(rows), set(PINNED_POSITIVES))
        for key, rule in sorted(rows.items()):
            with self.subTest(fixture=key[1]):
                self.assertIn(rule, {r for r, _, _ in PINNED_POSITIVES[key]})

    def test_a_pinned_rule_is_catalogued_and_the_family_is_among_what_is_raised(self):
        """A fixture may raise another family's rule as a coupling (the identity
        domain positive does), so what is required is that the directory's own
        family is represented among the rules the positive raises -- not that it is
        the only one."""
        for (family_dir, filename), pinned in sorted(PINNED_POSITIVES.items()):
            for rule, _, _ in pinned:
                with self.subTest(fixture=filename, rule=rule):
                    self.assertIn(rule, IMPACT_BY_RULE)
            with self.subTest(fixture=filename):
                self.assertTrue(
                    any(families.family_of_rule(rule).fixture_dir == family_dir
                        for rule, _, _ in pinned),
                    'no pinned candidate belongs to ' + family_dir)


class EngineCaseCoverageTests(unittest.TestCase):
    """One test per engine case the lane acceptance item names, both sides asserted.

    The item is: const references, a non-unique host method, the propagation of a
    refused one-hop limitation, a locally shadowed reviewed-role body and non-zero
    line numbers, with the controls on both sides asserted. A case is covered here
    only if the fixture that shows it and the fixture that does not both appear in
    the same test.
    """

    def one(self, family_dir, filename, token):
        """The single limitation of this run that mentions `token`."""
        found = [item for item in run_of(family_dir, filename).limitations
                 if token in item]
        self.assertEqual(len(found), 1,
                         'expected one limitation mentioning ' + repr(token))
        return found[0]

    def test_a_const_reference_entry_and_a_reference_entry_are_read_the_same(self):
        """Whether the parcel is bound by const reference or by reference says
        nothing about caller authorization, so neither kind may be credited for it
        and neither may be read as a different entry."""
        for family_dir, left, right, budget in INVARIANCE_PAIRS:
            with self.subTest(pair=(left, right)):
                self.assertEqual(changed_lines(family_dir, left, right), budget)
                left_run = run_of(family_dir, left)
                right_run = run_of(family_dir, right)
                left_pairs, right_pairs = candidates(left_run), candidates(right_run)
                self.assertTrue(left_pairs,
                                'equality between two empty runs is not evidence')
                self.assertEqual(left_run.status, right_run.status)
                self.assertEqual(left_pairs, right_pairs)

    def test_a_non_unique_host_method_is_refused_rather_than_chosen(self):
        refused = self.one('cap01', 'onehop_not_unique_positive.cpp', 'is not unique')
        self.assertIn('the callee body was not read', refused)
        self.assertIn('stays a candidate', refused)
        # The other side: one implementer, and it is ungated. The hop is followed,
        # nothing is refused, and the candidate is raised at the reply write for the
        # reason the fixture is about.
        unique = run_of('cap01', 'onehop_ungated_positive.cpp')
        self.assertEqual([item for item in unique.limitations
                          if 'is not unique' in item], [])
        self.assertEqual(candidates(unique), [('ipc.capability.export', 28)])

    def test_a_refused_one_hop_limitation_propagates_into_the_run(self):
        """The refusal is reported, not taken silently: the run keeps the candidate
        at the call site and states why the hop stopped with it. The credited side
        shows the other ending of the same mechanism, and says how many implementer
        guards were read."""
        refused = run_of('cap01', 'onehop_not_unique_positive.cpp')
        self.assertEqual(sorted({f.rule_id for f in refused.findings}),
                         ['ipc.capability.export'])
        self.assertIn('stays a candidate',
                      self.one('cap01', 'onehop_not_unique_positive.cpp',
                               'is not unique'))
        credited = run_of('cap01', 'onehop_credited_fixed.cpp')
        self.assertEqual(candidates(credited), [])
        self.one('cap01', 'onehop_credited_fixed.cpp',
                 'Cross-TU one-hop dispatch: 1 implementer guard')

    def test_a_locally_shadowed_reviewed_role_body_is_recorded_and_not_credited(self):
        """The limitation is a fact about the name, so it is recorded on every side
        of the pair: the reviewed name is not credited whichever way the body reads.
        What changes between the files is what that body derives."""
        for filename in ('caller_role_shadowed_positive.cpp',
                         'caller_role_shadowed_fixed.cpp',
                         'caller_role_shadowed_unmodelled_safe.cpp'):
            with self.subTest(fixture=filename):
                line = self.one('auth02', filename,
                                'is also defined in the scanned sources at')
                self.assertIn(filename + ':12', line)
                self.assertIn('was not credited', line)
        self.assertEqual(candidates(run_of('auth02', 'caller_role_shadowed_positive.cpp')),
                         [('ipc.auth.missing', 20)])
        self.assertEqual(candidates(run_of('auth02', 'caller_role_shadowed_fixed.cpp')), [])
        self.assertEqual(candidates(run_of('auth02',
                                           'caller_role_shadowed_unmodelled_safe.cpp')), [])

    def test_every_hop_citation_line_is_non_zero_and_names_its_construct(self):
        """`DetectorFinding` refuses a line below 1 at construction, so the fixture
        side is the part worth asserting: the lines the one-hop credit cites are the
        dispatch, the implementer and its gate, each read back from the file."""
        cite = self.one('cap01', 'onehop_credited_fixed.cpp',
                        'Cross-TU one-hop guard credited')
        for line, token in ((27, 'GetObject(id,object);'),
                            (32, 'int FixtureOnehopService::GetObject'),
                            (33, 'IsSACalling')):
            with self.subTest(line=line):
                self.assertIn('onehop_credited_fixed.cpp:%d' % line, cite)
                self.assertIn(token, source_line('cap01', 'onehop_credited_fixed.cpp', line))

    def test_a_member_predicate_body_is_read_and_a_file_scope_one_is_not(self):
        """Not one of the five named cases either: the other boundary found here.

        A reviewed caller-role name defined in the scanned sources gets different
        treatment depending on how it is defined. The member form is read -- the run
        says a call was read from that body, and that is the body whose comparison
        against a reviewed account the fixed fixture changes. The file-scope form is
        refused outright and its body is never used. Both are candidates here; what
        differs is what the run reports having done, so both sides are asserted."""
        member = self.one('auth02', 'caller_role_shadowed_positive.cpp',
                          'is also defined in the scanned sources at')
        self.assertIn('a call to it was read from that body', member)
        free = self.one('auth02', 'caller_role_shadowed_free_predicate_positive.cpp',
                        'Local caller-role definition is unresolved')
        self.assertIn('reviewed-name credit refused', free)
        self.assertIn('caller authorization remains unknown', free)
        self.assertEqual(
            candidates(run_of('auth02',
                              'caller_role_shadowed_free_predicate_positive.cpp')),
            [('ipc.auth.missing', 19)])

    def test_a_macro_named_stub_class_is_not_bound_by_the_entry_index(self):
        """Not one of the five named cases: the boundary found while writing them.

        The rest of this unit names its stub class through `#define Stub <fixture>`,
        and an object-like macro on that class stops the entry index from binding
        the handler -- measured. The one-hop fixtures therefore write their class
        names out, and this fixture keeps the macro-named shape as a control so the
        boundary cannot move unnoticed. Both sides: the same gated program raises
        nothing under a literal class name, and the candidate under the macro."""
        bound = self.one('cap01', 'onehop_macro_renamed_stub_positive.cpp',
                         'Dispatch handler not uniquely resolved')
        self.assertIn('not used as an entry', bound)
        self.assertEqual(candidates(run_of('cap01',
                                           'onehop_macro_renamed_stub_positive.cpp')),
                         [('ipc.capability.export', 28)])
        self.assertEqual(candidates(run_of('cap01', 'onehop_credited_fixed.cpp')), [])


class MinimalPairTests(unittest.TestCase):
    """Each positive's control (fixed or safe) differs from it in one line, so the
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
