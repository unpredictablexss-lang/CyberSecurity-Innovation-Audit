"""The family registry: what each family owns, and the guards on its composition.

These tests exist so six lines can work in parallel without a merge order: the
registry refuses to load if the families stop partitioning the consequence
catalogue, if a rule changes owner, if a family claims a policy value another
family claims, or if a family module is missing a declaration. A family may
therefore be read, moved and tested on its own, and the kernel it composes into
is checked here rather than in each family's own test file.

The CWE table below is deliberately a literal: it must fail if a family's CWE
drifts, not follow the registry wherever it goes.
"""
import hashlib
import json
from pathlib import Path
import types
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface import families
from src.ohscanner.detectors.interface.detector import _CWE, IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import IMPACT_BY_RULE, IpcPolicy, ServiceAccountRole

BASE = Path(__file__).parent / 'fixtures/ipc'

# The mechanism CWE each family reports. Written out rather than read from the
# registry: this is the reviewed classification, so a family that changes its CWE
# has to change this table too, with a reviewer looking at both.
REVIEWED_CWE = {
    'AUTH-01': 'CWE-441',
    'AUTH-02': 'CWE-862',
    'AUTH-03': 'CWE-863',
    'AUTH-04': 'CWE-863',
    'DATA-01': 'CWE-20',
    'CAP-01': 'CWE-926',
}


def context(text, path='sample.cpp'):
    index = parse_source(text, language='cpp')
    unit = SourceUnit(path, 'cpp', text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status)
    request = ScanRequest('ipc-test', 'fixture/ipc', 'synthetic-ipc-v1',
                          snapshot_digest((unit,)), 'current-component:fixture/ipc')
    return ScanContext(request, (unit,), {'ast': {path: index.to_dict()}})


def fake_module(name='fake', **declarations):
    """A family module as the registry sees it: attributes, nothing more."""
    return types.SimpleNamespace(__name__='family_module_' + name, **declarations)


def family(name='FAKE-01', rules=('ipc.auth.missing',), cwe='CWE-862', policy=None):
    declarations = dict(FAMILY=name, TITLE='t', CWE=cwe, RULES=rules)
    if policy is not None:
        declarations['POLICY'] = policy
    return families._declared(fake_module(name, **declarations))


class FamilyRegistryTests(unittest.TestCase):
    def test_families_partition_the_consequence_catalogue(self):
        """Every catalogue rule has exactly one owner, and no family invents one."""
        owners = {}
        for declared in families.registry():
            for rule in declared.rules:
                self.assertNotIn(rule, owners,
                                 rule + ' is claimed by both ' + owners.get(rule, '') + ' and '
                                 + declared.family_id)
                owners[rule] = declared.family_id
        self.assertEqual(set(owners), set(IMPACT_BY_RULE))

    def test_ids_cwes_and_fixture_directories_are_well_formed(self):
        self.assertEqual({f.family_id for f in families.registry()}, set(REVIEWED_CWE))
        for declared in families.registry():
            with self.subTest(family=declared.family_id):
                self.assertEqual(declared.cwe, REVIEWED_CWE[declared.family_id])
                # A fixture directory is derived from the id, so the matrix test
                # can tell which family a directory belongs to without a lookup.
                self.assertEqual(declared.fixture_dir,
                                 declared.family_id.replace('-', '').lower())
                self.assertEqual(families.family_of_rule(declared.rules[0]), declared)
                self.assertTrue(declared.module.startswith('src.ohscanner.detectors.interface.families.'))
        self.assertEqual(families.cwes(), REVIEWED_CWE)
        self.assertEqual(_CWE, REVIEWED_CWE)

    def test_a_module_that_declares_nothing_is_rejected(self):
        with self.assertRaises(ValueError) as caught:
            families._declared(fake_module('empty'))
        self.assertIn('does not declare', str(caught.exception))

    def test_a_rule_outside_the_catalogue_is_rejected(self):
        with self.assertRaises(ValueError) as caught:
            families._checked([family(rules=('ipc.auth.invented',))])
        self.assertIn('ipc.auth.invented', str(caught.exception))

    def test_a_rule_claimed_twice_is_rejected(self):
        with self.assertRaises(ValueError) as caught:
            families._checked([family('ONE-01'), family('TWO-01')])
        self.assertIn('claimed by both', str(caught.exception))

    def test_an_unclaimed_catalogue_rule_is_rejected(self):
        """The partition is checked in both directions: dropping a family leaves
        its rules owned by nobody, which must not load silently."""
        kept = [family('AUTH-02', rules=('ipc.auth.missing',)),
                family('AUTH-04', rules=('ipc.auth.guard-coverage',))]
        with self.assertRaises(ValueError) as caught:
            families._checked(kept)
        self.assertIn('no family claims catalogue rule(s)', str(caught.exception))
        self.assertIn('ipc.parcel.copy-range', str(caught.exception))

    def test_two_families_claiming_one_policy_value_is_rejected(self):
        """The one cross-line conflict the compiler cannot see.

        Both families claim `Dump`. That is a review decision, so it must not
        resolve by which family the merge happens to reach first. The families
        are made a complete partition first, so the check that fires is the policy
        one and not an earlier complaint about the rule set.
        """
        rules = sorted(IMPACT_BY_RULE)
        half = (len(rules) + 1) // 2
        with self.assertRaises(ValueError) as caught:
            families._checked([
                family('ONE-01', rules=tuple(rules[:half]),
                       policy={'sensitive_calls': frozenset({'Dump'})}),
                family('TWO-01', rules=tuple(rules[half:]),
                       policy={'sensitive_calls': frozenset({'Dump'})}),
            ])
        self.assertIn('the same value', str(caught.exception))
        # The positive control: the same partition loads when only one family
        # claims the value, so it is the shared claim that is refused.
        families._checked([
            family('ONE-01', rules=tuple(rules[:half]),
                   policy={'sensitive_calls': frozenset({'Dump'})}),
            family('TWO-01', rules=tuple(rules[half:])),
        ])

    def test_malformed_policy_fragments_are_rejected(self):
        cases = (
            ('unknown field', {'no_such_field': ('x',)}, 'unknown policy field'),
            # A scalar is a value the catalogue owns, not a set a family extends.
            ('scalar field', {'max_paths': (4,)}, 'may not add to scalar policy field'),
            # A bare string would iterate into characters, so it is not a set.
            ('string addition', {'sensitive_calls': 'Dump'}, 'must add a tuple or frozenset'),
        )
        for name, policy, expected in cases:
            with self.subTest(case=name):
                with self.assertRaises(ValueError) as caught:
                    families._declared(fake_module(
                        name, FAMILY='AUTH-02', TITLE='t', CWE='CWE-862',
                        RULES=('ipc.auth.missing',), POLICY=policy))
                self.assertIn(expected, str(caught.exception))


class PolicyCompositionTests(unittest.TestCase):
    def test_no_unreviewed_account_assignment_arrives_through_a_family(self):
        self.assertEqual(IpcPolicy().service_account_roles, ())
        merged = families.default_policy()
        self.assertEqual(merged.service_account_roles, ())
        self.assertEqual(merged.trusted_uids, IpcPolicy().trusted_uids)
        self.assertEqual(families.family_of_rule('ipc.auth.missing').family_id, 'AUTH-02')

    def test_merging_is_idempotent_and_keeps_the_callers_narrowing(self):
        merged = families.merge_policy()
        self.assertEqual(families.merge_policy(merged), merged)
        narrowed = families.merge_policy(IpcPolicy(max_paths=4))
        self.assertEqual(narrowed.max_paths, 4)
        self.assertEqual(narrowed.service_account_roles, merged.service_account_roles)

    def test_the_detector_and_a_hand_built_harness_agree(self):
        from src.ohscanner.detectors.interface.analysis import Interpreter
        from src.ohscanner.detectors.interface.entry_index import EntryIndex
        ctx = context((BASE / 'auth_positive.cpp').read_text())
        mine = IpcInterfaceDetector(IpcPolicy(max_paths=8)).policy
        self.assertEqual(mine.service_account_roles, families.default_policy().service_account_roles)
        self.assertEqual(mine.max_paths, 8)
        for policy in (IpcPolicy(), IpcPolicy(max_paths=8)):
            with self.subTest(policy=policy.max_paths):
                walk = Interpreter(ctx.units, policy, ctx.request)
                index = EntryIndex(ctx.units, policy)
                self.assertEqual(walk.policy.service_account_roles,
                                 families.default_policy().service_account_roles)
                self.assertEqual(index.policy.service_account_roles, ())


class FamilyFixtureMatrixTests(unittest.TestCase):
    """A family's own fixtures are held to the same matrix as the shared ones."""

    def matrix(self, manifest_path, expected_family=None):
        for item in json.loads(manifest_path.read_text()):
            with self.subTest(sample=item['sample_id']):
                self.assertIn(item['family'], {f.family_id for f in families.registry()})
                if expected_family is not None:
                    self.assertEqual(item['family'], expected_family,
                                     'a fixture under ' + expected_family + "'s directory declares "
                                     + str(item['family']))
                ctx = context((manifest_path.parent / item['file']).read_text())
                run = IpcInterfaceDetector().detect(ctx, ctx.units)
                self.assertEqual(run.status, 'completed')
                rules = {f.rule_id for f in run.findings}
                if item['expected_rule']:
                    self.assertIn(item['expected_rule'], rules)
                else:
                    self.assertEqual(rules, set())

    def test_the_shared_manifest_names_registered_families(self):
        """Every shipped fixture belongs to a family, and all six are represented."""
        items = json.loads((BASE / 'manifest.json').read_text())
        self.assertEqual({item['family'] for item in items}, set(REVIEWED_CWE))
        self.matrix(BASE / 'manifest.json')

    def test_a_family_directory_holds_that_family_only(self):
        """Directories appear as the family lines add fixtures; when one exists,
        its manifest is read with the same assertions and its family is fixed by
        the directory name, so a fixture cannot be filed under a foreign family."""
        for declared in families.registry():
            directory = BASE / declared.fixture_dir
            manifest_path = directory / 'manifest.json'
            if not manifest_path.exists():
                continue
            with self.subTest(family=declared.family_id):
                self.matrix(manifest_path, expected_family=declared.family_id)
                for item in json.loads(manifest_path.read_text()):
                    self.assertTrue((directory / item['file']).exists(),
                                    item['file'] + ' is listed but not in the directory')
                    self.assertIn(item['expected_rule'], set(declared.rules) | {None},
                                  'a fixture states the rule of another family')


if __name__ == '__main__':
    unittest.main()
