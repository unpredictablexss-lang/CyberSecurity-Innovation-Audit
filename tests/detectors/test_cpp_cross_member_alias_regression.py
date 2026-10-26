from __future__ import annotations
import hashlib
import unittest
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector, RULE_CROSS_MEMBER_ALIAS_UAF

VULN = {
    'setter.c': 'void set(struct A *left, struct B *right) { left->buffer = right->buffer; }\n',
    'destroy.c': 'void destroy(struct B *right) { free(right->buffer); }\n',
    'use.c': 'void render(struct A *left) { consume(left->buffer[0]); }\n',
}
FIXED = {
    'setter.c': 'void set(struct A *left, struct B *right) { left->buffer = clone_buffer(right->buffer); }\n',
    'destroy.c': VULN['destroy.c'], 'use.c': VULN['use.c'],
}
UNRELATED = {
    'setter.c': 'void set(struct A *left, struct B *right) { left->buffer = right->other; }\n',
    'destroy.c': VULN['destroy.c'], 'use.c': VULN['use.c'],
}

def scan(files, status='partial'):
    units=tuple(sorted((SourceUnit(path=path, language='c', text=text, sha256=hashlib.sha256(text.encode()).hexdigest(), parse_status=status) for path,text in files.items()), key=lambda unit: unit.path))
    ctx=ScanContext(request=ScanRequest(request_id='test:d2-cross-member',repository='fixture/cross-member',commit='3'*40,snapshot_sha256=snapshot_digest(units),target_id='current-component:fixture/cross-member',profile_id='fixture-no-build',provenance='fixture'),units=units)
    return CppResourceLifetimeDetector().detect(ctx,units)

class CrossMemberAliasRegressionTests(unittest.TestCase):
    def test_vulnerable_alias_release_later_read_kept_as_partial_candidate(self):
        run=scan(VULN)
        self.assertEqual(run.status,'blocked')
        findings=[f for f in run.findings if f.rule_id==RULE_CROSS_MEMBER_ALIAS_UAF]
        self.assertEqual(len(findings),1)
        self.assertEqual(set(run.analyzed_files),set(VULN))
    def test_independent_copy_and_unrelated_member_are_quiet_but_partial(self):
        for files in (FIXED,UNRELATED):
            run=scan(files)
            self.assertEqual(run.status,'blocked')
            self.assertFalse(any(f.rule_id==RULE_CROSS_MEMBER_ALIAS_UAF for f in run.findings))
            self.assertFalse(run.analyzed_files)
    def test_failed_inputs_do_not_produce_candidates(self):
        run=scan(VULN,'failed')
        self.assertEqual(run.status,'blocked')
        self.assertFalse(run.findings)

if __name__=='__main__': unittest.main()

