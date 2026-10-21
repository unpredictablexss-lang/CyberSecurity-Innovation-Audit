from __future__ import annotations
import hashlib
import unittest
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector, RULE_RECURSIVE_CLEANUP

VULNERABLE = '''
struct Form { struct Form *child; struct Part *first; };
struct Part { struct Form *nested; void (*dispose)(void *); struct Part *next; };
void dispose_form(void *value) { free_form((struct Form *)value); }
void cleanup_content(struct Part *part) { if (part->dispose) part->dispose(part->nested); }
void cleanup_part(struct Part *part) { cleanup_content(part); }
void free_form(struct Form *form) { while (form->first) { struct Part *part=form->first; cleanup_part(part); free(part); } free(form); }
void attach_nested(struct Part *part, struct Form *child) { part->nested=child; part->dispose=dispose_form; }
'''
FIXED = VULNERABLE.replace('struct Part *part=form->first; cleanup_part(part);', 'struct Part *part=form->first; form->first=part->next; part->dispose=NULL; cleanup_part(part);')
UNRELATED = 'void walk(struct Node *node) { if (node) walk(node->child); }\n'

def scan(text: str, parse_status='complete'):
    unit=SourceUnit(path='control.c', language='c', text=text, sha256=hashlib.sha256(text.encode()).hexdigest(), parse_status=parse_status)
    ctx=ScanContext(request=ScanRequest(request_id='test:d2-recursive',repository='fixture/resource',commit='2'*40,snapshot_sha256=snapshot_digest((unit,)),target_id='current-component:fixture/resource',profile_id='fixture-no-build',provenance='fixture'),units=(unit,))
    return CppResourceLifetimeDetector().detect(ctx,(unit,))

class RecursiveCleanupRegressionTests(unittest.TestCase):
    def test_vulnerable_callback_cleanup_cycle_candidate(self):
        run=scan(VULNERABLE)
        self.assertEqual(run.status,'completed')
        self.assertEqual(sum(f.rule_id==RULE_RECURSIVE_CLEANUP for f in run.findings),1)
    def test_fixed_iterative_detach_and_unrelated_recursion_quiet(self):
        for text in (FIXED,UNRELATED):
            self.assertFalse(any(f.rule_id==RULE_RECURSIVE_CLEANUP for f in scan(text).findings))
    def test_partial_candidate_is_kept_but_unknown(self):
        run=scan(VULNERABLE,'partial')
        self.assertEqual(run.status,'blocked')
        self.assertTrue(any(f.rule_id==RULE_RECURSIVE_CLEANUP for f in run.findings))
    def test_partial_callback_cycle_uses_recursive_cwe_not_uaf(self):
        run = scan(VULNERABLE, 'partial')
        candidates = [item for item in run.findings if item.rule_id == RULE_RECURSIVE_CLEANUP]
        self.assertTrue(candidates)
        for candidate in candidates:
            self.assertEqual(candidate.candidate_cwe, "CWE-674")
            self.assertEqual(candidate.consequence_cwe, "CWE-674")
            self.assertEqual(candidate.consequence_impact, "availability")

    def test_partial_without_candidate_stays_unknown(self):
        run=scan(UNRELATED,'partial')
        self.assertEqual(run.status,'blocked')
        self.assertFalse(run.findings)

if __name__=='__main__': unittest.main()
