"""Independent T83 controls for Pasteboard candidate suppression."""
import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest


class D83AdversarialTests(unittest.TestCase):
    def scan(self, source):
        unit = SourceUnit(path='pasteboard_service.cpp', language='cpp', text=source,
                          sha256=hashlib.sha256(source.encode()).hexdigest(), parse_status='complete')
        request = ScanRequest('t83-quota', 'fixture/t83', 'a' * 40, snapshot_digest((unit,)),
                              'current-component:fixture/t83')
        return KnownDisclosedCveDetector().detect(ScanContext(request, (unit,)), (unit,))

    def observer(self, before='', after='', helper=''):
        return helper + '''void AddPasteboardChangedObserver(Observer *observer) {
            auto it = observerMap_.find(GetUserId()); auto observers = it->second;
            ''' + before + ' observers->insert(observer); ' + after + ' }'

    def quota_candidate(self, source):
        return any(f.symbol == 'CVE-2025-25212' for f in self.scan(source).findings)

    def test_direct_quota_must_dominate_insertion(self):
        guard = 'if(observers->size() >= MAX_OBSERVERS_PER_PID) return;'
        for prefix in ('if(enabled) ', 'while(enabled) ', 'for(;enabled;) '):
            with self.subTest(prefix=prefix):
                self.assertTrue(self.quota_candidate(self.observer(prefix + guard)))
        for prefix in ('if(enabled) Notify(); else ', 'if(enabled) {} else '):
            with self.subTest(prefix=prefix):
                self.assertTrue(self.quota_candidate(self.observer(prefix + guard)))
        self.assertFalse(self.quota_candidate(self.observer(guard)))
        self.assertFalse(self.quota_candidate(self.observer(
            'if(observers->size() >= MAX_OBSERVERS_PER_PID) { return; }')))

    def test_wrong_receiver_post_insert_and_nonrefusing_checks_do_not_suppress(self):
        for before, after in (
            ('if(other->size() >= MAX_OBSERVERS_PER_PID) return;', ''),
            ('', 'if(observers->size() >= MAX_OBSERVERS_PER_PID) return;'),
            ('if(observers->size() >= MAX_OBSERVERS_PER_PID) Notify();', ''),
            ('if(observers->size() >= MAX_OBSERVERS_PER_PID && enabled) return;', ''),
        ):
            with self.subTest(before=before, after=after):
                self.assertTrue(self.quota_candidate(self.observer(before, after)))

    def test_helper_result_order_receiver_and_dominance(self):
        helper = '''bool AtQuota(Observers *values) {
            if(values->size() >= MAX_OBSERVERS_PER_PID) return true;
            return false; }'''
        for before, after in (
            ('AtQuota(observers);', ''),
            ('if(AtQuota(other)) return;', ''),
            ('', 'if(AtQuota(observers)) return;'),
            ('if(enabled) if(AtQuota(observers)) return;', ''),
            ('while(enabled) if(AtQuota(observers)) return;', ''),
            ('for(;enabled;) if(AtQuota(observers)) return;', ''),
        ):
            with self.subTest(before=before, after=after):
                self.assertTrue(self.quota_candidate(self.observer(before, after, helper)))
        self.assertFalse(self.quota_candidate(self.observer('if(AtQuota(observers)) return;', helper=helper)))

    def test_permission_token_never_erases_source_candidate(self):
        dispatch = '''PasteboardServiceStub::PasteboardServiceStub() {
            memberFuncMap_[GET_PASTE_DATA] = &PasteboardServiceStub::OnGetPasteData; }
            int OnRemoteRequest(int code) { auto it=memberFuncMap_.find(code);
            if(it!=memberFuncMap_.end()) return (this->*it->second)(); return 0; }'''
        for body in (
            'CheckPermission(); GetPasteData(); reply.WriteParcelable(data);',
            'GetPasteData(); CheckPermission(); reply.WriteParcelable(data);',
            'other.CheckPermission(); GetPasteData(); reply.WriteParcelable(data);',
            'if(!CheckPermission()) return -1; GetPasteData(); reply.WriteParcelable(data);',
        ):
            with self.subTest(body=body):
                findings = self.scan(dispatch + 'int OnGetPasteData(){' + body + '}').findings
                candidate = next(f for f in findings if f.symbol == 'CVE-2025-27247')
                self.assertTrue(any(o.kind == 'permission_guard' for o in candidate.evidence_obligations))


if __name__ == '__main__':
    unittest.main()
