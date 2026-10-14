import unittest

from scripts.review_cpp_candidates import build_holdout, review_policy


class ReviewPolicyTests(unittest.TestCase):
    def test_non_production_scope_is_refuted(self):
        policy = review_policy(
            "distributeddatamgr_kv_store",
            "kvstoremock/external_inner_kit/napi/include/extension_context.h",
            "abilityInfo_",
            "read",
        )
        self.assertEqual(policy["status"], "refuted")
        self.assertEqual(policy["group_id"], "RC-SCOPE-MOCK")

    def test_stable_owner_shape_is_not_confirmed(self):
        policy = review_policy(
            "distributeddatamgr_kv_store",
            "frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp",
            "nativeStore_",
            "read",
        )
        self.assertEqual(policy["status"], "likely_false_positive")
        self.assertNotIn("confirmed", policy["status"])

    def test_mutable_owner_pair_remains_plausible(self):
        policy = review_policy(
            "distributeddatamgr_kv_store",
            "frameworks/common/js_proxy.h",
            "instance_",
            "write",
        )
        self.assertEqual(policy["status"], "plausible_unproven")

    def test_holdout_and_development_have_no_shared_group_identity(self):
        rows = [
            {
                "root_cause_group": "RC-STREAM-LISTENER",
                "workbench_candidate_id": "a",
                "diagnostic_id": "d1",
                "file": "stream_manager.h",
                "symbol": "streamListener_",
                "source_sha256": "1" * 64,
            },
            {
                "root_cause_group": "RC-KV-OWNER",
                "workbench_candidate_id": "b",
                "diagnostic_id": "d2",
                "file": "impl.cpp",
                "symbol": "nativeStore_",
                "source_sha256": "2" * 64,
            },
        ]
        result = build_holdout(rows, [])
        self.assertEqual(result["holdout_candidate_count"], 1)
        self.assertEqual(result["development_candidate_count"], 1)
        self.assertFalse(
            result["leakage_checks"]["same_file_symbol_source_hash_overlap"]
        )


if __name__ == "__main__":
    unittest.main()
