import unittest

from src.ohscanner.indexing import (
    _effective_cpu_quota, _parse_cpu_max, _parse_cpu_v1,
)


class CpuQuotaParsingTests(unittest.TestCase):
    def test_cgroup_v2_limited_quota(self):
        self.assertEqual(_parse_cpu_max("150000 100000"),
                         {"cores": 1.5, "status": "limited"})

    def test_cgroup_v2_unlimited_quota(self):
        self.assertEqual(_parse_cpu_max("max 100000"),
                         {"cores": None, "status": "unlimited"})

    def test_cgroup_v1_quota(self):
        self.assertEqual(_parse_cpu_v1("50000\n", "100000\n"),
                         {"cores": 0.5, "status": "limited"})

    def test_invalid_or_disabled_quota_stays_unknown(self):
        self.assertIsNone(_parse_cpu_max("max 0"))
        self.assertIsNone(_parse_cpu_max("not-a-quota"))
        self.assertIsNone(_parse_cpu_v1("0", "100000"))
        self.assertIsNone(_parse_cpu_v1("50000", "invalid"))

    def test_effective_quota_uses_tightest_limited_ancestor(self):
        quota = _effective_cpu_quota([
            {"cores": None, "status": "unlimited"},
            {"cores": 2.0, "status": "limited"},
            {"cores": 1.5, "status": "limited"},
        ], "test")
        self.assertEqual(quota, {
            "cores": 1.5, "status": "limited", "source": "test",
        })


if __name__ == "__main__":
    unittest.main()
