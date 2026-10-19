from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_performance_admission.py")
t = p.read_text(encoding="utf-8")
t = t.replace('target_id="c11-performance-admission"', 'target_id="current-component:c11/in-memory-fixed-source"')
t = t.replace('return b"".join(f"100644 blob {s.oid}\\t{s.path}\\0".encode("utf-8") for s in sources)',
              'return b"".join(f"100644 blob {s.oid} {len(s.data)}\\t{s.path}\\0".encode("utf-8") for s in sources)')
t = t.replace('        sources = load_git_sources(ROOT, BASE_COMMIT, ("src",))',
              '        _, _, sources, _ = load_git_sources(ROOT, BASE_COMMIT, ("src",))')
t = t.replace('if case in {"full_no_cache", "shard_no_cache", "cache_cold", "cache_warm", "limit_2000", "limit_total_32mib"}:',
              'if case in {"full_no_cache", "shard_no_cache", "cache_cold", "cache_warm", "limit_1999", "limit_2000", "limit_2001", "limit_total_32mib", "limit_total_32mib_plus_1", "limit_blob_exact", "limit_blob_plus_1"}:')
t = t.replace('        elif case == "limit_2000":\n            def fn():\n                return limit_case([1024] * 2000)\n        elif case == "limit_total_32mib":\n            def fn():\n                return limit_case([1024 * 1024] * 32)',
'''        elif case == "limit_1999":
            def fn():
                return limit_case([1024] * 1999)
        elif case == "limit_2000":
            def fn():
                return limit_case([1024] * 2000)
        elif case == "limit_2001":
            def fn():
                return limit_case([1024] * 2001)
        elif case == "limit_total_32mib":
            def fn():
                return limit_case([1024 * 1024] * 32)
        elif case == "limit_total_32mib_plus_1":
            def fn():
                return limit_case([1024 * 1024] * 32 + [1])
        elif case == "limit_blob_exact":
            def fn():
                return limit_case([1024 * 1024, 1024])
        elif case == "limit_blob_plus_1":
            def fn():
                return limit_case([1024 * 1024 + 1, 1024])''')
t = t.replace('        ("limit_2000", 3), ("limit_total_32mib", 3),',
'''        ("limit_1999", 3), ("limit_2000", 3), ("limit_2001", 3),
        ("limit_total_32mib", 3), ("limit_total_32mib_plus_1", 3),
        ("limit_blob_exact", 3), ("limit_blob_plus_1", 3),''')
p.write_text(t, encoding="utf-8")
print("patched")
