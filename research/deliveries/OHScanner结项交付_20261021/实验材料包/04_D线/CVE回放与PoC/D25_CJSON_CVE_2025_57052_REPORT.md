# D25: cJSON CVE-2025-57052 rule, component PoC, and fix review

Date: 2026-10-19
Detector: `ohscanner.known_disclosed_cves` 0.6.0
Scope: pinned upstream cJSON source pair; product status remains unknown

## Finding and upstream fix

The upstream fix commit `74e1ff4994aa4139126967f6d289b675b4b36fef` explicitly says it fixes CVE-2025-57052. Its parent is `8f2beb57ddad1f94bed899790b00f46df893ccac`. In `cJSON_Utils.c:285`, the vulnerable loop checks `pointer[0] <= '9'` on every iteration while parsing `pointer[position]`; once the first character is a digit, later non-digit bytes can be accumulated as digits. The fix changes that condition to `pointer[position] <= '9'`. The NVD record lists cJSON 1.5.0 through 1.7.18 as affected.

## Static rule and source-bound result

Detector 0.6.0 now recognizes this exact function-local root cause and requires the same loop to accumulate `pointer[position]`. It does not match the fixed expression or an unrelated `pointer[0]` check outside the function.

The direct first-party detector run used the complete `cJSON_Utils.c` file at each pinned commit, with its Git blob and SHA-256 checked by the replay script. It reported CVE-2025-57052 at line 285 on the parent source and no such candidate on the fix commit. The parent source also contains a separate CVE-2026-67215 candidate; this report does not reassess that rule.

## Component PoC

The committed harness uses only the synthetic JSON array `["public-0","public-1","D_SYNTHETIC_SECRET"]` and malformed JSON Pointer `/1844674407370955160B`. In the vulnerable source, the wrapped array index resolves to element 2 and returns the synthetic marker. In the fixed source, the non-digit suffix is rejected and the pointer resolves to null. Both binaries were compiled from the pinned cJSON files and run in rootless user, mount, and network namespaces. This demonstrates the component API behavior; it does not demonstrate memory corruption, a product caller, or OpenHarmony data exposure.

Reproduce offline after obtaining the exact upstream files in two directories:

```bash
.venv-web/bin/python research/data_sensitive/d25_cjson_cve_2025_57052_replay.py \
  --before-source-dir /path/to/cjson-at-8f2beb5 \
  --after-source-dir /path/to/cjson-at-74e1ff4
```

The script verifies Git blob SHA-1 and SHA-256 for `cJSON_Utils.c`, `cJSON.c`, `cJSON.h`, and `cJSON_Utils.h`; it has no network or checkout behavior. Machine-readable observations and hashes are in `D25_CJSON_CVE_2025_57052_REPLAY.json`.

## Remediation and product conclusion

For a product that includes an affected cJSON revision, upgrade to a release containing the upstream fix or apply the exact one-line correction and add a regression asserting that a digit-leading array index followed by a non-digit is rejected. Rebuild and rescan the exact product dependency before claiming remediation.

The public upstream issue and component behavior are established. Whether any OpenHarmony product build includes the affected cJSON code, accepts attacker-controlled JSON Pointer input, or exposes protected data through this API remains unknown. No affected OpenHarmony release, product PoC, or product fix validation is claimed; `validated_vulnerability=0`.

## References

- Upstream fix commit（文件引用：https://github.com/DaveGamble/cJSON/commit/74e1ff4994aa4139126967f6d289b675b4b36fef）
- Upstream fix patch（文件引用：https://github.com/DaveGamble/cJSON/commit/74e1ff4994aa4139126967f6d289b675b4b36fef.patch）
- NVD CVE-2025-57052 record（文件引用：https://nvd.nist.gov/vuln/detail/cve-2025-57052）
