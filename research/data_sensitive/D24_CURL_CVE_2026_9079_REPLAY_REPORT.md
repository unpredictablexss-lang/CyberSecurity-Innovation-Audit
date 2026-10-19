# D24: curl CVE-2026-9079 backport-aware rule review

Date: 2026-10-19
Detector: ohscanner.known_disclosed_cves 0.5.0
Result: rule family covered; pinned source shows fix-equivalent code; product status unknown

## Advisory and root cause

The curl security advisory lists libcurl 8.8.0-8.20.0 as affected and fixes the issue in commit 88c7e16cceec816a2df45c89. The bug is that clearing proxy credentials can leave the prior username/password in the easy handle for later transfers. The upstream fix frees both stored strings after a successful option parse even when the newly parsed u or p is null. See the [official CVE advisory](https://curl.se/docs/CVE-2026-9079.html) and [upstream fix patch](https://github.com/curl/curl/commit/88c7e16cceec816a2df45c89.patch).

## Scanner change

Detector 0.5.0 adds a function-local rule for setopt_cptr_proxy and the CURLOPT_PROXYUSERPWD case. It produces a candidate when stored username/password are freed only under if (!result && u) / if (!result && p), so passing NULL can skip clearing the prior component. Tests cover this vulnerable shape and the upstream fixed shape. This is a narrow root-cause signature; it does not infer actual handle reuse or product disclosure.

## Pinned G-drive source replay

The fixed repository commit is 1386bb128bb060b284309397b97adcaaec21c003, tree b96addd5821a610eb0ceacc7e7a83deda64690c2. The scoped source includes include/curl/curlver.h (version 8.8.0) and lib/setopt.c (Git blob a1a90d1eb89bf212919964e34f93a865af2aa359, SHA-256 67e236893bdb317cb0e7363ce10da46dda1049ab430990f2856aec0bdea145c1). In the option branch at lines 1658-1663, both stored values are cleared under if (!result), then the username is conditionally decoded; this matches the fix behavior in the upstream patch. The public Runner replay was repeated twice and produced no CVE-2026-9079 candidate, with identical snapshot and coverage.

The run is still blocked with partial file coverage, so the absence of a finding does not certify the file or repository as safe. The source shape is evidence of a fix-equivalent change; the exact cherry-pick ancestry was not established by this scan.

## Verification and limits

- Vulnerable-shape and fixed-shape regression controls pass in the detector test suite.
- Pinned Runner replay: same exact commit and candidate identity/coverage across two runs; no CVE-2026-9079 candidate.
- No dynamic test of proxy handle reuse was rerun in this D24 experiment.
- No OpenHarmony product build inclusion, caller-controlled transfer sequence, exposed credential, affected release, or product impact is established. validated_vulnerability=0.
- The positive test shape is derived from the upstream fix diff; it is not an independent holdout.

## Fix recommendation

For affected unpatched libcurl builds, upgrade to 8.21.0 or apply the upstream fix and rebuild. Where upgrading is not immediately possible, avoid reusing easy handles while changing proxy credentials. Confirm the exact built libcurl and any downstream backports before reporting affected versions. These are upstream recommendations, not a product-specific patch validation.
