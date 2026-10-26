# Upstream source sync attempt

On 2026-10-19, an explicit, depth-1 Git fetch was attempted in an isolated bare repository at `D:\openHarmonyScanner\tmp\libpng-upstream-pins-20261019.git` for official tags `v1.6.55` and `v1.6.56` from `https://github.com/pnggroup/libpng.git`.

Exact command:

```powershell
git --git-dir=$repo fetch --no-tags --depth=1 origin refs/tags/v1.6.55:refs/tags/v1.6.55 refs/tags/v1.6.56:refs/tags/v1.6.56
```

Result: failed to connect to `github.com:443` after 21.1 seconds. No tag refs were fetched; no scan used this empty bare repository. The full upstream fix commit identities and official advisory details were independently verified from GitHub web pages and are recorded in `coverage_ledger_20261019.json`, but a fixed source checkout is still required for a paired production scan.
