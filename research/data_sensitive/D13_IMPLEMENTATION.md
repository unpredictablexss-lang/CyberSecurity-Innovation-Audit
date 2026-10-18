# D13 source Git object verification

## Result

The D4 source manifest was verified against the actual Git commit and tree objects for openharmony/communication_dsoftbus. Both pinned commits and tree IDs match the manifest. All 44 listed source files (22 at each revision) resolve from their pinned commit:path and match the manifest Git blob SHA-1, SHA-256, and byte size. The final verifier run had GIT_NO_LAZY_FETCH=1, so it did not retrieve missing objects while checking.

The missing file contents were retrieved only from the manifest-pinned raw GitHub commit URLs and inserted into an isolated partial clone with git hash-object -w; every downloaded file was digest-checked before insertion. No upstream source files were copied into the OHScanner repository. The G-drive mirror was not accessed.

## Historical source evidence

- Before commit: d33177135ec6c6aaf4a4c42de1f6878652b330e3, tree 18e92bf9aaf515b182240309ed1a4a12dd2b2d03, authored 2022-03-29.
- After commit: 63efce3ff7f2708527eb29216decaf5fe2dc33d0, tree 13fa948bd917684af7fd8e7b8c3f59b6943e1647, parent is the before commit, authored 2022-03-30.
- The later commit subject is "Remove unused sensitive prints".

This proves the exact source snapshot and historical change message. It does not prove that a security advisory was issued, that the change was a security fix, that a product release shipped either revision, or that a vulnerable product behavior was exploitable. The existing historical replay remains blocked by partial parsing and does not change validated_vulnerability=0.

## Reproduction

From the repository root:

    python3 research/data_sensitive/d13_verify_git_objects.py --git-repo /path/to/communication_dsoftbus/.git

The default is offline. To populate a partial clone with only the manifest-pinned file contents first, explicitly add --fetch-missing; the script validates SHA-1/SHA-256/size before storing each blob and then repeats verification with lazy fetch disabled.

The verifier writes D13_SOURCE_GIT_OBJECT_VERIFICATION.json. D13_VALIDATION.json records the 55-test data suite, 889-test full Python suite (884 passed, 5 skipped), compileall, and diff-check results. Its unit tests use an isolated temporary Git repository and cover a matching two-revision manifest plus digest mismatch rejection.
