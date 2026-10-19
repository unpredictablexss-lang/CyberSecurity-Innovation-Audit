# C13 focused known-vulnerability validation

Date: 2026-10-19 Asia/Shanghai
Checkout: `E:\网安\CyberSecurity-Innovation-Audit-c-line-static-20261019`
Base: `842948084660207fd64399cfd598ed93e5593dcc`

## Environment correction

Windows-linked worktrees store `.git` as a Windows path. Under WSL the tests must set both paths explicitly so pinned Git objects remain readable:

```bash
export GIT_DIR="/mnt/e/网安/CyberSecurity-Innovation-Audit/.git/worktrees/CyberSecurity-Innovation-Audit-c-line-static-20261019"
export GIT_WORK_TREE="/mnt/e/网安/CyberSecurity-Innovation-Audit-c-line-static-20261019"
cd "$GIT_WORK_TREE"
```

Without this correction, `git cat-file`/`git rev-parse` fail and tests error as external-source unavailable. That is an environment limitation, not a scanner safe result.

## Exact focused commands and results

```text
python -m unittest -v tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus
Ran 29 tests in 1.741s
OK
```

```text
python -m unittest -v tests.detectors.ark_runtime.test_c10_known_case_controls tests.detectors.ark_runtime.test_c11_alias_cross_helper tests.detectors.ark_runtime.test_c12_deep_semantics
Ran 25 tests in 0.391s
OK
```

The 29-test suite covers public disclosed CVE positive/fixed/boundary controls and the 28-row source-bound disposition corpus. The 25-test suite covers known Ark shapes plus alias/cast/helper/loop/numeric controls. All findings remain `candidate/unassessed`; these tests do not prove product reachability, CIA impact, Precision/Recall, zero FP/FN, or product safety.

## Remaining limitations

- Real Ark parent/fixed repository stores, build profile, product entry/permission/trigger/CIA and isolated PoC closure remain incomplete.
- Independent reliable truth and blind adjudication are not complete.
- GitHub push was attempted but the network reset/443 failures prevented remote publication at the time of this note.
