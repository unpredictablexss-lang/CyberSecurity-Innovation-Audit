# WEB-SOURCE-SYNC-01 浏览器 source sync 验收

- 运行 ID：`web-source-sync-01-r2`
- 状态：`passed`
- 失败阶段：无
- 开始：2026-10-15T06:46:16.822Z
- 结束：2026-10-15T06:48:04.090Z
- HEAD：`0e94ceafab1b2d79547bdf71c86e26e8b42a6b48`
- Remote：`https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`
- Dirty 文件数：42

## 检查

| 检查 | 状态 | 详情 |
|---|---|---|
| candidate_cluster_expand | passed | 2 original candidate IDs remain addressable |
| scan_report_downloads | passed | b5282906fa624b5297894428681a6d2a_report.json, b5282906fa624b5297894428681a6d2a_report.md |
| review_and_evidence_ui | passed | append-only review and source-bound evidence saved from candidate drawer |
| case_report_downloads | passed | ohscanner-case-74be2ac6d2ce4cc3820a4871d269b6ed.json, ohscanner-case-74be2ac6d2ce4cc3820a4871d269b6ed.md |
| operation_cancel | passed | queued source_sync cancelled from browser |
| operation_restart_recovery | passed | running operation became interrupted without publishing a partial result |
| revision_range | passed | 4e564ac99ee8..5d59e5f4a5fb |
| date_range | passed | committer-date [start,end) selected two fixed commits |
| version_matrix | passed | two fixed SHA observations compared; impact remains unknown |
| source_sync | passed | explicit sync completed; remote refs=1 |
| operation_timeout | passed | 10-second source-sync hard deadline published timed_out without a partial result |
| candidate_cluster_expand | passed | 2 original candidate IDs remain addressable |
| case_report_downloads | passed | ohscanner-case-74be2ac6d2ce4cc3820a4871d269b6ed.json, ohscanner-case-74be2ac6d2ce4cc3820a4871d269b6ed.md |
| restart_persistence | passed | operation, review, evidence, report hash and case report remained recoverable |
| browser_full_chain | passed | browser UI drove repository operation planning, cancellation/deadline, cluster review and downloads |

## 受控网络动作

| 动作 | 仓库 | 请求 URL | 实际 URL | 目的 |
|---|---|---|---|---|
| controlled loopback HTTPS Git clone/fetch under approved URL rewrite | openharmony/c_utils | https://github.com/openharmony/c_utils.git | https://127.0.0.1:9443/c_utils.git | browser source-sync acceptance |
| controlled loopback HTTPS Git fetch with hard deadline | openharmony/ace_napi | https://github.com/openharmony/ace_napi.git | https://127.0.0.1:9444/ace_napi.git | browser timeout acceptance |

## Source sync 过程诊断

```json
{
  "symptom": "browser_full_chain / source sync: Operation child exited 1",
  "mechanism": "An uncaught source-sync Git subprocess exception escaped the operation child and was reduced by the parent to a generic child exit error.",
  "contributing_conditions": [
    "Git subprocess execution inherited the caller working directory and GIT_CONFIG_* environment.",
    "The Git subprocess timeout equaled the outer hard deadline, allowing timeout-versus-supervisor races.",
    "stdout/stderr and failure stage were not committed as structured source-sync evidence."
  ],
  "exact_original_stderr": "unknown; the originally failed run artifacts were not preserved in the supplied checkout",
  "fix": [
    "Run source-sync Git from an isolated temporary cwd and remove inherited GIT_CONFIG_* values while retaining target-local fixture URL rewrite and CA configuration.",
    "Make the outer operation Worker the sole hard-deadline authority.",
    "Persist git-process.json and child-error.json with command, cwd, exit code, stdout, stderr and stage."
  ]
}
```

```json
{
  "git_process_records": [
    {
      "command": [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "credential.helper=",
        "-C",
        "/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/data/repo-cache/c_utils",
        "fetch",
        "--prune",
        "--tags",
        "https://github.com/openharmony/c_utils.git",
        "+refs/heads/*:refs/remotes/origin/*"
      ],
      "cwd": "/tmp",
      "exit_code": 0,
      "stderr": "From https://127.0.0.1:9443/c_utils\n * [new branch]      master     -> origin/master\n",
      "stdout": "",
      "supervisor_deadline": "outer operation Worker",
      "timeout_seconds": 300
    }
  ],
  "preserved": [
    "loopback HTTPS fixture",
    "target-local URL rewrite",
    "fixture CA certificate",
    "network action records"
  ]
}
```

## 操作与子进程证据

每个 source sync 的 `git-process.json` 保留命令、cwd、exit code、stdout、stderr；`worker.log` 保留 operation child 输出，完整记录位于本次 data root。

## 文件与哈希

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| data/operations/2d5fb147057b441f96021e9e1d5cb469/child-result.json | 1829 | df0237059295fba6a64982174f94dfbccb00608231efebec243de3e8a9b784df |
| data/operations/2d5fb147057b441f96021e9e1d5cb469/result.json | 2204 | 19ab968914475bd0540262a14d121d6b3982163526bc8f4073acdb081bbfc49d |
| data/operations/2d5fb147057b441f96021e9e1d5cb469/worker.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| data/operations/42e6f034268b4b1683f76d70dd10d4aa/worker.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| data/operations/624550270f584730b1a7b8446fbe3be2/child-result.json | 1365 | 522697c53eaba6bf760dc5f500ae59a86832646e8b308aa3ce96d6bd007baadb |
| data/operations/624550270f584730b1a7b8446fbe3be2/result.json | 1674 | dbdce6fc1c41bee82771271e90450c1cb9dadf38628d253ab8228dabe0d7e741 |
| data/operations/624550270f584730b1a7b8446fbe3be2/worker.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| data/operations/b1eb14c2ad6b454a9320c3468fe89377/child-result.json | 1049 | 99a764808ca6972ffa998923a02d63e8f2ee4b0bf9fa39e2b47e4c7ac64d54b4 |
| data/operations/b1eb14c2ad6b454a9320c3468fe89377/git-process.json | 707 | 5953cd5d16aa05d2a34a6997f0192789f0fc494e068943d0b4abcfa391f6cc2e |
| data/operations/b1eb14c2ad6b454a9320c3468fe89377/result.json | 1188 | 57fe9e6fdb2fe2e3c029f3f6fc94cd72f5421d0961f01d80c24b02f718c8669e |
| data/operations/b1eb14c2ad6b454a9320c3468fe89377/worker.log | 648 | 744ce05584cbbb336967fc41c8433022e08152e144a0193acabb63e86434cc0d |
| data/operations/d131124f310e4384be6942f4e3e246e1/child-result.json | 1872 | cd23a5736e3c3fca8e1adf3e6789ca363e37bf904b58b70fd2639a7f8c854c02 |
| data/operations/d131124f310e4384be6942f4e3e246e1/result.json | 2443 | 1be2a19567e4de3040ac72eb212753dcb56c50ce6ba8a62de314e41cd3adeae4 |
| data/operations/d131124f310e4384be6942f4e3e246e1/worker.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| git-fixture/cert.pem | 1135 | bac99e9381c2a79f89a1f33cedf88921b1a94ee576330d48a5d1170b21427ec9 |
| seed.json | 1573 | 46aa89a95a363e45c9dc165496b54ceb3a42a21fa6ac5e07062a267550343d9c |

## 命令

```text
node scripts/browser_acceptance.mjs
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.browser_acceptance_seed --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.git_https_fixture_server --port 9443 --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/git-fixture'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.git_https_fixture_server --port 9444 --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/git-fixture' --slow"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/data' OHSCANNER_TARGET_ROOTS='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8876"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/data' OHSCANNER_TARGET_ROOTS='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/targets' .venv-web/bin/python -m src.workbench.worker"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/data' OHSCANNER_TARGET_ROOTS='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/targets' .venv-web/bin/python -m src.workbench.operation_worker"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/data' OHSCANNER_TARGET_ROOTS='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r2/targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8876"
```

## 环境

```json
{
  "host": "Windows 11 + WSL2 Ubuntu 22.04",
  "browser": "Microsoft Edge headless via playwright-core",
  "backend": "/mnt/e/网安/CyberSecurity-Innovation-Audit @ current working tree",
  "data_root": "E:\\网安\\CyberSecurity-Innovation-Audit\\.codex-review-tmp\\browser-acceptance-web-source-sync-01-r2",
  "node": "v24.19.0",
  "playwright_core_path": "playwright-core",
  "edge_executable": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "wsl_distribution": "Ubuntu-22.04",
  "wsl_git": "2.34.1",
  "wsl_python": "3.10.12"
}
```

## 失败与 unknown

- 失败：无
- unknown/unverified：multi-user and public-network deployment
- unknown/unverified：Docker runtime validation
- unknown/unverified：product reachability and CIA impact

## 限制

- Browser acceptance covers local workbench behavior only; it is not vulnerability accuracy or product security validation.
- Version matrix reports static candidate observations with impact unknown.
- The timeout control uses a deterministic loopback HTTPS Git endpoint and does not create a complete repository.
- Public-network GitHub/Gitee/GitCode synchronization remains unverified.

本验收只证明本地工作台浏览器流程和受控 loopback source sync 行为，不解释为漏洞准确率或产品安全验证。
