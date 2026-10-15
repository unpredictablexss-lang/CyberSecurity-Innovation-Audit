# WEB-SOURCE-SYNC-01 浏览器 source sync 验收

- 运行 ID：`web-source-sync-01-r1`
- 状态：`passed`
- 失败阶段：无
- 开始：2026-10-15T06:37:52.068Z
- 结束：2026-10-15T06:39:40.550Z
- HEAD：`0e94ceafab1b2d79547bdf71c86e26e8b42a6b48`
- Remote：`https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`
- Dirty 文件数：41

## 检查

| 检查 | 状态 | 详情 |
|---|---|---|
| candidate_cluster_expand | passed | 2 original candidate IDs remain addressable |
| scan_report_downloads | passed | 814b99b91c3c49389d83ccd1a8074859_report.json, 814b99b91c3c49389d83ccd1a8074859_report.md |
| review_and_evidence_ui | passed | append-only review and source-bound evidence saved from candidate drawer |
| case_report_downloads | passed | ohscanner-case-c87b1873a9f049a8bc358fdd4c474326.json, ohscanner-case-c87b1873a9f049a8bc358fdd4c474326.md |
| operation_cancel | passed | queued source_sync cancelled from browser |
| operation_restart_recovery | passed | running operation became interrupted without publishing a partial result |
| revision_range | passed | 4e564ac99ee8..5d59e5f4a5fb |
| date_range | passed | committer-date [start,end) selected two fixed commits |
| version_matrix | passed | two fixed SHA observations compared; impact remains unknown |
| source_sync | passed | explicit sync completed; remote refs=1 |
| operation_timeout | passed | 10-second source-sync hard deadline published timed_out without a partial result |
| candidate_cluster_expand | passed | 2 original candidate IDs remain addressable |
| case_report_downloads | passed | ohscanner-case-c87b1873a9f049a8bc358fdd4c474326.json, ohscanner-case-c87b1873a9f049a8bc358fdd4c474326.md |
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
        "/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/data/repo-cache/c_utils",
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
| data/operations/37d010d2af2d4346a5455a4eede6d76c/child-result.json | 1365 | 087d67bcc3fc11db195fbba5d85ecc670fbb7e1962e6a5fbd5a8989115fc16bd |
| data/operations/37d010d2af2d4346a5455a4eede6d76c/result.json | 1674 | 1b29a7fcb7c032454a37ddade5dff16c765a504b80a4736915a8f4409747eb59 |
| data/operations/37d010d2af2d4346a5455a4eede6d76c/worker.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| data/operations/490190026f7d4932b30a7f39fcc7104a/child-result.json | 1829 | 7a5ec1f0b38a11b3791b28e658e89c63e8e1eaf175cab41edd5afdf6359853c5 |
| data/operations/490190026f7d4932b30a7f39fcc7104a/result.json | 2204 | 3ffc514c7ac40e4e18b4e4ecc330c1a4b1e4313c65e9becf91fd647c13150994 |
| data/operations/490190026f7d4932b30a7f39fcc7104a/worker.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| data/operations/4fb58f520c494c459db6f8e9b3ca8cfc/child-result.json | 1049 | 872f27a21935860c133100ea318bb675a9ac1a2606a439ba843e1f961d0839cf |
| data/operations/4fb58f520c494c459db6f8e9b3ca8cfc/git-process.json | 707 | 2d92dee8bf46caace4aac8e9eac1ae5ac65865fc095545fae0ad17e6f938b017 |
| data/operations/4fb58f520c494c459db6f8e9b3ca8cfc/result.json | 1188 | 2fe06835abf2920b9659f482eaccd2dc25191226a3b3a4480016da6a24b0883c |
| data/operations/4fb58f520c494c459db6f8e9b3ca8cfc/worker.log | 648 | 581edb3b6d2fad683ec236c49ad15621561db6be918cc5fee0ac46bcab8a1ef1 |
| data/operations/b465bee114eb4ddda1d714436194df20/worker.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| data/operations/bde430ae79a94335a7fa9063cca5f914/child-result.json | 1872 | 8bf4a7c0bd35ee608728989eb97f3ffda28676e49286ec4457e23fc610936558 |
| data/operations/bde430ae79a94335a7fa9063cca5f914/result.json | 2443 | 6b35942deb70c10a85c03d1459c6a565872c3f9657f9ece3c251830b20f62d19 |
| data/operations/bde430ae79a94335a7fa9063cca5f914/worker.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| git-fixture/cert.pem | 1135 | 47cf9053474a31d38a59b11a3d1b92d201420d8f062f3b17c8870c8105028cb0 |
| seed.json | 1573 | b20f4e20062c87436ded67fdf0ee0130603e3ad29099351f112e6471916cb93e |

## 命令

```text
node scripts/browser_acceptance.mjs
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.browser_acceptance_seed --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.git_https_fixture_server --port 9443 --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/git-fixture'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.git_https_fixture_server --port 9444 --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/git-fixture' --slow"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/data' OHSCANNER_TARGET_ROOTS='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8876"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/data' OHSCANNER_TARGET_ROOTS='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/targets' .venv-web/bin/python -m src.workbench.worker"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/data' OHSCANNER_TARGET_ROOTS='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/targets' .venv-web/bin/python -m src.workbench.operation_worker"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/data' OHSCANNER_TARGET_ROOTS='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/browser-acceptance-web-source-sync-01-r1/targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8876"
```

## 环境

```json
{
  "host": "Windows 11 + WSL2 Ubuntu 22.04",
  "browser": "Microsoft Edge headless via playwright-core",
  "backend": "/mnt/e/网安/CyberSecurity-Innovation-Audit @ current working tree",
  "data_root": "E:\\网安\\CyberSecurity-Innovation-Audit\\.codex-review-tmp\\browser-acceptance-web-source-sync-01-r1",
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
