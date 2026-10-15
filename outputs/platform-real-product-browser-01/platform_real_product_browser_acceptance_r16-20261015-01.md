# PLATFORM-REAL-PRODUCT-BROWSER-01 公网同步与真实产品组件浏览器验收

- 运行 ID：`r16-20261015-01`
- 状态：`failed`
- 开始：2026-10-15T09:10:35.432Z
- 结束：2026-10-15T09:11:26.171Z
- Backend HEAD：`cda936a0c837575e59436118970238015d6fc56c`
- Backend source SHA-256：`5b790322f57f10580ccaa9e9463a504e84c776576386417686574f3598b1f045`
- Product：`/home/audit/openharmony-audit/ipc-research/repos/inputmethod_imf` @ `e663b47013d534a56165ab7467fbb3e14bf7172b` / tree `5037e995cb4f3f29d54307b6e0fbf352cc9d6252`
- Component：`/home/audit/openharmony-targets/commonlibrary_c_utils` @ `b807d3dadb7dbb7639fe85b3a5f72da18d318da2` / tree `52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d`
- Browser：`155.0.4283.45`
- Edge executable：`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
- Dirty worktree 文件数（验收结束时 Git 状态）：`51`

## 检查

| 检查 | 状态 | 详情 |
|---|---|---|
| product_fixed_binding_and_coverage | passed | commit=e663b47013d534a56165ab7467fbb3e14bf7172b, tree=5037e995cb4f3f29d54307b6e0fbf352cc9d6252, detector=ohscanner.interface.ipc, coverage=partial |
| product_candidate_cluster_expand | passed | 2 fixed-source candidate identities remain addressable |
| product_review_evidence_case | passed | review=1, evidence=eaababa8de8e436086f41067394bd7a5, case=ce64f26dab75433987eed4a40512cb6c, candidate=49bafc7526163f31cccf224badc44270690c1c19e2504b3d19fa0d495701fd1e |
| product_report_and_case_downloads | passed | 9c800049a59f434b9d3551d6f9ecebb4_report.json, 9c800049a59f434b9d3551d6f9ecebb4_report.md, ohscanner-case-ce64f26dab75433987eed4a40512cb6c.json, ohscanner-case-ce64f26dab75433987eed4a40512cb6c.md |
| platform_real_product_browser_boundary | failed | Error: effective URL audit failed for https://github.com/openharmony/commonlibrary_c_utils.git: curl: (28) Operation timed out after 30005 milliseconds with 0 bytes received

    at auditEffectiveUrl (file:///E:/%E7%BD%91%E5%AE%89/CyberSecurity-Innovation-Audit/scripts/platform_real_product_browser_acceptance.mjs:254:11)
    at submitPublicSync (file:///E:/%E7%BD%91%E5%AE%89/CyberSecurity-Innovation-Audit/scripts/platform_real_product_browser_acceptance.mjs:259:17)
    at main (file:///E:/%E7%BD%91%E5%AE%89/CyberSecurity-Innovation-Audit/scripts/platform_real_product_browser_acceptance.mjs:569:31)
    at async file:///E:/%E7%BD%91%E5%AE%89/CyberSecurity-Innovation-Audit/scripts/platform_real_product_browser_acceptance.mjs:901:1 |

## 公网网络动作与 effective URL

| 动作 | 目的 | 请求 URL | effective URL | 状态 | result SHA-256 |
|---|---|---|---|---|---|
| public HTTPS effective-URL audit (HEAD, redirects followed) | PLATFORM-REAL-PRODUCT-BROWSER-01 GitHub clone | https://github.com/openharmony/commonlibrary_c_utils.git | https://github.com/openharmony/commonlibrary_c_utils.git |  |  |

## 固定产品组件审计边界

```json
{
  "scope": {
    "include_paths": [
      "."
    ],
    "mode": "repository_snapshot"
  },
  "detector": {
    "evidence_level": "candidate/unassessed",
    "id": "ohscanner.interface.ipc",
    "version": "0.5.0"
  },
  "coverage": {
    "analyzed_files": 62,
    "file_outcomes": null,
    "limitations": [],
    "status": "partial"
  },
  "report": {
    "job_id": "9c800049a59f434b9d3551d6f9ecebb4",
    "commit": "e663b47013d534a56165ab7467fbb3e14bf7172b",
    "tree": "5037e995cb4f3f29d54307b6e0fbf352cc9d6252",
    "sha256": "db2ab6d870c376f3c836bcde2c1404fccebcc85c5f7c8ca4088ce3a5be8fdfd4",
    "status": "completed_with_limitations",
    "diagnostic_count": 10,
    "candidate_evidence_level": "candidate/unassessed"
  },
  "review_evidence_case": {
    "case_id": "ce64f26dab75433987eed4a40512cb6c",
    "case_title": "Real product component audit case",
    "reviewed_candidate_id": "49bafc7526163f31cccf224badc44270690c1c19e2504b3d19fa0d495701fd1e",
    "review_history_required_after_restart": true,
    "supplemental_evidence_required_after_restart": true
  },
  "validation_queue": null
}
```

## exact command

```text
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && echo WSL_READY"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.platform_real_product_browser_seed --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r16-20261015-01'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r16-20261015-01/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8877"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r16-20261015-01/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets:/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r16-20261015-01/data/repo-cache' .venv-web/bin/python -m src.workbench.operation_worker"
curl.exe -sS -L -I -o NUL --max-time 30 -w "%{http_code}	%{url_effective}	%{num_redirects}" https://github.com/openharmony/commonlibrary_c_utils.git
wsl.exe -d Ubuntu-22.04 -- bash -lc "kill 1173 2>/dev/null || true"
wsl.exe -d Ubuntu-22.04 -- bash -lc "kill 1118 2>/dev/null || true"
```

## 文件与 SHA-256

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| .codex-review-tmp/platform-real-product-browser-r16-20261015-01/data/artifacts/9c800049a59f434b9d3551d6f9ecebb4/report.json | 134760 | db2ab6d870c376f3c836bcde2c1404fccebcc85c5f7c8ca4088ce3a5be8fdfd4 |
| .codex-review-tmp/platform-real-product-browser-r16-20261015-01/data/artifacts/9c800049a59f434b9d3551d6f9ecebb4/report.md | 11663 | 263fdfdb8b6e16d896f91f80745db227166080ee56c533ccfecd6643fe716740 |
| .codex-review-tmp/platform-real-product-browser-r16-20261015-01/seed.json | 3627 | 14824b1b56a15f78c8d341b1bacc2a28c91103d6997b7dfccc60fdb01029768b |

## 环境

```json
{
  "node": "v24.19.0",
  "playwright_core_path": "C:\\Users\\work_work\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\node\\node_modules\\playwright-core",
  "edge_executable": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "edge_version": "��������������Ự�д򿪡�",
  "browser_version": "155.0.4283.45",
  "git_version": "git version 2.55.0.windows.5",
  "curl_version": "curl 8.21.0 (Windows) libcurl/8.21.0 Schannel zlib/1.3.2 WinIDN WinLDAP",
  "credential_environment_values_recorded": false
}
```

## 限制与 unknown

- Public Git tests are explicit anonymous clone/fetch/effective-URL audits, not multi-user or public-network deployment acceptance.
- The real product component browser audit uses fixed Git objects; it does not modify or reset the dirty product checkout.
- Candidate review, evidence and case reports remain candidate/unassessed and are not product vulnerability confirmation.
- Docker validation queue state is component-harness evidence only; product reachability, privilege, CIA impact and exploitability remain unknown.
- No production service was attacked; network actions were limited to public Git read operations and HEAD effective-URL audits.
- unknown/unverified：multi-user deployment
- unknown/unverified：public Workbench deployment
- unknown/unverified：product-level vulnerability confirmation
- unknown/unverified：Precision/Recall or detector accuracy

本验收证明公网 Git 显式同步边界与固定真实产品组件的浏览器审计流程；不构成产品漏洞确认、多用户部署验收或检测准确率结论。
