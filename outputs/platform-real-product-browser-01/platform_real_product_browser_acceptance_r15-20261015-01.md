# PLATFORM-REAL-PRODUCT-BROWSER-01 公网同步与真实产品组件浏览器验收

- 运行 ID：`r15-20261015-01`
- 状态：`failed`
- 开始：2026-10-15T09:07:54.188Z
- 结束：2026-10-15T09:09:13.625Z
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
| browser_renderer_retry | passed | retried after transient Edge renderer connection reset |
| product_review_evidence_case | passed | review=1, evidence=d0f19cba6e6545ae8fc959ea3f49362d, case=faaaa5139f864b2a98ee4388edb41f99, candidate=49bafc7526163f31cccf224badc44270690c1c19e2504b3d19fa0d495701fd1e |
| platform_real_product_browser_boundary | failed | page.waitForEvent: Timeout 30000ms exceeded while waiting for event "download"
=========================== logs ===========================
waiting for event "download"
============================================================
    at downloadText (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:216:46)
    at exerciseProductReports (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:399:26)
    at async main (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:556:5)
    at async file:///E:/%E7%BD%91%E5%AE%89/CyberSecurity-Innovation-Audit/scripts/platform_real_product_browser_acceptance.mjs:900:1 |

## 公网网络动作与 effective URL

| 动作 | 目的 | 请求 URL | effective URL | 状态 | result SHA-256 |
|---|---|---|---|---|---|


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
    "job_id": "0baeaa9895a34cdcab5c6bf2d47543ef",
    "commit": "e663b47013d534a56165ab7467fbb3e14bf7172b",
    "tree": "5037e995cb4f3f29d54307b6e0fbf352cc9d6252",
    "sha256": "fd0d5c408cf605d93d43486315ebebfa6cad2b10966296b15eef1d90f37eac38",
    "status": "completed_with_limitations",
    "diagnostic_count": 10,
    "candidate_evidence_level": "candidate/unassessed"
  },
  "review_evidence_case": {
    "case_id": "faaaa5139f864b2a98ee4388edb41f99",
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
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.platform_real_product_browser_seed --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r15-20261015-01'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r15-20261015-01/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8877"
wsl.exe -d Ubuntu-22.04 -- bash -lc "kill 1104 2>/dev/null || true"
```

## 文件与 SHA-256

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| .codex-review-tmp/platform-real-product-browser-r15-20261015-01/data/artifacts/0baeaa9895a34cdcab5c6bf2d47543ef/report.json | 134761 | fd0d5c408cf605d93d43486315ebebfa6cad2b10966296b15eef1d90f37eac38 |
| .codex-review-tmp/platform-real-product-browser-r15-20261015-01/data/artifacts/0baeaa9895a34cdcab5c6bf2d47543ef/report.md | 11663 | 263fdfdb8b6e16d896f91f80745db227166080ee56c533ccfecd6643fe716740 |
| .codex-review-tmp/platform-real-product-browser-r15-20261015-01/seed.json | 3627 | 7535326e49d2e0ad8cca21c542379adc35c19895796a275451aa4f9c2e711c85 |

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
