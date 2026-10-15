# PLATFORM-REAL-PRODUCT-BROWSER-01 公网同步与真实产品组件浏览器验收

- 运行 ID：`r10-20261015-01`
- 状态：`failed`
- 开始：2026-10-15T08:58:39.282Z
- 结束：2026-10-15T08:59:30.690Z
- Backend HEAD：`cda936a0c837575e59436118970238015d6fc56c`
- Backend source SHA-256：`5b790322f57f10580ccaa9e9463a504e84c776576386417686574f3598b1f045`
- Product：`/home/audit/openharmony-audit/ipc-research/repos/inputmethod_imf` @ `e663b47013d534a56165ab7467fbb3e14bf7172b` / tree `5037e995cb4f3f29d54307b6e0fbf352cc9d6252`
- Component：`/home/audit/openharmony-targets/commonlibrary_c_utils` @ `b807d3dadb7dbb7639fe85b3a5f72da18d318da2` / tree `52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d`
- Browser：`155.0.4283.45`
- Edge executable：`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
- Dirty worktree 文件数（验收结束时 Git 状态）：`49`

## 检查

| 检查 | 状态 | 详情 |
|---|---|---|
| product_fixed_binding_and_coverage | passed | commit=e663b47013d534a56165ab7467fbb3e14bf7172b, tree=5037e995cb4f3f29d54307b6e0fbf352cc9d6252, detector=ohscanner.interface.ipc, coverage=partial |
| product_candidate_cluster_expand | passed | 2 fixed-source candidate identities remain addressable |
| product_review_evidence_case | passed | review=1, evidence=d5b7dc74ebd24268895e82418de65520, case=89b5c76ee119480c9b5ad7f1b0335b06, candidate=49bafc7526163f31cccf224badc44270690c1c19e2504b3d19fa0d495701fd1e |
| platform_real_product_browser_boundary | failed | locator.click: Timeout 30000ms exceeded.
Call log:
[2m  - waiting for getByRole('tab', { name: '报告与产物' })[22m
[2m    - locator resolved to <div role="tab" tabindex="-1" aria-selected="false" class="ant-tabs-tab-btn" id="rc-tabs-0-tab-reports" aria-controls="rc-tabs-0-panel-reports">报告与产物</div>[22m
[2m  - attempting click action[22m
[2m    - waiting for element to be visible, enabled and stable[22m
[2m    - element is visible, enabled and stable[22m
[2m    - scrolling into view if needed[22m
[2m    - done scrolling[22m
[2m    - <div class="ant-drawer-header">…</div> from <div>…</div> subtree intercepts pointer events[22m
[2m  - retrying click action[22m
[2m    - waiting for element to be visible, enabled and stable[22m
[2m    - element is visible, enabled and stable[22m
[2m    - scrolling into view if needed[22m
[2m    - done scrolling[22m
[2m    - <div class="ant-col ant-form-item-label css-1cowar7">…</div> from <div>…</div> subtree intercepts pointer events[22m
[2m  - retrying click action[22m
[2m    - waiting 20ms[22m
[2m    - waiting for element to be visible, enabled and stable[22m
[2m    - element is visible, enabled and stable[22m
[2m    - scrolling into view if needed[22m
[2m    - done scrolling[22m
[2m    - <label for="notes" title="依据、证据位置与下一步" class="ant-form-item-required">依据、证据位置与下一步</label> from <div>…</div> subtree intercepts pointer events[22m
[2m  2 × retrying click action[22m
[2m      - waiting 100ms[22m
[2m      - waiting for element to be visible, enabled and stable[22m
[2m      - element is visible, enabled and stable[22m
[2m      - scrolling into view if needed[22m
[2m      - done scrolling[22m
[2m      - <div class="ant-drawer-header">…</div> from <div>…</div> subtree intercepts pointer events[22m
[2m  14 × retrying click action[22m
[2m       - waiting 500ms[22m
[2m       - waiting for element to be visible, enabled and stable[22m
[2m       - element is visible, enabled and stable[22m
[2m       - scrolling into view if needed[22m
[2m       - done scrolling[22m
[2m       - <div class="ant-col ant-form-item-label css-1cowar7">…</div> from <div>…</div> subtree intercepts pointer events[22m
[2m     - retrying click action[22m
[2m       - waiting 500ms[22m
[2m       - waiting for element to be visible, enabled and stable[22m
[2m       - element is visible, enabled and stable[22m
[2m       - scrolling into view if needed[22m
[2m       - done scrolling[22m
[2m       - <label for="notes" title="依据、证据位置与下一步" class="ant-form-item-required">依据、证据位置与下一步</label> from <div>…</div> subtree intercepts pointer events[22m
[2m     - retrying click action[22m
[2m       - waiting 500ms[22m
[2m       - waiting for element to be visible, enabled and stable[22m
[2m       - element is visible, enabled and stable[22m
[2m       - scrolling into view if needed[22m
[2m       - done scrolling[22m
[2m       - <div class="ant-drawer-header">…</div> from <div>…</div> subtree intercepts pointer events[22m
[2m     - retrying click action[22m
[2m       - waiting 500ms[22m
[2m       - waiting for element to be visible, enabled and stable[22m
[2m       - element is visible, enabled and stable[22m
[2m       - scrolling into view if needed[22m
[2m       - done scrolling[22m
[2m       - <div class="ant-drawer-header">…</div> from <div>…</div> subtree intercepts pointer events[22m
[2m  - retrying click action[22m
[2m    - waiting 500ms[22m

    at exerciseProductReports (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:385:50)
    at async main (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:527:5)
    at async file:///E:/%E7%BD%91%E5%AE%89/CyberSecurity-Innovation-Audit/scripts/platform_real_product_browser_acceptance.mjs:871:1 |

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
    "job_id": "4013eac498fd4c9898cbecec0bf31b24",
    "commit": "e663b47013d534a56165ab7467fbb3e14bf7172b",
    "tree": "5037e995cb4f3f29d54307b6e0fbf352cc9d6252",
    "sha256": "212352872efefc789c6dec872abbd663d915cab074aa18662000775da5fd1e2f",
    "status": "completed_with_limitations",
    "diagnostic_count": 10,
    "candidate_evidence_level": "candidate/unassessed"
  },
  "review_evidence_case": {
    "case_id": "89b5c76ee119480c9b5ad7f1b0335b06",
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
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.platform_real_product_browser_seed --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r10-20261015-01'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r10-20261015-01/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8877"
wsl.exe -d Ubuntu-22.04 -- bash -lc "kill 1106 2>/dev/null || true"
```

## 文件与 SHA-256

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| .codex-review-tmp/platform-real-product-browser-r10-20261015-01/data/artifacts/4013eac498fd4c9898cbecec0bf31b24/report.json | 134760 | 212352872efefc789c6dec872abbd663d915cab074aa18662000775da5fd1e2f |
| .codex-review-tmp/platform-real-product-browser-r10-20261015-01/data/artifacts/4013eac498fd4c9898cbecec0bf31b24/report.md | 11663 | 263fdfdb8b6e16d896f91f80745db227166080ee56c533ccfecd6643fe716740 |
| .codex-review-tmp/platform-real-product-browser-r10-20261015-01/seed.json | 3627 | 5c95dadebad61cfe1c67941376570811a939cf9cc12118bdebab5b6d9fb50b5e |

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
