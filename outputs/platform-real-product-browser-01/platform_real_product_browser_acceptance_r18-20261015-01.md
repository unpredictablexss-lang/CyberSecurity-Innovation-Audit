# PLATFORM-REAL-PRODUCT-BROWSER-01 公网同步与真实产品组件浏览器验收

- 运行 ID：`r18-20261015-01`
- 状态：`failed`
- 开始：2026-10-15T09:20:57.449Z
- 结束：2026-10-15T09:21:41.185Z
- Backend HEAD：`cda936a0c837575e59436118970238015d6fc56c`
- Backend source SHA-256：`8849b39d08a4f24c825062ca556b13cf2540ca27d9dfb2cf0220d4fcab64e6d0`
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
| platform_real_product_browser_boundary | failed | locator.click: Timeout 30000ms exceeded.
Call log:
[2m  - waiting for locator('.ant-modal button.ant-btn-primary')[22m
[2m    - locator resolved to <button type="button" class="ant-btn css-1cowar7 ant-btn-primary ant-btn-color-primary ant-btn-variant-solid">…</button>[22m
[2m  - attempting click action[22m
[2m    - waiting for element to be visible, enabled and stable[22m
[2m    - element is visible, enabled and stable[22m
[2m    - scrolling into view if needed[22m
[2m    - done scrolling[22m
[2m    - performing click action[22m
[2m    - <input readonly value="" id="case_id" type="search" role="combobox" unselectable="on" autocomplete="off" aria-expanded="false" aria-haspopup="listbox" aria-owns="case_id_list" aria-autocomplete="list" aria-controls="case_id_list" class="ant-select-selection-search-input"/> from <div class="ant-modal-body">…</div> subtree intercepts pointer events[22m
[2m  - retrying click action[22m
[2m    - waiting for element to be visible, enabled and stable[22m

    at createProductReviewEvidenceCase (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:337:59)
    at async main (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:560:19)
    at async file:///E:/%E7%BD%91%E5%AE%89/CyberSecurity-Innovation-Audit/scripts/platform_real_product_browser_acceptance.mjs:905:1 |

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
    "job_id": "0bb820794d194ae2ab134795850361f6",
    "commit": "e663b47013d534a56165ab7467fbb3e14bf7172b",
    "tree": "5037e995cb4f3f29d54307b6e0fbf352cc9d6252",
    "sha256": "b4c955fdbf0f5b56fdee7f9144ef8dd6ddc81c986191b6bf6d9178b15e78e4bd",
    "status": "completed_with_limitations",
    "diagnostic_count": 10,
    "candidate_evidence_level": "candidate/unassessed"
  },
  "review_evidence_case": null,
  "validation_queue": null
}
```

## exact command

```text
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && echo WSL_READY"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.platform_real_product_browser_seed --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r18-20261015-01'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r18-20261015-01/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8877"
wsl.exe -d Ubuntu-22.04 -- bash -lc "kill 1112 2>/dev/null || true"
```

## 文件与 SHA-256

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| .codex-review-tmp/platform-real-product-browser-r18-20261015-01/data/artifacts/0bb820794d194ae2ab134795850361f6/report.json | 134760 | b4c955fdbf0f5b56fdee7f9144ef8dd6ddc81c986191b6bf6d9178b15e78e4bd |
| .codex-review-tmp/platform-real-product-browser-r18-20261015-01/data/artifacts/0bb820794d194ae2ab134795850361f6/report.md | 11663 | 263fdfdb8b6e16d896f91f80745db227166080ee56c533ccfecd6643fe716740 |
| .codex-review-tmp/platform-real-product-browser-r18-20261015-01/seed.json | 3627 | d8c999ce1b35bb4f8ab8963e23384e8f7c792b0e2a969251dc1288da650c88ef |

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
