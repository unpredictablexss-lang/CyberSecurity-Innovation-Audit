# PLATFORM-REAL-PRODUCT-BROWSER-01 公网同步与真实产品组件浏览器验收

- 运行 ID：`r9-20261015-01`
- 状态：`failed`
- 开始：2026-10-15T08:56:16.234Z
- 结束：2026-10-15T08:56:33.115Z
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
| platform_real_product_browser_boundary | failed | locator.waitFor: Target page, context or browser has been closed
Browser logs:

<launching> C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe --disable-field-trial-config --disable-background-networking --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-back-forward-cache --disable-breakpad --disable-client-side-phishing-detection --disable-component-extensions-with-background-pages --disable-component-update --no-default-browser-check --disable-default-apps --disable-dev-shm-usage --disable-edgeupdater --disable-extensions --disable-features=AvoidUnnecessaryBeforeUnloadCheckSync,BoundaryEventDispatchTracksNodeRemoval,DestroyProfileOnBrowserClose,DialMediaRouteProvider,GlobalMediaControls,HttpsUpgrades,LensOverlay,MediaRouter,PaintHolding,ThirdPartyStoragePartitioning,BlockOriginHeaderModificationOnRedirect,Translate,AutoDeElevate,OptimizationHints,msForceBrowserSignIn,msEdgeUpdateLaunchServicesPreferredVersion --enable-features=CDPScreenshotNewSurface --allow-pre-commit-input --disable-hang-monitor --disable-ipc-flooding-protection --disable-popup-blocking --disable-prompt-on-repost --disable-renderer-backgrounding --disable-updater-scheduler --force-color-profile=srgb --metrics-recording-only --no-first-run --password-store=basic --use-mock-keychain --no-service-autorun --export-tagged-pdf --disable-search-engine-choice-screen --unsafely-disable-devtools-self-xss-warnings --edge-skip-compat-layer-relaunch --disable-infobars --disable-search-engine-choice-screen --disable-sync --enable-unsafe-swiftshader --headless --hide-scrollbars --mute-audio --blink-settings=primaryHoverType=2,availableHoverTypes=2,primaryPointerType=4,availablePointerTypes=4 --no-sandbox --user-data-dir=C:\Users\WORK_W~1\AppData\Local\Temp\playwright_chromiumdev_profile-vdZoNM --remote-debugging-pipe --no-startup-window
<launched> pid=27640
[pid=27640][err] [27640:26744:1015/165630.303:ERROR:chrome\browser\importer\edge_china_browsers\edge_qqbrowser_importer_utils_win.cc:165] QQBrowser user data path not found.
[pid=27640][err] [27640:27644:1015/165630.499:ERROR:content\browser\gpu\gpu_process_host.cc:1103] GPU process exited unexpectedly: exit_code=34
[pid=27640][err] [27640:27644:1015/165630.748:ERROR:gpu\command_buffer\client\cmd_buffer_helper.cc:143] ContextResult::kFatalFailure: CommandBufferHelper::AllocateRingBuffer() failed
Call log:
[2m  - waiting for getByText('e663b47013d5', { exact: true }).first() to be visible[22m

    at verifyProductBrowser (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:292:78)
    at async main (E:\网安\CyberSecurity-Innovation-Audit\scripts\platform_real_product_browser_acceptance.mjs:523:7)
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
    "job_id": "e129c9eb08314edd8f56e876ce9a58be",
    "commit": "e663b47013d534a56165ab7467fbb3e14bf7172b",
    "tree": "5037e995cb4f3f29d54307b6e0fbf352cc9d6252",
    "sha256": "5e76eb0ff53ae6a7fc9d59fdb74464be465ef25fdaa780653199e14c28ab2148",
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
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && .venv-web/bin/python -m scripts.platform_real_product_browser_seed --root '/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r9-20261015-01'"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '/mnt/e/网安/CyberSecurity-Innovation-Audit' && env OHSCANNER_DATA='/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/platform-real-product-browser-r9-20261015-01/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port 8877"
wsl.exe -d Ubuntu-22.04 -- bash -lc "kill 1121 2>/dev/null || true"
```

## 文件与 SHA-256

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| .codex-review-tmp/platform-real-product-browser-r9-20261015-01/data/artifacts/e129c9eb08314edd8f56e876ce9a58be/report.json | 134761 | 5e76eb0ff53ae6a7fc9d59fdb74464be465ef25fdaa780653199e14c28ab2148 |
| .codex-review-tmp/platform-real-product-browser-r9-20261015-01/data/artifacts/e129c9eb08314edd8f56e876ce9a58be/report.md | 11663 | 263fdfdb8b6e16d896f91f80745db227166080ee56c533ccfecd6643fe716740 |
| .codex-review-tmp/platform-real-product-browser-r9-20261015-01/seed.json | 3626 | e7a3fe8979757b0c9aeb19323ade4c40774d5d585fcfc8cdf0872f4b7005167e |

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
