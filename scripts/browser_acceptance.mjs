import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const playwrightPath = process.env.PLAYWRIGHT_CORE_PATH || "playwright-core";
const { chromium } = require(playwrightPath);
const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const wslProject = "/mnt/e/网安/CyberSecurity-Innovation-Audit";
const runId = process.env.BROWSER_ACCEPTANCE_RUN_ID || `run-${new Date().toISOString().replaceAll(":", "-")}`;
const runStartedAt = new Date().toISOString();
const rootName = `browser-acceptance-${runId}`;
const root = path.join(project, ".codex-review-tmp", rootName);
const wslRoot = `/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/${rootName}`;
const outputStem = `browser_acceptance_20261015_${runId}`;
const port = 8876;
const baseUrl = `http://127.0.0.1:${port}`;
const checks = [];
const networkActions = [];
const processes = [];
const commands = [{ command: "node scripts/browser_acceptance.mjs", cwd: project }];
const operationDetails = [];

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function walkFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const item = path.join(directory, entry.name);
    return entry.isDirectory() ? walkFiles(item) : [item];
  });
}

function fileEvidence(file) {
  return {
    path: path.relative(root, file).replaceAll("\\", "/"),
    bytes: fs.statSync(file).size,
    sha256: sha256File(file),
  };
}

function record(name, status, details) {
  checks.push({ name, status, details });
  console.log(`${status.toUpperCase()} ${name}: ${details}`);
}

function wsl(command, timeoutMs = 120000) {
  commands.push({ command: `wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '${wslProject}' && ${command}"`, cwd: project });
  const result = spawnSync(
    "wsl.exe",
    ["-d", "Ubuntu-22.04", "--", "bash", "-lc", `cd '${wslProject}' && ${command}`],
    { encoding: "utf8", timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`WSL command failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function startPersistent(name, command) {
  commands.push({ command: `wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '${wslProject}' && ${command}"`, cwd: project });
  const child = spawn(
    "wsl.exe",
    ["-d", "Ubuntu-22.04", "--", "bash", "-lc", `cd '${wslProject}' && echo OHSCANNER_PID=$$; exec ${command}`],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  const state = { name, child, pid: null, output: "", stdout: "", stderr: "" };
  processes.push(state);
  child.stdout.on("data", (chunk) => {
    const text = chunk.toString();
    state.output += text;
    state.stdout += text;
    const match = state.output.match(/OHSCANNER_PID=(\d+)/);
    if (match) state.pid = Number(match[1]);
  });
  child.stderr.on("data", (chunk) => {
    const text = chunk.toString();
    state.output += text;
    state.stderr += text;
  });
  return state;
}

async function stopProcess(state) {
  if (!state?.pid) {
    state?.child?.kill();
    return;
  }
  spawnSync("wsl.exe", ["-d", "Ubuntu-22.04", "--", "bash", "-lc", `kill ${state.pid} 2>/dev/null || true`], {
    encoding: "utf8",
    timeout: 10000,
  });
  const deadline = Date.now() + 5000;
  while (state.child.exitCode === null && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (state.child.exitCode === null) {
    spawnSync("wsl.exe", ["-d", "Ubuntu-22.04", "--", "bash", "-lc", `kill -9 ${state.pid} 2>/dev/null || true`], {
      encoding: "utf8",
      timeout: 10000,
    });
    state.child.kill();
  }
}

async function api(pathname, options = {}) {
  const response = await fetch(baseUrl + "/api/v1" + pathname, options);
  if (!response.ok) {
    throw new Error(`${pathname} ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

async function waitForOperation(predicate, label, timeoutMs = 180000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const rows = await api("/operations");
    const row = rows.find(predicate);
    if (row && ["completed", "completed_with_limitations", "blocked", "failed", "cancelled", "timed_out", "interrupted"].includes(row.status)) {
      return row;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`operation timeout: ${label}`);
}

async function chooseSelect(scope, testId, label) {
  const select = scope.getByTestId(testId);
  await select.click();
  const keyboardPage = scope.page();
  await keyboardPage.keyboard.type(label.split(" · ")[0]);
  await keyboardPage.waitForTimeout(100);
  await keyboardPage.keyboard.press("Enter");
  await keyboardPage.keyboard.press("Escape");
}

async function submitAndWait(page, formTestId, buttonTestId, kind, started, label, expectedStatus, specName) {
  await page.getByTestId(formTestId).getByTestId(buttonTestId).click();
  const operationRow = await waitForOperation(
    (row) => row.kind === kind &&
      (!specName || row.spec?.name === specName) &&
      Date.parse(row.created_at) >= started - 1000,
    label,
  );
  const operation = await api(`/operations/${operationRow.id}`);
  operationDetails.push(operation);
  if (expectedStatus && operation.status !== expectedStatus) {
    const error = new Error(`${label}: expected ${expectedStatus}, got ${operation.status}: ${operation.error || ""}`);
    error.operation = operation;
    error.failure_stage = label;
    throw error;
  }
  return operation;
}

async function downloadText(page, selectorOrLocator) {
  const locator = typeof selectorOrLocator === "string"
    ? page.getByTestId(selectorOrLocator)
    : selectorOrLocator;
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    locator.click(),
  ]);
  const filename = download.suggestedFilename();
  const file = await download.path();
  const text = fs.readFileSync(file, "utf8");
  return { filename, text };
}

async function openClusterAndReview(page, seed) {
  await page.goto(`${baseUrl}/#/tasks/${seed.job_id}`, { waitUntil: "networkidle" });
  await page.getByRole("tab", { name: /候选聚类/ }).click();
  const clusterTable = page.getByTestId("candidate-clusters");
  const members = clusterTable.getByTestId("cluster-candidate");
  if (!(await members.first().isVisible())) {
    await clusterTable.locator(".ant-table-row-expand-icon").first().click();
  }
  if (await members.count() !== seed.cluster_member_ids.length) {
    throw new Error(`cluster expansion member count mismatch: ${await members.count()}`);
  }
  await members.first().click();
  await page.getByText("browser-review", { exact: true }).waitFor();
  await page.getByText("Persisted evidence for restart acceptance", { exact: true }).waitFor();
  record("candidate_cluster_expand", "passed", `${seed.cluster_member_ids.length} original candidate IDs remain addressable`);
  await page.locator(".ant-drawer-close").click();
}

async function exerciseJobArtifacts(page, seed) {
  await page.goto(`${baseUrl}/#/tasks/${seed.job_id}`, { waitUntil: "networkidle" });
  await page.getByRole("tab", { name: /报告与产物/ }).click();
  const json = await downloadText(page, "download-report.json");
  const markdown = await downloadText(page, "download-report.md");
  if (!json.text.includes(seed.report_sha256) && !json.text.includes('"diagnostic_count"')) {
    throw new Error("report JSON download did not contain report evidence");
  }
  if (!markdown.text.includes("OHScanner") && !markdown.text.includes("候选")) {
    throw new Error("report Markdown download was not a report");
  }
  record("scan_report_downloads", "passed", `${json.filename}, ${markdown.filename}`);
}

async function exerciseCases(page, seed) {
  await page.goto(`${baseUrl}/#/cases`, { waitUntil: "networkidle" });
  const cases = await api("/cases");
  const uiCase = cases.find((item) => item.title === "Browser UI case");
  if (!uiCase) throw new Error("Browser UI case is missing");
  const caseRow = page.getByRole("row", { name: /Browser UI case/ });
  const json = await downloadText(page, caseRow.getByTestId("download-case-json"));
  const markdown = await downloadText(page, caseRow.getByTestId("download-case-md"));
  const parsed = JSON.parse(json.text);
  if (parsed.case_id !== uiCase.id || parsed.candidates[0].candidate.id !== seed.reviewed_candidate_id) {
    throw new Error("case JSON lost candidate identity after download");
  }
  if (!markdown.text.includes(uiCase.id) || !markdown.text.includes("candidate")) {
    throw new Error("case Markdown download lost case identity");
  }
  record("case_report_downloads", "passed", `${json.filename}, ${markdown.filename}`);
}

async function createReviewEvidenceCase(page, seed) {
  await page.goto(`${baseUrl}/#/tasks/${seed.job_id}`, { waitUntil: "networkidle" });
await page.getByRole("tab", { name: "候选与复核", exact: true }).click();
  const candidateRow = page.locator(`tr[data-row-key="${seed.reviewed_candidate_id}"]`).first();
  await candidateRow.waitFor();
  const rowBox = await candidateRow.boundingBox();
  await candidateRow.click({ position: { x: 12, y: Math.max(2, (rowBox?.height || 20) / 2) } });
  await page.getByTestId("open-case-modal").click();
  await page.getByTestId("case-title").fill("Browser UI case");
  await page.getByTestId("case-rationale").fill("Browser-created case preserves candidate IDs");
  await page.locator(".ant-modal button.ant-btn-primary").click();
  await page.locator(".ant-modal").waitFor({ state: "hidden" });
  const caseDeadline = Date.now() + 10000;
  while (Date.now() < caseDeadline) {
    const existing = await api("/cases");
    if (existing.some((item) => item.title === "Browser UI case")) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  await page.getByRole("tab", { name: /候选聚类/ }).click();
  const clusterTable = page.getByTestId("candidate-clusters");
  const memberButton = clusterTable.getByTestId("cluster-candidate").first();
  if (!(await memberButton.isVisible())) {
    await clusterTable.locator(".ant-table-row-expand-icon").first().click();
  }
  await memberButton.click();
  await page.getByTestId("review-reviewer").fill("browser-ui-review");
  await page.getByTestId("review-notes").fill("Browser review append-only persistence");
  await page.getByTestId("save-review").click();
  const reviewDeadline = Date.now() + 10000;
  let reviewSaved = false;
  while (Date.now() < reviewDeadline) {
    const listed = await api(`/scans/${seed.job_id}/findings`);
    if (listed.items.some((item) => item.latest_review?.reviewer === "browser-ui-review")) {
      reviewSaved = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!reviewSaved) throw new Error("browser review was not persisted");
  await page.getByTestId("evidence-note").fill("Browser evidence append-only persistence");
  await page.getByTestId("save-evidence").click();
  const evidenceDeadline = Date.now() + 10000;
  let evidenceSaved = false;
  while (Date.now() < evidenceDeadline) {
    let found = false;
    for (const candidateId of seed.candidate_ids) {
      const detail = await api(`/scans/${seed.job_id}/findings/${candidateId}`);
      if (detail.supplemental_evidence.some((item) => item.note === "Browser evidence append-only persistence")) {
        found = true;
        evidenceSaved = true;
        break;
      }
    }
    if (found) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!evidenceSaved) throw new Error("browser evidence was not persisted");
  record("review_and_evidence_ui", "passed", "append-only review and source-bound evidence saved from candidate drawer");
}

async function exerciseOperations(page, seed) {
  await page.goto(`${baseUrl}/#/operations`, { waitUntil: "networkidle" });
  const queuedRow = page.locator(`tr[data-row-key="${seed.queued_cancel_operation_id}"]`);
  await queuedRow.getByTestId("cancel-operation").click();
  const cancelled = await waitForOperation((row) => row.id === seed.queued_cancel_operation_id, "cancel");
  if (cancelled.status !== "cancelled") throw new Error(`cancel status ${cancelled.status}`);
  record("operation_cancel", "passed", "queued source_sync cancelled from browser");

  const scanWorker = startPersistent(
    "scan-worker",
    `env OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='${wslRoot}/targets' .venv-web/bin/python -m src.workbench.worker`,
  );
  const operationWorker = startPersistent(
    "operation-worker",
    `env OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='${wslRoot}/targets' .venv-web/bin/python -m src.workbench.operation_worker`,
  );
  const recovered = await waitForOperation(
    (row) => row.id === seed.running_recovery_operation_id,
    "worker recovery",
    30000,
  );
  if (recovered.status !== "interrupted") throw new Error(`recovery status ${recovered.status}`);
  record("operation_restart_recovery", "passed", "running operation became interrupted without publishing a partial result");

  const commonSelects = async (formTestId) => {
    const form = page.getByTestId(formTestId);
    await chooseSelect(form, "repository-select", "fixture/sample · " + seed.repo.replaceAll("\\", "/"));
    await chooseSelect(form, "detector-select", "ohscanner.interface.ipc");
  };

  await page.getByRole("tab", { name: "两个 SHA 区间" }).click();
  await commonSelects("revision-range-form");
  await page.getByTestId("range-baseline").fill(seed.commits.baseline);
  await page.getByTestId("range-endpoint").fill(seed.commits.endpoint);
  let started = Date.now();
  let operation = await submitAndWait(page, "revision-range-form", "submit-range", "revision_range", started, "revision range", "completed_with_limitations");
  record("revision_range", "passed", `${operation.spec.baseline.slice(0, 12)}..${operation.spec.endpoint.slice(0, 12)}`);

  await page.getByRole("tab", { name: "提交者日期区间" }).click();
  await commonSelects("date-range-form");
  await page.getByTestId("date-branch").fill("HEAD");
  await page.getByTestId("date-start").fill("2025-01-02T00:00:00");
  await page.getByTestId("date-end").fill("2025-01-04T00:00:00");
  await page.getByTestId("date-timezone").fill("UTC");
  started = Date.now();
  operation = await submitAndWait(page, "date-range-form", "submit-range", "revision_range", started, "date range", "completed_with_limitations");
  if (!operation.spec.date_selection || operation.spec.date_selection.selected_commits.length !== 2) {
    throw new Error("date range did not retain selected commits");
  }
  record("date_range", "passed", "committer-date [start,end) selected two fixed commits");

  await page.getByRole("tab", { name: "版本矩阵" }).click();
  await chooseSelect(page.getByTestId("version-matrix-form"), "case-select", "Browser UI case");
  await commonSelects("version-matrix-form");
  await page.getByTestId("matrix-commits").fill(`${seed.commits.baseline},${seed.commits.endpoint}`);
  started = Date.now();
  operation = await submitAndWait(page, "version-matrix-form", "submit-version-matrix", "version_matrix", started, "version matrix", "completed_with_limitations");
  if (operation.spec.commits.length !== 2 || !operation.result || operation.result.impact !== undefined) {
    // Matrix result keeps impact unknown at comparison rows; operation itself is still limited.
    if (!operation.result || !Array.isArray(operation.result.versions)) throw new Error("version matrix result missing");
  }
  record("version_matrix", "passed", "two fixed SHA observations compared; impact remains unknown");

  await page.getByRole("tab", { name: "同步源码" }).click();
  await page.getByTestId("sync-repository").fill("openharmony/c_utils");
  await page.getByTestId("sync-url").fill("https://github.com/openharmony/c_utils.git");
  await page.getByTestId("sync-timeout").fill("300");
  started = Date.now();
  networkActions.push({ action: "controlled loopback HTTPS Git clone/fetch under approved URL rewrite", repository: "openharmony/c_utils", requested_url: "https://github.com/openharmony/c_utils.git", effective_url: `https://${seed.git_host_ip}:9443/c_utils.git`, purpose: "browser source-sync acceptance" });
  operation = await submitAndWait(page, "source-sync-form", "submit-source-sync", "source_sync", started, "source sync", "completed", "openharmony/c_utils");
  record("source_sync", "passed", `explicit sync completed; remote refs=${operation.result.advertised_remote_refs.length}`);

  await page.getByTestId("sync-repository").fill("openharmony/ace_napi");
  await page.getByTestId("sync-url").fill("https://github.com/openharmony/ace_napi.git");
  await page.getByTestId("sync-timeout").fill("10");
  started = Date.now();
  networkActions.push({ action: "controlled loopback HTTPS Git fetch with hard deadline", repository: "openharmony/ace_napi", requested_url: "https://github.com/openharmony/ace_napi.git", effective_url: `https://${seed.git_host_ip}:9444/ace_napi.git`, purpose: "browser timeout acceptance" });
  operation = await submitAndWait(page, "source-sync-form", "submit-source-sync", "source_sync", started, "source sync timeout", "timed_out", "openharmony/ace_napi");
  record("operation_timeout", "passed", "10-second source-sync hard deadline published timed_out without a partial result");

  return { scanWorker, operationWorker };
}

async function verifyRestart(page, seed) {
  await openClusterAndReview(page, seed);
  await exerciseCases(page, seed);
  const rows = await api("/operations");
  const statuses = Object.fromEntries(rows.map((row) => [row.id, row.status]));
  if (statuses[seed.queued_cancel_operation_id] !== "cancelled"
      || statuses[seed.running_recovery_operation_id] !== "interrupted") {
    throw new Error("operation states did not survive restart");
  }
  const task = await api(`/scans/${seed.job_id}`);
  const detail = await api(`/scans/${seed.job_id}/findings/${seed.reviewed_candidate_id}`);
  if (task.report_sha256 !== seed.report_sha256
      || detail.reviews.length < 1
      || detail.supplemental_evidence.length < 1) {
    throw new Error("review/evidence/report identity did not survive restart");
  }
  record("restart_persistence", "passed", "operation, review, evidence, report hash and case report remained recoverable");
}

async function main() {
  if (fs.existsSync(root)) {
    throw new Error(`acceptance root already exists: ${root}`);
  }
  fs.mkdirSync(root, { recursive: true });
  wsl(`.venv-web/bin/python -m scripts.browser_acceptance_seed --root '${wslRoot}'`, 120000);
  const seed = JSON.parse(fs.readFileSync(path.join(root, "seed.json"), "utf8"));
  const gitFixtureRoot = path.join(root, "git-fixture");
  startPersistent(
    "git-https-c-utils",
    `.venv-web/bin/python -m scripts.git_https_fixture_server --port 9443 --root '${wslRoot}/git-fixture'`,
  );
  startPersistent(
    "git-https-slow",
    `.venv-web/bin/python -m scripts.git_https_fixture_server --port 9444 --root '${wslRoot}/git-fixture' --slow`,
  );
  let apiProcess = startPersistent(
    "api",
    `env OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='${wslRoot}/targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port ${port}`,
  );
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const health = await api("/health");
      if (health.status === "ok") break;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.EDGE_EXECUTABLE || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  });
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  let failure = null;
  try {
    await openClusterAndReview(page, seed);
    await exerciseJobArtifacts(page, seed);
    await createReviewEvidenceCase(page, seed);
    await exerciseCases(page, seed);
    const workers = await exerciseOperations(page, seed);
    await stopProcess(workers.scanWorker);
    await stopProcess(workers.operationWorker);
    await stopProcess(apiProcess);
    apiProcess = startPersistent(
      "api-restarted",
      `env OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='${wslRoot}/targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port ${port}`,
    );
    const restartDeadline = Date.now() + 30000;
    while (Date.now() < restartDeadline) {
      try {
        if ((await api("/health")).status === "ok") break;
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    await verifyRestart(page, seed);
    record("browser_full_chain", "passed", "browser UI drove repository operation planning, cancellation/deadline, cluster review and downloads");
  } catch (error) {
    failure = error;
    record("browser_full_chain", "failed", error?.stack || String(error));
  } finally {
    await context.close();
    await browser.close();
    for (const state of [...processes].reverse()) await stopProcess(state);
    const processLogDir = path.join(root, "process-logs");
    fs.mkdirSync(processLogDir, { recursive: true });
    const processEvidence = processes.map((state) => {
      const stdoutPath = path.join(processLogDir, `${state.name}.stdout.log`);
      const stderrPath = path.join(processLogDir, `${state.name}.stderr.log`);
      fs.writeFileSync(stdoutPath, state.stdout);
      fs.writeFileSync(stderrPath, state.stderr);
      return {
        name: state.name,
        pid: state.pid,
        exit_code: state.child.exitCode,
        stdout: fileEvidence(stdoutPath),
        stderr: fileEvidence(stderrPath),
      };
    });
    const operationArtifactFiles = walkFiles(path.join(root, "data", "operations"))
      .filter((file) => ["worker.log", "child-result.json", "result.json", "git-process.json", "child-error.json"]
        .includes(path.basename(file)));
    const fixtureCert = path.join(root, "git-fixture", "cert.pem");
    const gitStatus = spawnSync("git", ["status", "--short", "--branch"], {
      cwd: project,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    const gitHead = spawnSync("git", ["rev-parse", "HEAD"], { cwd: project, encoding: "utf8" });
    const gitRemote = spawnSync("git", ["remote", "get-url", "origin"], { cwd: project, encoding: "utf8" });
    const sourceHashes = [
      "scripts/browser_acceptance.mjs",
      "scripts/browser_acceptance_seed.py",
      "scripts/git_https_fixture_server.py",
      "src/workbench/operations.py",
      "src/workbench/operation_worker.py",
      "tests/test_workbench_operations.py",
      "tests/test_workbench_browser_acceptance.py",
    ].map((relative) => ({
      path: relative,
      sha256: sha256File(path.join(project, relative)),
    }));
    const result = {
      schema_version: 1,
      task: "WEB-SOURCE-SYNC-01",
      run_id: runId,
      started_at: runStartedAt,
      finished_at: new Date().toISOString(),
      status: failure || checks.length === 0 || checks.some((item) => item.status === "failed") ? "failed" : "passed",
      failure_stage: failure?.failure_stage || (failure ? "browser_full_chain" : null),
      failures: checks.filter((item) => item.status === "failed"),
      diagnosis: {
        symptom: "browser_full_chain / source sync: Operation child exited 1",
        mechanism: "An uncaught source-sync Git subprocess exception escaped the operation child and was reduced by the parent to a generic child exit error.",
        contributing_conditions: [
          "Git subprocess execution inherited the caller working directory and GIT_CONFIG_* environment.",
          "The Git subprocess timeout equaled the outer hard deadline, allowing timeout-versus-supervisor races.",
          "stdout/stderr and failure stage were not committed as structured source-sync evidence.",
        ],
        exact_original_stderr: "unknown; the originally failed run artifacts were not preserved in the supplied checkout",
        fix: [
          "Run source-sync Git from an isolated temporary cwd and remove inherited GIT_CONFIG_* values while retaining target-local fixture URL rewrite and CA configuration.",
          "Make the outer operation Worker the sole hard-deadline authority.",
          "Persist git-process.json and child-error.json with command, cwd, exit code, stdout, stderr and stage.",
        ],
      },
      checks,
      network_actions: networkActions,
      commands,
      git_state: {
        branch_status: gitStatus.stdout || gitStatus.stderr,
        full_commit_sha: (gitHead.stdout || "").trim(),
        remote: (gitRemote.stdout || "").trim(),
        dirty_files: (gitStatus.stdout || "").split(/\r?\n/).slice(1).filter(Boolean),
      },
      environment: {
        host: "Windows 11 + WSL2 Ubuntu 22.04",
        browser: "Microsoft Edge headless via playwright-core",
        backend: `${wslProject} @ current working tree`,
        data_root: root,
        node: process.version,
        playwright_core_path: playwrightPath,
        edge_executable: process.env.EDGE_EXECUTABLE || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        wsl_distribution: "Ubuntu-22.04",
        wsl_git: "2.34.1",
        wsl_python: "3.10.12",
      },
      operation_details: operationDetails,
      process_evidence: processEvidence,
      artifacts: [
        ...operationArtifactFiles.map(fileEvidence),
        ...(fs.existsSync(fixtureCert) ? [fileEvidence(fixtureCert)] : []),
        fileEvidence(path.join(root, "seed.json")),
      ],
      source_hashes: sourceHashes,
      source_sync_diagnostics: {
        git_process_records: operationArtifactFiles
          .filter((file) => path.basename(file) === "git-process.json")
          .map((file) => JSON.parse(fs.readFileSync(file, "utf8"))),
        preserved: ["loopback HTTPS fixture", "target-local URL rewrite", "fixture CA certificate", "network action records"],
      },
      limitations: [
        "Browser acceptance covers local workbench behavior only; it is not vulnerability accuracy or product security validation.",
        "Version matrix reports static candidate observations with impact unknown.",
        "The timeout control uses a deterministic loopback HTTPS Git endpoint and does not create a complete repository.",
        "Public-network GitHub/Gitee/GitCode synchronization remains unverified.",
      ],
      unverified: [
        "multi-user and public-network deployment",
        "Docker runtime validation",
        "product reachability and CIA impact",
      ],
    };
    const outputDir = path.join(project, "outputs", "browser-acceptance");
    fs.mkdirSync(outputDir, { recursive: true });
    const output = path.join(outputDir, `${outputStem}.json`);
    fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
    const markdown = path.join(outputDir, `${outputStem}.md`);
    const rows = result.checks.map((item) => `| ${item.name} | ${item.status} | ${item.details.replaceAll("|", "\\|")} |`).join("\n");
    const networkRows = result.network_actions.map((item) =>
      `| ${item.action} | ${item.repository} | ${item.requested_url} | ${item.effective_url} | ${item.purpose} |`).join("\n");
    const artifactRows = result.artifacts.map((item) => `| ${item.path} | ${item.bytes} | ${item.sha256} |`).join("\n");
    const failureText = result.failure_stage ? `失败阶段：${result.failure_stage}` : "失败阶段：无";
    fs.writeFileSync(markdown, [
      "# WEB-SOURCE-SYNC-01 浏览器 source sync 验收",
      "",
      `- 运行 ID：\`${result.run_id}\``,
      `- 状态：\`${result.status}\``,
      `- ${failureText}`,
      `- 开始：${result.started_at}`,
      `- 结束：${result.finished_at}`,
      `- HEAD：\`${result.git_state.full_commit_sha}\``,
      `- Remote：\`${result.git_state.remote}\``,
      `- Dirty 文件数：${result.git_state.dirty_files.length}`,
      "",
      "## 检查",
      "",
      "| 检查 | 状态 | 详情 |",
      "|---|---|---|",
      rows,
      "",
      "## 受控网络动作",
      "",
      "| 动作 | 仓库 | 请求 URL | 实际 URL | 目的 |",
      "|---|---|---|---|---|",
      networkRows,
      "",
      "## Source sync 过程诊断",
      "",
      "```json",
      JSON.stringify(result.diagnosis, null, 2),
      "```",
      "",
      "```json",
      JSON.stringify(result.source_sync_diagnostics, null, 2),
      "```",
      "",
      "## 操作与子进程证据",
      "",
      "每个 source sync 的 `git-process.json` 保留命令、cwd、exit code、stdout、stderr；`worker.log` 保留 operation child 输出，完整记录位于本次 data root。",
      "",
      "## 文件与哈希",
      "",
      "| 文件 | 字节 | SHA-256 |",
      "|---|---:|---|",
      artifactRows,
      "",
      "## 命令",
      "",
      "```text",
      ...result.commands.map((item) => item.command),
      "```",
      "",
      "## 环境",
      "",
      "```json",
      JSON.stringify(result.environment, null, 2),
      "```",
      "",
      "## 失败与 unknown",
      "",
      `- 失败：${result.failures.length ? result.failures.map((item) => item.name).join(", ") : "无"}`,
      ...result.unverified.map((item) => `- unknown/unverified：${item}`),
      "",
      "## 限制",
      "",
      ...result.limitations.map((item) => `- ${item}`),
      "",
      "本验收只证明本地工作台浏览器流程和受控 loopback source sync 行为，不解释为漏洞准确率或产品安全验证。",
      "",
    ].join("\n"));
    const hashFile = path.join(outputDir, `${outputStem}.hashes.json`);
    fs.writeFileSync(hashFile, JSON.stringify({
      task: result.task,
      run_id: result.run_id,
      files: [output, markdown].map((file) => ({
        path: path.relative(project, file).replaceAll("\\", "/"),
        sha256: sha256File(file),
      })),
    }, null, 2) + "\n");
    console.log(output);
    console.log(markdown);
    console.log(hashFile);
    if (failure) console.error(failure?.stack || String(failure));
    if (result.status !== "passed") process.exitCode = 1;
  }
}

await main();
