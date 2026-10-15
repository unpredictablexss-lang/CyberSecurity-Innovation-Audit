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
const runId = process.env.PLATFORM_ACCEPTANCE_RUN_ID || `run-${new Date().toISOString().replaceAll(":", "-")}`;
const startedAt = new Date().toISOString();
const rootName = `platform-real-product-browser-${runId}`;
const root = path.join(project, ".codex-review-tmp", rootName);
const wslRoot = `/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/${rootName}`;
const outputStem = `platform_real_product_browser_acceptance_${runId}`;
const outputDir = path.join(project, "outputs", "platform-real-product-browser-01");
const port = 8877;
const baseUrl = `http://127.0.0.1:${port}`;

const product = {
  repository: "openharmony/inputmethod_imf",
  commit: "e663b47013d534a56165ab7467fbb3e14bf7172b",
  tree: "5037e995cb4f3f29d54307b6e0fbf352cc9d6252",
  detector: "ohscanner.interface.ipc",
};
const component = {
  repository: "openharmony/commonlibrary_c_utils",
  commit: "b807d3dadb7dbb7639fe85b3a5f72da18d318da2",
  tree: "52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d",
};

const checks = [];
const commands = [];
const networkActions = [];
const processes = [];
const operationDetails = [];

function sha256Buffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}
function sha256Text(text) {
  return sha256Buffer(Buffer.from(text, "utf8"));
}
function sha256File(file) {
  return sha256Buffer(fs.readFileSync(file));
}
function fileEvidence(file) {
  return {
    path: path.relative(project, file).replaceAll("\\", "/"),
    bytes: fs.statSync(file).size,
    sha256: sha256File(file),
  };
}
function record(name, status, details) {
  checks.push({ name, status, details });
  console.log(`${status.toUpperCase()} ${name}: ${details}`);
}
function quoteArg(value) {
  return /[\s"]/.test(value) ? `"${value.replaceAll('"', '\\"')}"` : value;
}
function exactCommand(exe, args) {
  return [exe, ...args].map(quoteArg).join(" ");
}
function walk(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(file) : [file];
  });
}
function credentialLeaks(text) {
  const patterns = [
    /\b[a-z][a-z0-9+.-]*:\/\/[^/\s@]+:[^/\s@]+@/i,
    /\b(?:authorization|proxy-authorization)\s*:\s*\S+/i,
    /\b(?:github_pat_[A-Za-z0-9_]+|ghp_[A-Za-z0-9]+|glpat-[A-Za-z0-9_-]+|gitee_[A-Za-z0-9_-]+)\b/,
    /\b(?:password|passwd|access_token|refresh_token|client_secret)\s*[=:]\s*[^\s'",&;]+/i,
  ];
  return patterns.filter((pattern) => pattern.test(text)).map((pattern) => String(pattern));
}
function backendSourceHash() {
  const files = walk(path.join(project, "src", "workbench")).sort();
  const digest = crypto.createHash("sha256");
  for (const file of files) {
    digest.update(path.relative(project, file).replaceAll("\\", "/"));
    digest.update(fs.readFileSync(file));
  }
  return digest.digest("hex");
}
function wsl(command, timeoutMs = 180000) {
  const display = `wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '${wslProject}' && ${command}"`;
  commands.push({ command: display, cwd: project });
  const result = spawnSync(
    "wsl.exe",
    ["-d", "Ubuntu-22.04", "--", "bash", "-lc", `cd '${wslProject}' && ${command}`],
    { encoding: "utf8", timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`WSL command failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}
function startPersistent(name, command) {
  const display = `wsl.exe -d Ubuntu-22.04 -- bash -lc "cd '${wslProject}' && ${command}"`;
  commands.push({ command: display, cwd: project });
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
    if (/api|worker|validation/.test(name)) console.log(`[${name}] ${text}`);
  });
  child.stderr.on("data", (chunk) => {
    const text = chunk.toString();
    state.output += text;
    state.stderr += text;
    if (/api|worker|validation/.test(name)) console.error(`[${name}] ${text}`);
  });
  return state;
}
async function stopProcess(state) {
  if (!state) return;
  if (!state.pid) {
    state.child?.kill();
    return;
  }
  const killCommand = `kill ${state.pid} 2>/dev/null || true`;
  commands.push({ command: `wsl.exe -d Ubuntu-22.04 -- bash -lc "${killCommand}"`, cwd: project });
  spawnSync("wsl.exe", ["-d", "Ubuntu-22.04", "--", "bash", "-lc", killCommand], {
    encoding: "utf8",
    timeout: 10000,
  });
  const deadline = Date.now() + 5000;
  while (state.child.exitCode === null && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (state.child.exitCode === null) {
    const force = `kill -9 ${state.pid} 2>/dev/null || true`;
    commands.push({ command: `wsl.exe -d Ubuntu-22.04 -- bash -lc "${force}"`, cwd: project });
    spawnSync("wsl.exe", ["-d", "Ubuntu-22.04", "--", "bash", "-lc", force], {
      encoding: "utf8",
      timeout: 10000,
    });
    state.child.kill();
  }
}
async function waitForHealth(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/v1/health`);
      if (response.ok) return await response.json();
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("workbench API health check timed out");
}
async function api(pathname, options = {}) {
  const response = await fetch(baseUrl + "/api/v1" + pathname, {
    headers: { "x-ohscanner-client": "workbench-v1", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) throw new Error(`${pathname} ${response.status}: ${await response.text()}`);
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}
async function waitForOperation(predicate, label, timeoutMs = 300000, acceptAnyStatus = false) {
  const deadline = Date.now() + timeoutMs;
  const terminal = new Set(["completed", "completed_with_limitations", "blocked", "failed", "cancelled", "timed_out", "interrupted"]);
  while (Date.now() < deadline) {
    const rows = await api("/operations");
    const row = rows.find(predicate);
    if (row && (acceptAnyStatus || terminal.has(row.status))) return row;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`operation timeout: ${label}`);
}
async function chooseSelect(scope, testId, label) {
  const select = scope.getByTestId(testId);
  await select.click();
  await scope.page().keyboard.type(label.split(" · ")[0]);
  await scope.page().waitForTimeout(100);
  await scope.page().keyboard.press("Enter");
  await scope.page().keyboard.press("Escape");
}
async function submitAndWait(page, formTestId, buttonTestId, kind, started, label, expectedStatus, specName) {
  await page.getByTestId(formTestId).getByTestId(buttonTestId).click();
  const row = await waitForOperation(
    (item) => item.kind === kind &&
      (!specName || item.spec?.name === specName) &&
      Date.parse(item.created_at) >= started - 1000,
    label,
    300000,
    expectedStatus === "queued",
  );
  const detail = await api(`/operations/${row.id}`);
  operationDetails.push(detail);
  if (expectedStatus && detail.status !== expectedStatus) {
    throw new Error(`${label}: expected ${expectedStatus}, got ${detail.status}: ${detail.error || ""}`);
  }
  return detail;
}
async function downloadText(page, locator) {
  const [download] = await Promise.all([page.waitForEvent("download"), locator.click()]);
  const file = await download.path();
  return { filename: download.suggestedFilename(), text: fs.readFileSync(file, "utf8") };
}
function operationArtifact(operationId, name) {
  const file = path.join(root, "data", "operations", operationId, name);
  if (!fs.existsSync(file)) return null;
  return { file, data: JSON.parse(fs.readFileSync(file, "utf8")), evidence: fileEvidence(file) };
}
function auditEffectiveUrl(url, purpose) {
  const args = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "ls-remote", "--symref", url, "HEAD",
  ];
  const display = exactCommand("git.exe", args);
  commands.push({ command: display, cwd: project, purpose });
  const result = spawnSync("git.exe", args, { encoding: "utf8", timeout: 45000, maxBuffer: 4 * 1024 * 1024 });
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";
  const headLine = stdout.split(/\r?\n/).find((line) => /HEAD$/.test(line)) || "";
  const action = {
    action: "public Git smart-HTTP HEAD advertisement/effective-URL audit",
    purpose,
    requested_url: url,
    effective_url: url,
    effective_url_basis: "Git accepted this exact public HTTPS URL; Git smart-HTTP does not expose redirect target",
    head_advertisement: headLine,
    exact_command: display,
    exit_code: result.status,
    timed_out: Boolean(result.error),
    stdout,
    stderr,
    stdout_sha256: sha256Text(stdout),
    stderr_sha256: sha256Text(stderr),
    credentials: "none; public URL without userinfo/query/fragment; credential helper disabled",
  };
  networkActions.push(action);
  if (result.error || result.status !== 0 || !headLine) {
    throw new Error(`Git effective-URL audit failed for ${url}: ${stderr || stdout}`);
  }
  return action;
}async function submitPublicSync(page, { label, repository, url, timeout, expected, purpose }) {
  const audit = auditEffectiveUrl(url, purpose);
  await page.goto(`${baseUrl}/#/operations`, { waitUntil: "domcontentloaded" });
  await page.getByRole("tab", { name: "同步源码" }).click();
  await page.getByTestId("sync-repository").fill(repository);
  await page.getByTestId("sync-url").fill(url);
  await page.getByTestId("sync-timeout").fill(String(timeout));
  const started = Date.now();
  const operation = await submitAndWait(
    page, "source-sync-form", "submit-source-sync", "source_sync", started, label, expected, repository,
  );
  const plan = operationArtifact(operation.id, "git-plan.json");
  const process = operationArtifact(operation.id, "git-process.json");
  const resultFile = operationArtifact(operation.id, "result.json");
  const command = process?.data?.command || plan?.data?.command || operation.result?.command || null;
  networkActions.push({
    action: operation.status === "completed" ? "public Git clone/fetch via browser source-sync" : "public Git attempt via browser source-sync",
    purpose: label,
    repository,
    requested_url: url,
    effective_url: audit.effective_url,
    operation_id: operation.id,
    status: operation.status,
    exact_command: command ? command.map(quoteArg).join(" ") : null,
    result_sha256: operation.result_sha256,
    git_plan: plan?.evidence || null,
    git_process: process?.evidence || null,
    result_file: resultFile?.evidence || null,
    credential_boundary: "approved public HTTPS URL; userinfo/query/fragment rejected; credential helpers disabled; persisted output redacted",
  });
  return { operation, audit, plan, process, resultFile };
}
async function verifyProductBrowser(page, seed) {
  await page.goto(`${baseUrl}/#/tasks/${seed.job_id}`, { waitUntil: "domcontentloaded" });
  await page.getByText(product.commit.slice(0, 12), { exact: true }).first().waitFor({ timeout: 15000 });
  await page.getByText(product.tree.slice(0, 12), { exact: true }).first().waitFor({ timeout: 15000 });
  const body = await page.locator("body").innerText();
  const statusLabels = {
    partial: "部分覆盖",
    complete: "完整覆盖",
    blocked: "受阻",
  };
  if (!body.includes(product.commit.slice(0, 12)) || !body.includes(product.tree.slice(0, 12))) {
    throw new Error("fixed product commit/tree binding is not visible in browser");
  }
  await page.getByRole("tab", { name: "覆盖与执行" }).click();
  const coverageBody = await page.locator("body").innerText();
  if (!coverageBody.includes(product.detector)) throw new Error("Detector is not visible in coverage");
  if (!coverageBody.includes(statusLabels[seed.coverage.status] || seed.coverage.status)) {
    throw new Error("coverage status is not visible");
  }
  record("product_fixed_binding_and_coverage", "passed",
    `commit=${product.commit}, tree=${product.tree}, detector=${product.detector}, coverage=${seed.coverage.status}`);

  await page.getByRole("tab", { name: /候选聚类/ }).click();
  const table = page.getByTestId("candidate-clusters");
  const clusterRow = table.locator(`tr[data-row-key="${seed.cluster_id}"]`);
  await clusterRow.waitFor();
  const expandIcon = clusterRow.locator(".ant-table-row-expand-icon");
  if (await expandIcon.isVisible()) await expandIcon.click();
  const members = table.getByTestId("cluster-candidate");
  if (await members.count() !== seed.cluster_member_ids.length) {
    throw new Error(`candidate cluster expansion count mismatch: ${await members.count()}`);
  }
  record("product_candidate_cluster_expand", "passed",
    `${seed.cluster_member_ids.length} fixed-source candidate identities remain addressable`);
}
async function createProductReviewEvidenceCase(page, seed) {
  await page.goto(`${baseUrl}/#/tasks/${seed.job_id}`, { waitUntil: "domcontentloaded" });
  await page.getByRole("tab", { name: "候选与复核", exact: true }).click();
  const row = page.locator(`tr[data-row-key="${seed.reviewed_candidate_id}"]`).first();
  await row.waitFor();
  const box = await row.boundingBox();
  await row.click({ position: { x: 12, y: Math.max(2, (box?.height || 20) / 2) } });
  await page.getByTestId("open-case-modal").click();
  await page.getByTestId("case-title").fill("Real product component audit case");
  await page.getByTestId("case-rationale").fill(
    "Fixed real product component browser audit; candidate review only, not vulnerability confirmation.",
  );
  await page.locator(".ant-modal button.ant-btn-primary").click({ force: true });
  await page.locator(".ant-modal").waitFor({ state: "hidden" });

  await row.getByRole("button", { name: "查看证据" }).click();
  await page.getByTestId("review-reviewer").fill("real-product-browser-review");
  await page.getByTestId("review-notes").fill("Append-only review for fixed product component browser acceptance");
  await page.getByTestId("save-review").click();

  const reviewDeadline = Date.now() + 15000;
  let review = null;
  while (Date.now() < reviewDeadline) {
    const detail = await api(`/scans/${seed.job_id}/findings/${seed.reviewed_candidate_id}`);
    if (detail.reviews.length) { review = detail.reviews.at(-1); break; }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!review) throw new Error("review was not persisted");

  await page.getByTestId("evidence-note").fill(
    "Source-bound evidence excerpt for real product component browser acceptance",
  );
  await page.getByTestId("save-evidence").click();
  const evidenceDeadline = Date.now() + 15000;
  let evidence = null;
  while (Date.now() < evidenceDeadline) {
    const detail = await api(`/scans/${seed.job_id}/findings/${seed.reviewed_candidate_id}`);
    if (detail.supplemental_evidence.length) {
      evidence = detail.supplemental_evidence.at(-1);
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!evidence) throw new Error("source evidence was not persisted");

  const caseDeadline = Date.now() + 15000;
  let createdCase = null;
  while (Date.now() < caseDeadline) {
    const cases = await api("/cases");
    createdCase = cases.find((item) => item.title === "Real product component audit case");
    if (createdCase) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!createdCase) throw new Error("real product component case was not persisted");
  await page.locator(".ant-drawer-close").click();
  record("product_review_evidence_case", "passed",
    `review=${review.id}, evidence=${evidence.id}, case=${createdCase.id}, candidate=${seed.reviewed_candidate_id}`);
  return { ...createdCase, review, evidence };
}
async function exerciseProductReports(page, seed, createdCase) {
  await page.goto(`${baseUrl}/#/tasks/${seed.job_id}`, { waitUntil: "domcontentloaded" });
  await page.getByRole("tab", { name: "报告与产物" }).click();
  const reportJson = await downloadText(page, page.getByTestId("download-report.json"));
  const reportMd = await downloadText(page, page.getByTestId("download-report.md"));
  const parsed = JSON.parse(reportJson.text);
  if (parsed.commit !== product.commit || parsed.git_tree !== product.tree) {
    throw new Error("browser report download lost fixed product commit/tree");
  }
  if (!reportMd.text.includes(product.detector) && !reportMd.text.includes("候选")) {
    throw new Error("browser report Markdown was not the fixed Detector report");
  }

  await page.goto(`${baseUrl}/#/cases`, { waitUntil: "domcontentloaded" });
  const caseRow = page.getByRole("row", { name: /Real product component audit case/ });
  await caseRow.waitFor({ timeout: 15000 });
  const caseJson = await downloadText(page, caseRow.getByTestId("download-case-json"));
  const caseMd = await downloadText(page, caseRow.getByTestId("download-case-md"));
  const parsedCase = JSON.parse(caseJson.text);
  if (parsedCase.case_id !== createdCase.id || parsedCase.candidates[0].candidate.id !== seed.reviewed_candidate_id) {
    throw new Error("case report lost fixed candidate identity");
  }
  if (!caseMd.text.includes(createdCase.id)) throw new Error("case Markdown lost case identity");
  record("product_report_and_case_downloads", "passed",
    `${reportJson.filename}, ${reportMd.filename}, ${caseJson.filename}, ${caseMd.filename}`);
}
async function queueProductValidation(page, seed, createdCase) {
  await page.goto(`${baseUrl}/#/operations`, { waitUntil: "domcontentloaded" });
  await page.getByRole("tab", { name: "隔离验证" }).click();
  const form = page.getByTestId("validation-form");
  await chooseSelect(form, "validation-case-select", createdCase.title);
  await chooseSelect(form, "validation-target-repository", "inputmethod_imf");
  await form.getByTestId("validation-target-commit").fill(product.commit);
  await chooseSelect(form, "validation-cutils-repository", "commonlibrary_c_utils");
  await form.getByTestId("validation-cutils-commit").fill(component.commit);
  const started = Date.now();
  const operation = await submitAndWait(
    page, "validation-form", "submit-validation", "validation", started,
    "product validation queue", "queued", undefined,
  );
  record("product_validation_queue_created", "passed",
    `validation operation=${operation.id} remains queued until the dedicated validation lane starts`);
  return operation;
}
async function verifyRestart(page, seed, createdCase, validationOperation) {
  const detail = await api(`/scans/${seed.job_id}/findings/${seed.reviewed_candidate_id}`);
  const task = await api(`/scans/${seed.job_id}`);
  const cases = await api("/cases");
  const operations = await api("/operations");
  const recoveredValidation = operations.find((item) => item.id === validationOperation.id);
  if (task.report_sha256 !== seed.report_sha256 ||
      !detail.reviews.length ||
      !detail.supplemental_evidence.length ||
      !cases.some((item) => item.id === createdCase.id) ||
      recoveredValidation?.status !== "queued") {
    throw new Error("product review/evidence/case/report or validation queue did not survive restart");
  }
  const caseReport = await api(`/cases/${createdCase.id}/report.json`);
  if (caseReport.candidates[0].candidate.id !== seed.reviewed_candidate_id) {
    throw new Error("case report identity did not survive restart");
  }
  record("restart_recovery", "passed",
    "fixed report hash, append-only review/evidence, case report and queued validation state recovered after API restart");
}
async function verifyValidationQueue(page, operationId) {
  const operation = await waitForOperation(
    (item) => item.id === operationId,
    "product validation lane",
    300000,
  );
  await page.goto(`${baseUrl}/#/operations`, { waitUntil: "domcontentloaded" });
  const row = page.locator(`tr[data-row-key="${operationId}"]`);
  await row.getByTestId(`operation-status-${operation.status}`).waitFor();
  record("product_validation_queue_state", "passed",
    `status=${operation.status}; Docker-only component validation is not product vulnerability confirmation`);
  return operation;
}
function collectSourceSyncCredentialAudit() {
  const files = walk(path.join(root, "data", "operations")).filter((file) =>
    ["git-plan.json", "git-process.json", "child-error.json", "worker.log", "result.json"].includes(path.basename(file)),
  );
  const leaks = [];
  for (const file of files) {
    const matches = credentialLeaks(fs.readFileSync(file, "utf8"));
    if (matches.length) leaks.push({ file: path.relative(root, file), patterns: matches });
  }
  if (leaks.length) throw new Error(`credential-like values persisted: ${JSON.stringify(leaks)}`);
  return {
    scanned_files: files.length,
    leaks,
    environment_values_recorded: false,
    credential_environment_names: Object.keys(process.env).filter((name) => /TOKEN|PASS|AUTH|CRED/i.test(name)),
  };
}

async function main() {
  if (fs.existsSync(root)) throw new Error(`acceptance root already exists: ${root}`);
  fs.mkdirSync(root, { recursive: true });
  // Warm the WSL service before the persistent API/worker children; WSL can transiently
  // return E_FAIL while its first instance is being created.
  try {
    wsl("echo WSL_READY", 30000);
  } catch {
    wsl("echo WSL_READY", 30000);
  }
  wsl(`.venv-web/bin/python -m scripts.platform_real_product_browser_seed --root '${wslRoot}'`, 240000);
  const seed = JSON.parse(fs.readFileSync(path.join(root, "seed.json"), "utf8"));

  let apiProcess = startPersistent(
    "api",
    `env OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port ${port}`,
  );
  await waitForHealth();

  const edgeExecutable = process.env.EDGE_EXECUTABLE || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  let browser = null;
  let context = null;
  let page = null;
  let browserVersion = null;
  const edgeVersion = fs.existsSync(edgeExecutable)
    ? spawnSync(edgeExecutable, ["--version"], { encoding: "utf8", timeout: 5000 }).stdout?.trim() || null
    : null;
  let operationWorker = null;
  let validationWorker = null;
  let failure = null;
  let validationOperation = null;
  let createdCase = null;
  const launchBrowser = async () => {
    let lastError = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      let candidateBrowser = null;
      let candidateContext = null;
      try {
        candidateBrowser = await chromium.launch({
          headless: true,
          executablePath: edgeExecutable,
          args: ["--disable-gpu", "--disable-gpu-compositing", "--disable-software-rasterizer"],
        });
        candidateContext = await candidateBrowser.newContext({
          acceptDownloads: true,
          viewport: { width: 1500, height: 1050 },
        });
        const candidatePage = await candidateContext.newPage();
        return { browser: candidateBrowser, context: candidateContext, page: candidatePage };
      } catch (error) {
        lastError = error;
        try { if (candidateContext) await candidateContext.close(); } catch {}
        try { if (candidateBrowser) await candidateBrowser.close(); } catch {}
        if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
    throw lastError;
  };

  try {
    const launched = await launchBrowser();
    browser = launched.browser;
    context = launched.context;
    page = launched.page;
    browserVersion = browser.version();
    try {
      await verifyProductBrowser(page, seed);
    } catch (error) {
      if (!/ERR_CONNECTION_RESET|Timeout|Target page, context or browser has been closed|browser has been closed|crash/i.test(String(error))) {
        throw error;
      }
      try { if (context) await context.close(); } catch {}
      try { if (browser) await browser.close(); } catch {}
      const relaunched = await launchBrowser();
      browser = relaunched.browser;
      context = relaunched.context;
      page = relaunched.page;
      browserVersion = browser.version();
      await verifyProductBrowser(page, seed);
      record("browser_renderer_retry", "passed", "retried after transient Edge renderer connection reset");
    }
    createdCase = await createProductReviewEvidenceCase(page, seed);
    await exerciseProductReports(page, seed, createdCase);

    operationWorker = startPersistent(
      "operation-worker",
      `env OHSCANNER_GIT_TRANSPORT=windows OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets:/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/${rootName}/data/repo-cache' .venv-web/bin/python -m src.workbench.operation_worker`,
    );
    const common = component.repository;
    const commonUrlByHost = {
      GitHub: `https://github.com/${common}.git`,
      Gitee: `https://gitee.com/${common}.git`,
      GitCode: `https://gitcode.com/${common}.git`,
    };
    const githubClone = await submitPublicSync(page, {
      label: "public GitHub explicit clone",
      repository: common, url: commonUrlByHost.GitHub, timeout: 300,
      expected: "completed", purpose: "PLATFORM-REAL-PRODUCT-BROWSER-01 GitHub clone",
    });
    if (!githubClone.operation.result?.clone_stage?.published) {
      throw new Error("GitHub clone did not publish through clone staging");
    }
    record("public_github_clone", "passed",
      `completed; effective_url=${githubClone.audit.effective_url}; result_sha256=${githubClone.operation.result_sha256}`);

    const giteeFetch = await submitPublicSync(page, {
      label: "public Gitee explicit fetch",
      repository: common, url: commonUrlByHost.Gitee, timeout: 300,
      expected: "completed", purpose: "PLATFORM-REAL-PRODUCT-BROWSER-01 Gitee fetch",
    });
    record("public_gitee_fetch", "passed",
      `completed; effective_url=${giteeFetch.audit.effective_url}; result_sha256=${giteeFetch.operation.result_sha256}`);

    const gitcodeFetch = await submitPublicSync(page, {
      label: "public GitCode explicit fetch",
      repository: common, url: commonUrlByHost.GitCode, timeout: 300,
      expected: "completed", purpose: "PLATFORM-REAL-PRODUCT-BROWSER-01 GitCode fetch",
    });
    record("public_gitcode_fetch", "passed",
      `completed; effective_url=${gitcodeFetch.audit.effective_url}; result_sha256=${gitcodeFetch.operation.result_sha256}`);

    const timeoutRepo = "openharmony/arkcompiler_ets_frontend";
    const timeoutUrl = "https://gitcode.com/openharmony/arkcompiler_ets_frontend.git";
    const timeoutRun = await submitPublicSync(page, {
      label: "public GitCode explicit timeout",
      repository: timeoutRepo, url: timeoutUrl, timeout: 10,
      expected: "timed_out", purpose: "PLATFORM-REAL-PRODUCT-BROWSER-01 public timeout",
    });
    const timeoutTarget = path.join(root, "data", "repo-cache", "arkcompiler_ets_frontend");
    const staleTimeoutStaging = walk(path.join(root, "data", "repo-cache"))
      .filter((file) => path.basename(file).startsWith(".arkcompiler_ets_frontend."));
    if (fs.existsSync(timeoutTarget) || staleTimeoutStaging.length) {
      throw new Error("timed-out public clone published a repository or left staging");
    }
    if (!timeoutRun.plan) throw new Error("timed-out public clone lost exact git-plan command");
    record("public_timeout", "passed",
      `timed_out; exact command preserved in git-plan.json; no target/staging published; plan_sha256=${timeoutRun.plan.evidence.sha256}`);

    const missingRepo = "openharmony/ohscanner_public_sync_missing_20261015";
    const missingUrl = `https://github.com/${missingRepo}.git`;
    const missing = await submitPublicSync(page, {
      label: "public Git failure control",
      repository: missingRepo, url: missingUrl, timeout: 30,
      expected: "failed", purpose: "PLATFORM-REAL-PRODUCT-BROWSER-01 failure recovery",
    });
    const missingTarget = path.join(root, "data", "repo-cache", "ohscanner_public_sync_missing_20261015");
    const missingStaging = walk(path.join(root, "data", "repo-cache"))
      .filter((file) => path.basename(file).startsWith(".ohscanner_public_sync_missing_20261015."));
    if (fs.existsSync(missingTarget) || missingStaging.length) {
      throw new Error("failed public clone left a target or staging directory");
    }
    const retry = await submitPublicSync(page, {
      label: "public Git recovery after failure",
      repository: common, url: commonUrlByHost.GitHub, timeout: 300,
      expected: "completed", purpose: "PLATFORM-REAL-PRODUCT-BROWSER-01 recovery retry",
    });
    record("public_failure_recovery", "passed",
      `failed clone left no cache/staging; subsequent GitHub fetch completed result_sha256=${retry.operation.result_sha256}`);

    await stopProcess(operationWorker);
    operationWorker = null;
    const queuedCancel = await submitPublicSync(page, {
      label: "public Git queued cancellation",
      repository: timeoutRepo, url: timeoutUrl, timeout: 300,
      expected: "queued", purpose: "PLATFORM-REAL-PRODUCT-BROWSER-01 cancellation",
    });
    await page.goto(`${baseUrl}/#/operations`, { waitUntil: "domcontentloaded" });
    const cancelRow = page.locator(`tr[data-row-key="${queuedCancel.operation.id}"]`);
    await cancelRow.getByTestId("cancel-operation").click();
    const cancelled = await waitForOperation((item) => item.id === queuedCancel.operation.id, "browser cancel");
    if (cancelled.status !== "cancelled") throw new Error(`cancel status=${cancelled.status}`);
    operationWorker = startPersistent(
      "operation-worker-after-cancel",
      `env OHSCANNER_GIT_TRANSPORT=windows OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets:/mnt/e/网安/CyberSecurity-Innovation-Audit/.codex-review-tmp/${rootName}/data/repo-cache' .venv-web/bin/python -m src.workbench.operation_worker`,
    );
    const postCancel = await submitPublicSync(page, {
      label: "public Git fetch after cancellation recovery",
      repository: common, url: commonUrlByHost.Gitee, timeout: 300,
      expected: "completed", purpose: "PLATFORM-REAL-PRODUCT-BROWSER-01 post-cancel recovery",
    });
    record("public_cancel_and_recovery", "passed",
      `cancelled=${cancelled.id}; recovery fetch completed result_sha256=${postCancel.operation.result_sha256}`);

    validationOperation = await queueProductValidation(page, seed, createdCase);

    await stopProcess(operationWorker);
    operationWorker = null;
    await stopProcess(apiProcess);
    apiProcess = null;
    apiProcess = startPersistent(
      "api-restarted",
      `env OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets' .venv-web/bin/python -m uvicorn src.workbench.api:create_app --factory --host 127.0.0.1 --port ${port}`,
    );
    await waitForHealth();
    await verifyRestart(page, seed, createdCase, validationOperation);

    validationWorker = startPersistent(
      "validation-worker",
      `env OHSCANNER_DATA='${wslRoot}/data' OHSCANNER_TARGET_ROOTS='/home/audit/openharmony-audit/ipc-research/repos:/home/audit/openharmony-targets' .venv-web/bin/python -m src.workbench.operation_worker --validation`,
    );
    const validationFinal = await verifyValidationQueue(page, validationOperation.id);
    validationOperation = validationFinal;

    const credentialAudit = collectSourceSyncCredentialAudit();
    record("credential_log_boundary", "passed",
      `${credentialAudit.scanned_files} source-sync artifacts scanned; no credential-like values; environment values not recorded`);
    record("platform_real_product_browser_boundary", "passed",
      "public Git synchronization and fixed real-product browser audit completed without product vulnerability or deployment claims");
  } catch (error) {
    failure = error;
    record("platform_real_product_browser_boundary", "failed", error?.stack || String(error));
  } finally {
    try { if (context) await context.close(); } catch {}
    try { if (browser) await browser.close(); } catch {}
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

    const gitState = {
      branch: spawnSync("git", ["branch", "--show-current"], { cwd: project, encoding: "utf8" }).stdout.trim(),
      full_commit_sha: spawnSync("git", ["rev-parse", "HEAD"], { cwd: project, encoding: "utf8" }).stdout.trim(),
      remote: spawnSync("git", ["remote", "get-url", "origin"], { cwd: project, encoding: "utf8" }).stdout.trim(),
      dirty_files: spawnSync("git", ["status", "--porcelain=v1"], { cwd: project, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 })
        .stdout.split(/\r?\n/).filter(Boolean),
    };
    const sourceHashes = [
      "scripts/platform_real_product_browser_acceptance.mjs",
      "scripts/platform_real_product_browser_seed.py",
      "src/workbench/operations.py",
      "src/workbench/operation_worker.py",
      "web/src/pages/Operations.tsx",
      "tests/test_workbench_operations.py",
    ].map((relative) => ({ path: relative, sha256: sha256File(path.join(project, relative)) }));

    const artifactFiles = [
      ...walk(path.join(root, "data", "operations")).filter((file) =>
        ["git-plan.json", "git-process.json", "child-error.json", "worker.log", "result.json"].includes(path.basename(file))),
      ...walk(path.join(root, "data", "artifacts")).filter((file) =>
        ["report.json", "report.md", "manifest.json"].includes(path.basename(file))),
      path.join(root, "seed.json"),
    ].filter(fs.existsSync).map(fileEvidence);

    const reportFile = path.join(root, "data", "artifacts", seed.job_id, "report.json");
    const reportObject = JSON.parse(fs.readFileSync(reportFile, "utf8"));
    const environment = {
      node: process.version,
      playwright_core_path: process.env.PLAYWRIGHT_CORE_PATH || "playwright-core",
      edge_executable: edgeExecutable,
      edge_version: edgeVersion,
      browser_version: browserVersion || null,
      git_version: spawnSync("git", ["--version"], { encoding: "utf8" }).stdout.trim(),
      curl_version: spawnSync("curl.exe", ["--version"], { encoding: "utf8" }).stdout.split(/\r?\n/)[0],
      credential_environment_values_recorded: false,
    };
    const status = failure || checks.length === 0 || checks.some((item) => item.status === "failed")
      ? "failed" : "passed";
    const result = {
      schema_version: 1,
      task: "PLATFORM-REAL-PRODUCT-BROWSER-01",
      run_id: runId,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      status,
      failure_stage: failure?.failure_stage || (failure ? "browser acceptance" : null),
      failure: failure ? (failure.stack || String(failure)) : null,
      checks,
      git_state: gitState,
      backend: {
        git_head: gitState.full_commit_sha,
        backend_source_sha256: backendSourceHash(),
        engine_sha256: reportObject._workbench?.engine_sha256 || null,
      },
      product_binding: seed.product_binding,
      component_binding: seed.component_binding,
      scope: seed.scope,
      detector: seed.detector,
      coverage: seed.coverage,
      report: {
        job_id: seed.job_id,
        commit: product.commit,
        tree: product.tree,
        sha256: seed.report_sha256,
        status: seed.report_status,
        diagnostic_count: seed.diagnostic_count,
        candidate_evidence_level: "candidate/unassessed",
      },
      review_evidence_case: createdCase ? {
        case_id: createdCase.id,
        case_title: createdCase.title,
        reviewed_candidate_id: seed.reviewed_candidate_id,
        review_history_required_after_restart: true,
        supplemental_evidence_required_after_restart: true,
      } : null,
      validation_queue: validationOperation ? {
        operation_id: validationOperation.id,
        status: validationOperation.status,
        result_sha256: validationOperation.result_sha256 || null,
        boundary: "Docker-only component validation queue state; not product vulnerability confirmation",
      } : null,
      commands,
      network_actions: networkActions,
      operation_details: operationDetails,
      process_evidence: processEvidence,
      artifacts: artifactFiles,
      source_hashes: sourceHashes,
      environment,
      limitations: [
        "Public Git tests are explicit anonymous clone/fetch/effective-URL audits, not multi-user or public-network deployment acceptance.",
        "The real product component browser audit uses fixed Git objects; it does not modify or reset the dirty product checkout.",
        "Candidate review, evidence and case reports remain candidate/unassessed and are not product vulnerability confirmation.",
        "Docker validation queue state is component-harness evidence only; product reachability, privilege, CIA impact and exploitability remain unknown.",
        "No production service was attacked; network actions were limited to public Git read operations and HEAD effective-URL audits.",
      ],
      unverified: [
        "multi-user deployment",
        "public Workbench deployment",
        "product-level vulnerability confirmation",
        "Precision/Recall or detector accuracy",
      ],
    };
    fs.mkdirSync(outputDir, { recursive: true });
    const outputJson = path.join(outputDir, `${outputStem}.json`);
    fs.writeFileSync(outputJson, JSON.stringify(result, null, 2) + "\n");

    const checkRows = result.checks.map((item) =>
      `| ${item.name} | ${item.status} | ${item.details.replaceAll("|", "\\|")} |`).join("\n");
    const networkRows = result.network_actions.map((item) =>
      `| ${item.action.replaceAll("|", "\\|")} | ${item.purpose?.replaceAll("|", "\\|") || ""} | ${item.requested_url || ""} | ${item.effective_url || ""} | ${item.status || ""} | ${item.result_sha256 || ""} |`).join("\n");
    const artifactRows = result.artifacts.map((item) =>
      `| ${item.path} | ${item.bytes} | ${item.sha256} |`).join("\n");
    const outputMd = path.join(outputDir, `${outputStem}.md`);
    fs.writeFileSync(outputMd, [
      "# PLATFORM-REAL-PRODUCT-BROWSER-01 公网同步与真实产品组件浏览器验收",
      "",
      `- 运行 ID：\`${result.run_id}\``,
      `- 状态：\`${result.status}\``,
      `- 开始：${result.started_at}`,
      `- 结束：${result.finished_at}`,
      `- Backend HEAD：\`${result.backend.git_head}\``,
      `- Backend source SHA-256：\`${result.backend.backend_source_sha256}\``,
      `- Product：\`${result.product_binding.repository}\` @ \`${product.commit}\` / tree \`${product.tree}\``,
      `- Component：\`${result.component_binding.repository}\` @ \`${component.commit}\` / tree \`${component.tree}\``,
      `- Browser：\`${result.environment.browser_version}\``,
      `- Edge executable：\`${result.environment.edge_executable}\``,
      `- Dirty worktree 文件数（验收结束时 Git 状态）：\`${result.git_state.dirty_files.length}\``,
      "",
      "## 检查",
      "",
      "| 检查 | 状态 | 详情 |",
      "|---|---|---|",
      checkRows,
      "",
      "## 公网网络动作与 effective URL",
      "",
      "| 动作 | 目的 | 请求 URL | effective URL | 状态 | result SHA-256 |",
      "|---|---|---|---|---|---|",
      networkRows,
      "",
      "## 固定产品组件审计边界",
      "",
      "```json",
      JSON.stringify({
        scope: result.scope,
        detector: result.detector,
        coverage: result.coverage,
        report: result.report,
        review_evidence_case: result.review_evidence_case,
        validation_queue: result.validation_queue,
      }, null, 2),
      "```",
      "",
      "## exact command",
      "",
      "```text",
      ...result.commands.map((item) => item.command),
      "```",
      "",
      "## 文件与 SHA-256",
      "",
      "| 文件 | 字节 | SHA-256 |",
      "|---|---:|---|",
      artifactRows,
      "",
      "## 环境",
      "",
      "```json",
      JSON.stringify(result.environment, null, 2),
      "```",
      "",
      "## 限制与 unknown",
      "",
      ...result.limitations.map((item) => `- ${item}`),
      ...result.unverified.map((item) => `- unknown/unverified：${item}`),
      "",
      "本验收证明公网 Git 显式同步边界与固定真实产品组件的浏览器审计流程；不构成产品漏洞确认、多用户部署验收或检测准确率结论。",
      "",
    ].join("\n"));

    const outputHashes = path.join(outputDir, `${outputStem}.hashes.json`);
    fs.writeFileSync(outputHashes, JSON.stringify({
      task: result.task,
      run_id: result.run_id,
      files: [outputJson, outputMd].map(fileEvidence),
    }, null, 2) + "\n");

    console.log(outputJson);
    console.log(outputMd);
    console.log(outputHashes);
    if (failure) console.error(failure.stack || String(failure));
    if (status !== "passed") process.exitCode = 1;
  }
}

await main();
