import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const playwrightPath = process.env.PLAYWRIGHT_CORE_PATH || "playwright-core";
const { chromium } = require(playwrightPath);

const baseUrl = process.env.OHSCANNER_BROWSER_BASE_URL || "http://127.0.0.1:8876";
const executablePath =
  process.env.BROWSER_EXECUTABLE ||
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const evidencePath =
  process.env.BROWSER_EVIDENCE_PATH ||
  path.resolve("operations-selection-browser.json");
const screenshotPath =
  process.env.BROWSER_SCREENSHOT_PATH ||
  path.resolve("operations-selection-browser.png");
const oldDetailDelayMs = Number(process.env.OLD_DETAIL_DELAY_MS || 2500);
const headers = { "X-OHScanner-Client": "workbench-v1" };
const observedDetailIds = [];
const requestLog = [];

async function api(pathname, body) {
  const response = await fetch(baseUrl + "/api/v1" + pathname, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { ...headers, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`${pathname} ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

async function createOperation(repository = "openharmony/c_utils") {
  return api("/operations/source-sync", {
    repository,
    url: `https://github.com/${repository}.git`,
    timeout_seconds: 900,
  });
}

async function readDetailId(page) {
  const detail = page.getByTestId("operation-detail");
  await detail.waitFor();
  const text = (await detail.textContent()) || "";
  const id = text.match(/\b[0-9a-f]{32}\b/)?.[0];
  if (!id) throw new Error(`operation detail did not expose a 32-digit id: ${text}`);
  return id;
}

function writeEvidence(result) {
  fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
  fs.writeFileSync(evidencePath, JSON.stringify(result, null, 2) + "\n");
}

async function main() {
  const startedAt = new Date().toISOString();
  let browser;
  let page;
  let oldOperation;
  let newOperation;
  try {
    oldOperation = await createOperation();
    browser = await chromium.launch({ executablePath, headless: true });
    page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.on("request", (request) => {
      if (request.url().includes("/api/v1/operations")) {
        requestLog.push({
          method: request.method(),
          url: request.url().replace(baseUrl, ""),
          at: new Date().toISOString(),
        });
      }
    });

    await page.goto(`${baseUrl}/#/operations`, { waitUntil: "networkidle" });
    await page.getByTestId("view-operation").first().click();
    const openedId = await readDetailId(page);
    if (openedId !== oldOperation.id) {
      throw new Error(`opened ${openedId}, expected old operation ${oldOperation.id}`);
    }
    observedDetailIds.push(openedId);
    await page.route(`**/api/v1/operations/${oldOperation.id}`, async (route) => {
      if (route.request().method() !== "GET") {
        await route.continue();
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, oldDetailDelayMs));
      await route.continue();
    });
    const idsBeforeSubmit = new Set((await api("/operations")).map((item) => item.id));

    await page.getByTestId("sync-repository").fill("openharmony/c_utils");
    await page.getByTestId("sync-url").fill("https://github.com/openharmony/c_utils.git");
    await page.getByTestId("submit-source-sync").click();
    const submitDeadline = Date.now() + 10000;
    while (Date.now() < submitDeadline && !newOperation) {
      const rows = await api("/operations");
      newOperation = rows.find((item) => !idsBeforeSubmit.has(item.id));
      if (!newOperation) await page.waitForTimeout(100);
    }
    if (!newOperation) {
      const errors = await page.locator(".ant-form-item-explain-error").allTextContents();
      await page.screenshot({ path: screenshotPath, fullPage: true });
      throw new Error(`browser submit did not create a second operation; validation=${JSON.stringify(errors)}`);
    }

    const observationDeadline = Date.now() + 5000;
    while (Date.now() < observationDeadline) {
      const id = await readDetailId(page);
      if (observedDetailIds.at(-1) !== id) observedDetailIds.push(id);
      await page.waitForTimeout(100);
    }
    const finalId = await readDetailId(page);
    if (observedDetailIds.at(-1) !== finalId) observedDetailIds.push(finalId);
    await page.screenshot({ path: screenshotPath, fullPage: true });

    const newSelectedAt = observedDetailIds.indexOf(newOperation.id);
    const staleOverwrite = observedDetailIds.some(
      (id, index) => id === oldOperation.id && index > newSelectedAt && newSelectedAt >= 0,
    );

    const result = {
      task: "old operation detail open before creating a new operation",
      status: finalId === newOperation.id && !staleOverwrite ? "passed" : "failed",
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      base_url: baseUrl,
      browser: { kind: "chromium-compatible real browser", executable_path: executablePath },
      old_operation_id: oldOperation.id,
      new_operation_id: newOperation.id,
      observed_detail_ids: observedDetailIds,
      final_detail_id: finalId,
      stale_old_response_overwrote_new_selection: staleOverwrite,
      request_log: requestLog,
      screenshot: screenshotPath,
      old_detail_response_delay_ms: oldDetailDelayMs,
      boundary: "Real browser UI against the real local FastAPI backend. The old detail response is delayed but not replaced; no response mocks or handler replay.",
    };
    writeEvidence(result);
    console.log(JSON.stringify(result, null, 2));
    if (result.status !== "passed") {
      throw new Error(
        `selection regression: final=${finalId}, stale_overwrite=${staleOverwrite}, observed=${observedDetailIds.join(",")}`,
      );
    }
  } catch (error) {
    const result = {
      task: "old operation detail open before creating a new operation",
      status: "failed",
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      base_url: baseUrl,
      browser: { kind: "chromium-compatible real browser", executable_path: executablePath },
      old_operation_id: oldOperation?.id ?? null,
      new_operation_id: newOperation?.id ?? null,
      observed_detail_ids: observedDetailIds,
      request_log: requestLog,
      screenshot: screenshotPath,
      old_detail_response_delay_ms: oldDetailDelayMs,
      error: String(error),
      boundary: "Real browser UI against the real local FastAPI backend. The old detail response is delayed but not replaced; no response mocks or handler replay.",
    };
    if (page) {
      await page.screenshot({ path: screenshotPath, fullPage: true }).catch(() => {});
    }
    writeEvidence(result);
    console.error(JSON.stringify(result, null, 2));
    process.exitCode = 1;
  } finally {
    await browser?.close();
  }
}

await main();
