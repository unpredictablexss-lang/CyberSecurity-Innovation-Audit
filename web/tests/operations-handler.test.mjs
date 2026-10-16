import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mocks = {
  react: `
    let hookIndex = 0;
    export const hooks = [];
    export const changes = [];
    export const paths = [];
    export const pendingOldGets = [];
    export function useState(initial) {
      const index = hookIndex++;
      if (!hooks[index]) {
        hooks[index] = [initial, (value) => {
          hooks[index][0] = value;
          if (value && value.id) changes.push(value.id);
        }];
      }
      return hooks[index];
    }
    export function useRef(initial) {
      const index = hookIndex++;
      if (!hooks[index]) hooks[index] = { current: initial };
      return hooks[index];
    }
    export function useEffect() {}
    export default {
      Fragment: "Fragment",
      createElement: (type, props, ...children) => ({ type, props: props || {}, children }),
    };
  `,
  antd: `
    export const Alert = "Alert", Button = "Button", Card = "Card", InputNumber = "InputNumber";
    export const Select = "Select", Space = "Space", Table = "Table", Tabs = "Tabs", Tag = "Tag";
    export const Form = Object.assign("Form", { Item: "Form.Item" });
    export const Input = Object.assign("Input", { TextArea: "Input.TextArea" });
    export const Typography = { Text: "Text", Title: "Title" };
    export const message = { success() {}, error() {} };
  `,
  "../api": `
    import { paths, pendingOldGets } from "react";
    export const terminal = new Set();
    export async function api(path, body) {
      paths.push(path);
      if (body !== undefined) return { id: "new-operation" };
      if (path === "/operations/old-operation") {
        return new Promise((resolve) => pendingOldGets.push(resolve));
      }
      if (path.startsWith("/operations/")) return { id: path.slice("/operations/".length) };
      return [];
    }
  `,
  "../components": `export const Header = "Header", Hash = "Hash";`,
};

function findNode(node, type) {
  if (!node || typeof node !== "object") return null;
  if (node.type === type) return node;
  for (const child of (node.children || []).flat()) {
    const hit = findNode(child, type);
    if (hit) return hit;
  }
  return null;
}

async function flush() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "ohscanner-operations-handler-"));
try {
  const outfile = path.join(temporary, "operations-handler.mjs");
  const source = await fs.readFile(path.join(webRoot, "src/pages/Operations.tsx"), "utf8");
  await build({
    stdin: {
      contents: source + "\nexport { changes, paths, pendingOldGets } from 'react';",
      loader: "tsx",
      resolveDir: path.join(webRoot, "src/pages"),
    },
    bundle: true,
    format: "esm",
    outfile,
    plugins: [{
      name: "operations-handler-mocks",
      setup(pluginBuild) {
        pluginBuild.onResolve({ filter: /.*/ }, (args) =>
          args.path in mocks ? { path: args.path, namespace: "mock" } : undefined,
        );
        pluginBuild.onLoad({ filter: /.*/, namespace: "mock" }, (args) =>
          ({ contents: mocks[args.path], loader: "js" }),
        );
      },
    }],
  });

  const module = await import(pathToFileURL(outfile));
  const tree = module.default();
  const table = findNode(tree, "Table");
  const operationColumn = table.props.columns.at(-1);
  const oldRow = { id: "old-operation", status: "queued" };
  const operationCell = operationColumn.render(null, oldRow);
  const viewButton = operationCell.children[0];

  viewButton.props.onClick();
  await flush();
  assert.equal(module.pendingOldGets.length, 1);
  module.pendingOldGets.shift()({ id: "old-operation" });
  await flush();
  assert.deepEqual(module.changes, ["old-operation"]);

  viewButton.props.onClick();
  await flush();
  assert.equal(module.pendingOldGets.length, 1);
  module.changes.length = 0;
  const requestStart = module.paths.length;

  const tabs = findNode(tree, "Tabs");
  const matrix = tabs.props.items.find((item) => item.key === "matrix");
  const submitted = matrix.children.props.onFinish({
    case_id: "case",
    repository_id: "repo",
    detector_ids: ["detector"],
    commits_text: "a".repeat(40) + "," + "b".repeat(40),
    include_paths_text: ".",
    timeout_seconds: 600,
    memory_mb: 2048,
  });

  await flush();
  assert.ok(module.paths.includes("/operations/version-matrices"));
  for (const resolve of module.pendingOldGets.splice(0)) resolve({ id: "old-operation" });
  await submitted;
  await flush();

  assert.ok(module.changes.length >= 1);
  assert.ok(module.changes.every((id) => id === "new-operation"));
  assert.ok(!module.paths.slice(requestStart).includes("/operations/old-operation"));
  console.log(JSON.stringify({
    scenario: "old detail request is still pending when a new operation is created",
    selection_writes: module.changes,
    api_paths_after_submit_started: module.paths.slice(requestStart),
    kind: "actual Operations.tsx form/view handlers with mocked React primitives and API transport; not browser E2E",
  }, null, 2));
} finally {
  await fs.rm(temporary, { recursive: true, force: true });
}
