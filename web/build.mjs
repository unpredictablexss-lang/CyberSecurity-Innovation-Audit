import { build } from "esbuild";
import { mkdir, copyFile } from "node:fs/promises";
await mkdir("dist", { recursive: true });
await build({
  entryPoints: ["src/main.tsx"],
  bundle: true,
  outdir: "dist/assets",
  format: "esm",
  splitting: true,
  minify: true,
  sourcemap: false,
  loader: { ".ttf": "file", ".woff2": "file" },
  entryNames: "app",
  chunkNames: "chunk-[hash]",
});
await build({
  entryPoints: ["monaco-editor/esm/vs/editor/editor.worker.js"],
  bundle: true,
  outfile: "dist/assets/editor.worker.js",
  format: "iife",
  minify: true,
});
await copyFile("index.html", "dist/index.html");
