import test from "node:test";
import assert from "node:assert/strict";
import {
  canPreviewOfficialRepository,
  pinnedRepositoryImportRequest,
} from "../src/features/workbench/onlineRepository.js";

test("online repository preview is disabled while loading or using a stale catalog", () => {
  assert.equal(canPreviewOfficialRepository({ loading: true, stale: false, slug: "demo" }), false);
  assert.equal(canPreviewOfficialRepository({ loading: false, stale: true, slug: "demo" }), false);
  assert.equal(canPreviewOfficialRepository({ loading: false, stale: false, slug: "../demo" }), false);
  assert.equal(canPreviewOfficialRepository({ loading: false, stale: false, slug: "demo" }), true);
  for (const slug of ["kernel_linux_4.19", "kernel_linux_5.10", "third_party_rust_lazy-static.rs",
    "kernel_linux_6.6", "third_party_decimal.js", ".gitcode"]) {
    assert.equal(canPreviewOfficialRepository({ loading: false, stale: false, slug }), true);
  }
  for (const slug of ["", ".", "..", "repo/name", "repo" + String.fromCharCode(92) + "name",
    String.fromCharCode(10), "x".repeat(101)]) {
    assert.equal(canPreviewOfficialRepository({ loading: false, stale: false, slug }), false);
  }
  assert.equal(canPreviewOfficialRepository({ loading: false, stale: false, slug: "🍀".repeat(50) }), true);
});

test("import submission is bound to the reviewed default branch, full commit, and preview hash", () => {
  const preview = {
    slug: "demo",
    default_branch: "main",
    commit: "1".repeat(40),
    preview_sha256: "2".repeat(64),
    tree_preview: [{ path: "src", object_sha: "3".repeat(40) }],
  };
  assert.deepEqual(pinnedRepositoryImportRequest(preview), {
    slug: "demo",
    branch: "main",
    commit: "1".repeat(40),
    preview_sha256: "2".repeat(64),
    include_paths: ["."],
  });
  assert.throws(() => pinnedRepositoryImportRequest({ ...preview, commit: "short" }), /扫描版本预览/);
  assert.throws(() => pinnedRepositoryImportRequest({ ...preview, preview_sha256: "" }), /扫描版本预览/);
  for (const slug of ["kernel_linux_4.19", "kernel_linux_5.10", "third_party_rust_lazy-static.rs",
    "kernel_linux_6.6", "third_party_decimal.js", ".gitcode"]) {
    assert.equal(pinnedRepositoryImportRequest({ ...preview, slug }).slug, slug);
  }
  assert.throws(() => pinnedRepositoryImportRequest({ ...preview, slug: "../escape" }), /扫描版本预览/);
});
