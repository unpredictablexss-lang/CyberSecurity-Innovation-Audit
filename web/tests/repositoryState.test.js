import test from "node:test";
import assert from "node:assert/strict";
import { canUseCatalog, canUseVerifiedRepository, filterManagedRepositories } from "../src/features/workbench/repositoryState.js";

test("repository management search matches friendly name, source root, path, and unavailable reason", () => {
  const repositories = [
    { id: "one", name: "openharmony/foo", path: "/srv/repos/foo" },
    { id: "two", name: "openharmony/bar", path: "/mnt/g/bar" },
  ];
  const catalog = [
    { id: "one", display_name: "openharmony/foo", root_alias: "trusted", status: "available" },
    { id: "two", display_name: "openharmony/bar", root_alias: "G盘镜像", status: "unavailable", reason: "Git 校验失败" },
  ];
  assert.deepEqual(filterManagedRepositories(repositories, catalog, "G盘镜像"), [repositories[1]]);
  assert.deepEqual(filterManagedRepositories(repositories, catalog, "/srv/repos"), [repositories[0]]);
  assert.deepEqual(filterManagedRepositories(repositories, catalog, "git 校验失败"), [repositories[1]]);
  assert.deepEqual(filterManagedRepositories(repositories, catalog, " "), repositories);
});

test("stale repository actions stay disabled while catalog data is loading or failed", () => {
  assert.equal(canUseCatalog({ loading: true, error: "" }), false);
  assert.equal(canUseCatalog({ loading: false, error: "directory check failed" }), false);
  assert.equal(canUseCatalog({ loading: false, error: "" }), true);
  assert.equal(canUseVerifiedRepository({ loading: true, error: "", status: "available" }), false);
  assert.equal(canUseVerifiedRepository({ loading: false, error: "refresh failed", status: "available" }), false);
  assert.equal(canUseVerifiedRepository({ loading: false, error: "", status: "unavailable" }), false);
  assert.equal(canUseVerifiedRepository({ loading: false, error: "", status: "available" }), true);
});
