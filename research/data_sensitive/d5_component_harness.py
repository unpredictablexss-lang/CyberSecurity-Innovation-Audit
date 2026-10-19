"""Compile and run the exact D4 ProcessReceivedData body in a tiny rootless sandbox.

This demonstrates only how the pinned function body handles synthetic plaintext
and a stubbed decrypt/parser/logger boundary. It is not a product build or
product-vulnerability PoC. No network or real credentials are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import tree_sitter_c
from tree_sitter import Language, Parser

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "research/data_sensitive/D4_SOURCE_MANIFEST.json"
OUTPUT = ROOT / "research/data_sensitive/D5_COMPONENT_HARNESS.json"
TARGET = "core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c"
MARKER = "D_SYNTHETIC_SESSION_KEY_7F3A"

PREAMBLE = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define SOFTBUS_OK 0
#define SOFTBUS_ERR (-1)
#define SOFTBUS_MALLOC_ERR (-2)
#define SOFTBUS_MEM_ERR (-3)
#define SOFTBUS_LOG_TRAN 1
#define SOFTBUS_LOG_ERROR 2
#define EOK 0
#define SESSION_KEY_INDEX_SIZE 1
#define OVERHEAD_LEN 1
#define FLAG_REQUEST 1

typedef struct { char bytes[4]; } TdcPacketHead;
typedef struct {
    char data[1024];
    char *w;
    size_t size;
} ServerDataBuf;
typedef struct { int lock; } TestMutex;
typedef struct { TestMutex lock; } ServerDataList;
typedef struct { uint32_t inLen; uint32_t outLen; char *in; char *out; } MsgCryptInfo;
typedef struct { int parsed; } cJSON;

static ServerDataBuf g_node;
static ServerDataList g_list;
static ServerDataList *g_tcpSrvDataList = &g_list;
static const char *g_plaintext = NULL;
static int g_decrypt_status = SOFTBUS_OK;
static char g_logs[4096];
static int g_log_calls = 0;
static int g_process_calls = 0;

static void SoftBusMutexLock(TestMutex *lock) { (void)lock; }
static void SoftBusMutexUnlock(TestMutex *lock) { (void)lock; }
static ServerDataBuf *TransSrvGetDataBufNodeById(int32_t channelId)
{
    (void)channelId;
    return &g_node;
}
static int32_t GetPktHeadInfoByDatabuf(ServerDataBuf *node, uint32_t *inLen,
    uint64_t *seq, uint32_t *flags)
{
    (void)node;
    *inLen = (uint32_t)strlen(g_plaintext) + SESSION_KEY_INDEX_SIZE + OVERHEAD_LEN;
    *seq = 7;
    *flags = FLAG_REQUEST;
    return SOFTBUS_OK;
}
static void *SoftBusCalloc(size_t size) { return calloc(1, size); }
static void SoftBusFree(void *ptr) { free(ptr); }
static int32_t DecryptMessage(int32_t channelId, uint32_t flags, MsgCryptInfo *info)
{
    (void)channelId;
    (void)flags;
    size_t len = strlen(g_plaintext);
    memcpy(info->out, g_plaintext, len);
    info->outLen = (uint32_t)len;
    return g_decrypt_status;
}
static int32_t memmove_s(void *dst, size_t dstMax, const void *src, size_t count)
{
    if (count > dstMax) return -1;
    memmove(dst, src, count);
    return EOK;
}
static cJSON *cJSON_Parse(const char *text)
{
    static cJSON packet;
    size_t len = strlen(text);
    if (len < 2 || text[0] != '{' || text[len - 1] != '}') return NULL;
    packet.parsed = 1;
    return &packet;
}
static void cJSON_Delete(cJSON *packet) { (void)packet; }
static int32_t ProcessMessage(int32_t channelId, uint32_t flags, uint64_t seq, cJSON *packet)
{
    (void)channelId;
    (void)flags;
    (void)seq;
    (void)packet;
    g_process_calls++;
    return SOFTBUS_OK;
}
static void SoftBusLog(int module, int level, const char *format, ...)
{
    (void)module;
    (void)level;
    va_list args;
    va_start(args, format);
    size_t used = strlen(g_logs);
    vsnprintf(g_logs + used, sizeof(g_logs) - used, format, args);
    va_end(args);
    g_log_calls++;
}
"""

DRIVER = r"""
int main(int argc, char **argv)
{
    if (argc != 2) return 90;
    const char *scenario = argv[1];
    if (strcmp(scenario, "valid_secret_request") == 0) {
        g_plaintext = "{\"SESSION_KEY\":\"D_SYNTHETIC_SESSION_KEY_7F3A\"}";
    } else if (strcmp(scenario, "valid_nonsecret_reply") == 0) {
        g_plaintext = "{\"message\":\"ordinary reply\"}";
    } else if (strcmp(scenario, "decrypt_failure") == 0) {
        g_plaintext = "{\"SESSION_KEY\":\"D_SYNTHETIC_SESSION_KEY_7F3A\"}";
        g_decrypt_status = SOFTBUS_ERR;
    } else {
        return 91;
    }
    g_node.size = sizeof(g_node.data);
    g_node.w = g_node.data + sizeof(TdcPacketHead) + strlen(g_plaintext)
        + SESSION_KEY_INDEX_SIZE + OVERHEAD_LEN;
    int32_t result = ProcessReceivedData(7);
    printf("return=%d marker=%d log_calls=%d process_calls=%d\n",
        result, strstr(g_logs, "D_SYNTHETIC_SESSION_KEY_7F3A") != NULL,
        g_log_calls, g_process_calls);
    return 0;
}
"""


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def walk(node):
    yield node
    for child in node.named_children:
        yield from walk(child)


def function_name(node, source: bytes) -> str:
    declarator = node.child_by_field_name("declarator")
    if declarator is None:
        return ""
    function = next((item for item in walk(declarator)
                    if item.type == "function_declarator"), None)
    if function is None:
        return ""
    name = function.child_by_field_name("declarator")
    return source[name.start_byte:name.end_byte].decode() if name else ""


def extract_function(source: bytes) -> str:
    tree = Parser(Language(tree_sitter_c.language())).parse(source)
    matches = [node for node in walk(tree.root_node)
               if node.type == "function_definition"
               and function_name(node, source) == "ProcessReceivedData"]
    if len(matches) != 1 or matches[0].has_error:
        raise ValueError(f"expected one complete ProcessReceivedData definition, found {len(matches)}")
    node = matches[0]
    return source[node.start_byte:node.end_byte].decode()


def run_sandbox(binary: Path, scenario: str) -> dict:
    script = (
        "set -eu; "
        "mount -t tmpfs -o size=16m tmpfs /tmp; "
        "mkdir /tmp/root; cp \"$1\" /tmp/root/harness; chmod 500 /tmp/root/harness; "
        "chroot /tmp/root /harness \"$2\""
    )
    command = [
        "unshare", "--user", "--map-root-user", "--mount", "--net", "--fork",
        "bash", "-c", script, "sandbox", str(binary), scenario,
    ]
    started = time.monotonic()
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(
            f"sandbox failed for {scenario} (exit {result.returncode}): "
            f"stdout={result.stdout[-500:]!r}, stderr={result.stderr[-1000:]!r}"
        )
    values = {}
    for item in result.stdout.strip().split():
        key, value = item.split("=", 1)
        values[key] = int(value)
    return {"scenario": scenario, "observed": values,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "sandbox": "rootless user+mount+network namespace; tmpfs chroot; static binary"}


def source_for(manifest: dict, commit: str, cache_dir: Path) -> tuple[bytes, dict]:
    rows = [row for row in manifest["files"]
            if row["commit"] == commit and row["file"] == TARGET]
    if len(rows) != 1:
        raise ValueError(f"manifest target row mismatch for {commit}")
    row = rows[0]
    path = cache_dir / commit / TARGET
    if not path.is_file():
        raise FileNotFoundError(f"missing pinned source cache: {path}; fetch with D11 replay first")
    data = path.read_bytes()
    checks = {
        "size_matches": len(data) == row["size"],
        "sha256_matches": hashlib.sha256(data).hexdigest() == row["sha256"],
        "git_blob_matches": git_blob_sha(data) == row["blob"],
    }
    if not all(checks.values()):
        raise ValueError(f"source bytes mismatch for {commit}: {checks}")
    return data, {"commit": commit, "tree": row["tree"], "path": TARGET,
                  "blob": row["blob"], "sha256": row["sha256"], "size": len(data),
                  "checks": checks}


def build_and_run(source: bytes, source_row: dict, build_dir: Path, run: bool) -> dict:
    function = extract_function(source)
    generated = (PREAMBLE + "\n" + function + "\n" + DRIVER).encode()
    c_file = build_dir / (source_row["commit"][:8] + "_harness.c")
    binary = build_dir / (source_row["commit"][:8] + "_harness")
    c_file.write_bytes(generated)
    compiler = shutil.which("gcc")
    if not compiler:
        raise FileNotFoundError("gcc is required to compile the component harness")
    version = subprocess.run([compiler, "--version"], check=True, capture_output=True,
                             text=True, timeout=5).stdout.splitlines()[0]
    subprocess.run([compiler, "-std=gnu11", "-O0", "-static", "-Wall", "-Werror",
                    "-o", str(binary), str(c_file)], check=True, capture_output=True,
                   text=True, timeout=30)
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    result = {"source": source_row, "extracted_function_sha256": hashlib.sha256(function.encode()).hexdigest(),
              "generated_c_sha256": hashlib.sha256(generated).hexdigest(),
              "binary_sha256": binary_sha, "compiler": version,
              "execution": "not_run", "scenarios": []}
    if run:
        for scenario in ("valid_secret_request", "valid_nonsecret_reply", "decrypt_failure"):
            result["scenarios"].append(run_sandbox(binary, scenario))
        result["execution"] = "rootless_sandbox_pass"
    return result


def check_expectations(run: dict) -> None:
    rows = {row["source"]["commit"]: row for row in run["versions"]}
    before = rows[run["before_commit"]]
    after = rows[run["after_commit"]]
    for scenario in ("valid_secret_request", "valid_nonsecret_reply", "decrypt_failure"):
        if before["execution"] != "rootless_sandbox_pass" or after["execution"] != "rootless_sandbox_pass":
            raise AssertionError("one or both source functions were compiled but not run")
    before_cases = {row["scenario"]: row["observed"] for row in before["scenarios"]}
    after_cases = {row["scenario"]: row["observed"] for row in after["scenarios"]}
    expected = {
        "valid_secret_request": (1, 1, 1),
        "valid_nonsecret_reply": (0, 1, 1),
        "decrypt_failure": (0, 1, 0),
    }
    for scenario, (before_marker, before_logs, before_process) in expected.items():
        old = before_cases[scenario]
        if (old["marker"], old["log_calls"], old["process_calls"]) != (
                before_marker, before_logs, before_process):
            raise AssertionError(f"unexpected pre-change behavior in {scenario}: {old}")
        new = after_cases[scenario]
        new_marker = 0
        new_logs = 1 if scenario == "decrypt_failure" else 0
        if (new["marker"], new["log_calls"], new["process_calls"]) != (
                new_marker, new_logs, before_process):
            raise AssertionError(f"unexpected post-change behavior in {scenario}: {new}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=Path("/tmp/ohscanner-d11-d4-source-cache"))
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--run-isolated", action="store_true",
                        help="run only the extracted function in a rootless no-network tmpfs chroot")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    commits = (manifest["before_commit"], manifest["after_commit"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ohscanner-d5-component-", dir="/var/tmp") as directory:
        build_dir = Path(directory)
        versions = []
        for commit in commits:
            source, row = source_for(manifest, commit, args.cache_dir)
            versions.append(build_and_run(source, row, build_dir, args.run_isolated))
        result = {
            "schema": 1,
            "experiment": "D5 isolated extracted ProcessReceivedData component behavior",
            "scope": "Exact pinned function body with deterministic crypto/parser/logger stubs; not a full product build",
            "sandbox": "No network namespace; user namespace root; mount namespace with tmpfs chroot containing only the static harness binary",
            "before_commit": commits[0], "after_commit": commits[1],
            "versions": versions,
            "component_assertions": "not_run",
            "product_h01_h08": "not_run",
            "validated_vulnerability": 0,
            "product_impact": "unknown",
            "limitations": [
                "DecryptMessage, cJSON, ProcessMessage, SoftBusLog backend, build flags, and log service are deterministic stubs.",
                "The harness proves only whether this exact function body passes a synthetic decrypted request to the stub logger.",
                "It does not establish a product build, real cryptographic path, persistent log output, unauthorized reader, affected release, or vulnerability confirmation.",
                "The full product H01-H08 matrix remains not_run; this is not Docker/API/Worker/public Runner integration.",
            ],
        }
        if args.run_isolated:
            check_expectations(result)
            result["component_assertions"] = "passed"
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "output": str(args.output),
            "run_isolated": args.run_isolated,
            "component_assertions": result["component_assertions"],
            "versions": [{"commit": row["source"]["commit"], "execution": row["execution"],
                          "scenarios": len(row["scenarios"])} for row in versions],
            "validated_vulnerability": 0,
        }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
