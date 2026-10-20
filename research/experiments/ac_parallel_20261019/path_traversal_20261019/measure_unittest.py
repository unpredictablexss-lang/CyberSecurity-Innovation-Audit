from __future__ import annotations
import ctypes, json, os, subprocess, sys, time
from pathlib import Path

ROOT = Path.cwd()
OUT = Path("research/experiments/ac_parallel_20261019/path_traversal_20261019")
PY = r"C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
PYTHONPATH = r".;E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps"
LEGACY = [
    "tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_identity_and_positive_file_operation_controls",
    "tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_fixture_manifest_hashes_and_categories",
    "tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_containment_basename_and_allowlist_controls",
    "tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_no_source_no_sink_and_unrelated_api_are_not_candidates",
    "tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_unresolved_cross_function_and_partial_parse_remain_unknown",
    "tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_candidate_requires_file_sink_not_path_concatenation_alone",
    "tests.detectors.test_cpp_path_traversal_detector.CppPathTraversalDetectorTests.test_budget_and_unexpected_analysis_failures_fail_closed",
]

class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
    ]

def peak_rss_bytes(pid: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    handle = kernel32.OpenProcess(0x0410, False, pid)
    if not handle:
        return 0
    try:
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return 0
        return int(counters.PeakWorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)

def run(mode: str) -> None:
    if mode == "final":
        args = [PY, "-X", "utf8", "-m", "unittest", "tests.detectors.test_cpp_path_traversal_detector", "-v"]
    elif mode == "legacy7":
        args = [PY, "-X", "utf8", "-m", "unittest", *LEGACY, "-v"]
    else:
        raise SystemExit("mode must be final or legacy7")
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH
    started = time.perf_counter()
    proc = subprocess.Popen(args, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    peak = 0
    while proc.poll() is None:
        peak = max(peak, peak_rss_bytes(proc.pid))
        time.sleep(0.005)
    peak = max(peak, peak_rss_bytes(proc.pid))
    output = proc.communicate()[0]
    wall = time.perf_counter() - started
    (OUT / f"{mode}_measured_unittest_stdout_stderr.txt").write_text(output, encoding="utf-8", newline="")
    manifest = {
        "schema_version": "ohscanner-test-measurement-v1",
        "mode": mode,
        "cwd": str(ROOT),
        "python": PY,
        "argv": args,
        "command": subprocess.list2cmdline(args),
        "env": {"PYTHONPATH": PYTHONPATH},
        "returncode": proc.returncode,
        "wall_seconds": wall,
        "max_rss_bytes": peak,
        "output_file": str(OUT / f"{mode}_measured_unittest_stdout_stderr.txt"),
    }
    (OUT / f"{mode}_measured_run_manifest.json").write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=True))

run(sys.argv[1])
