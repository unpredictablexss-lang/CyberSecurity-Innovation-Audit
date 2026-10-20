import difflib
import subprocess
from pathlib import Path

root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
root_win = r"E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ark_runtime\c8_parallel_20261019\worktrees\exception-guard"
out = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019"
paths = [
    "src/ohscanner/detectors/ark_runtime/exception_guard.py",
    "tests/detectors/ark_runtime/test_exception_guard.py",
    "tests/detectors/ark_runtime/fixtures/EXC01.cpp",
    "src/ohscanner/detectors/ark_runtime/runtime_exception.py",
    "tests/detectors/ark_runtime/test_runtime_exception.py",
]

def git(*args):
    return subprocess.check_output(["git.exe", "-C", root_win, *args])

def blob_bytes(commit, path):
    try:
        return git("show", f"{commit}:{path}")
    except subprocess.CalledProcessError:
        return b""

def diff_path(commit, path):
    old = blob_bytes(commit, path).decode("utf-8")
    new = (root / path).read_bytes().decode("utf-8")
    old_name = "/dev/null" if not old else "a/" + path
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=old_name, tofile="b/" + path))

def make_patch(commit, name):
    patch = "".join(diff_path(commit, path) for path in paths)
    (out / name).write_text(patch, encoding="utf-8", newline="")

make_patch("7af25f5ced471e5d6acc8cf5efd4c696275ce940", "old_baseline_7af25f5_minimal.patch")
make_patch("09ba5aba03c7c7d6787bace349b8fc0a6b0a5457", "latest_static_09ba5aba_minimal.patch")
