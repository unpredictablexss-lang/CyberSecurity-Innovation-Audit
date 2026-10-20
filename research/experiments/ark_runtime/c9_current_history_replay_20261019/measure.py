from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter

HERE = Path(__file__).resolve().parent
WORKTREE = HERE.parents[3]
PYTHON = Path(sys.executable)
OUTPUT = HERE

ENV_KEYS = (
    'SystemRoot', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'PATH', 'PATHEXT',
    'PYTHONPATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONHASHSEED', 'PYTHONPYCACHEPREFIX',
    'GIT_NO_LAZY_FETCH', 'GIT_ALLOW_PROTOCOL', 'GIT_TERMINAL_PROMPT',
    'GIT_NO_REPLACE_OBJECTS', 'OHSCANNER_ARK_REPO',
)


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = (
        ('cb', wintypes.DWORD),
        ('PageFaultCount', wintypes.DWORD),
        ('PeakWorkingSetSize', ctypes.c_size_t),
        ('WorkingSetSize', ctypes.c_size_t),
        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
        ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
        ('PagefileUsage', ctypes.c_size_t),
        ('PeakPagefileUsage', ctypes.c_size_t),
    )


def peak_rss(handle) -> int:
    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
    if ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), counters.cb):
        return int(counters.PeakWorkingSetSize)
    return 0


def run(name: str, argv: list[str], expected: set[int]) -> dict:
    stdout_path = OUTPUT / (name + '.stdout.txt')
    stderr_path = OUTPUT / (name + '.stderr.txt')
    environment = {key: os.environ[key] for key in ENV_KEYS if key in os.environ}
    start = perf_counter()
    peak = 0
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        process = subprocess.Popen(
            argv,
            cwd=str(WORKTREE),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
        handle = ctypes.windll.kernel32.OpenProcess(
            0x1000 | 0x0010, False, process.pid)
        try:
            while process.poll() is None:
                if handle:
                    peak = max(peak, peak_rss(handle))
                process.wait(timeout=0.005)
        except subprocess.TimeoutExpired:
            pass
        finally:
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
        returncode = process.wait()
    wall = perf_counter() - start
    stdout_bytes = stdout_path.read_bytes()
    stderr_bytes = stderr_path.read_bytes()
    return {
        'name': name,
        'argv': argv,
        'cwd': str(WORKTREE),
        'environment': environment,
        'expected_exit_codes': sorted(expected),
        'exit_code': returncode,
        'expected_exit_code_observed': returncode in expected,
        'wall_seconds': wall,
        'peak_rss_bytes': peak,
        'stdout_file': stdout_path.name,
        'stdout_bytes': len(stdout_bytes),
        'stdout_sha256': hashlib.sha256(stdout_bytes).hexdigest(),
        'stderr_file': stderr_path.name,
        'stderr_bytes': len(stderr_bytes),
        'stderr_sha256': hashlib.sha256(stderr_bytes).hexdigest(),
    }


def write_json(path: Path, payload) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
        newline='\n',
    )


def main() -> int:
    python = str(PYTHON)
    replay = str(Path('research/experiments/ark_runtime/c9_current_history_replay_20261019/replay.py').as_posix())
    output = str(Path('research/experiments/ark_runtime/c9_current_history_replay_20261019').as_posix())
    commands = (
        (
            'replay',
            [python, replay, '--repo-dir', r'E:\网安\_oh_targets\arkcompiler_ets_runtime',
             '--output-dir', output],
            {0, 2},
        ),
        (
            'c9-tests',
            [python, '-m', 'unittest',
             'research.experiments.ark_runtime.c9_current_history_replay_20261019.test_current_history_replay',
             '-v'],
            {0},
        ),
        (
            'ark-runtime-tests',
            [python, '-m', 'unittest', 'discover',
             '-s', 'tests/detectors/ark_runtime', '-t', '.', '-v'],
            {0, 1},
        ),
        (
            'compile-c9',
            [python, 'research/experiments/ark_runtime/c9_current_history_replay_20261019/compile_check.py'],
            {0},
        ),
    )
    runs = [run(name, argv, expected) for name, argv, expected in commands]
    all_expected = all(item['expected_exit_code_observed'] for item in runs)
    measurement = {
        'schema_version': 'c9.current-history-replay.measurement/v1',
        'python_executable': python,
        'measurement_method': 'PROCESS_MEMORY_COUNTERS.PeakWorkingSetSize polled at 5ms',
        'commands': runs,
        'all_expected_exit_codes_observed': all_expected,
        'token_cost': {'status': 'unknown', 'reason': 'no reliable local meter'},
    }
    write_json(OUTPUT / 'measurement.json', measurement)

    sections = []
    for item in runs:
        stdout = (OUTPUT / item['stdout_file']).read_text(encoding='utf-8', errors='replace')
        stderr = (OUTPUT / item['stderr_file']).read_text(encoding='utf-8', errors='replace')
        sections.append(
            '=== ' + item['name'] + ' ===\n'
            + 'argv=' + json.dumps(item['argv'], ensure_ascii=False) + '\n'
            + 'exit=' + str(item['exit_code'])
            + ' expected=' + json.dumps(item['expected_exit_codes']) + '\n'
            + 'wall_seconds=' + format(item['wall_seconds'], '.6f') + '\n'
            + 'peak_rss_bytes=' + str(item['peak_rss_bytes']) + '\n'
            + '--- stdout ---\n' + stdout
            + '\n--- stderr ---\n' + stderr + '\n'
        )
    (OUTPUT / 'test-results.txt').write_text(
        '\n'.join(sections), encoding='utf-8', newline='\n')

    hash_targets = sorted(
        path for path in OUTPUT.rglob('*')
        if path.is_file() and path.name != 'hashes.json'
        and '__pycache__' not in path.parts and 'pycache' not in path.parts
    )
    hashes = {
        path.relative_to(OUTPUT).as_posix(): {
            'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in hash_targets
    }
    write_json(OUTPUT / 'hashes.json', hashes)
    print(json.dumps({
        'all_expected_exit_codes_observed': all_expected,
        'runs': {item['name']: item['exit_code'] for item in runs},
    }, ensure_ascii=False))
    return 0 if all_expected else 3


if __name__ == '__main__':
    raise SystemExit(main())



